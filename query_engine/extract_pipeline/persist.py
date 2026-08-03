"""
Ontology-aware SQLite persist layer — with duplication-aware upserts.

Every insert goes through :mod:`extract_pipeline.dedup`:

    1. Exact canonical lookup (by identity) ──▶ reuse existing PK.
    2. Normalized/alias lookup ───────────────▶ reuse existing PK + remember
                                                the new spelling as an alias.
    3. If we end up inserting a new row, we still run cross-identity
       ``same_as`` detection on the batch and write edges into
       ``entity_same_as``.

The function returns detailed counts so callers (and tests) can verify that
repeat insertion of the same content produces zero new rows — only same_as
or alias edges.
"""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Any

from .dedup import (
    SameAsPair,
    detect_vendor_same_as,
    detect_vuln_same_as,
    ensure_same_as_schema,
    find_existing_license,
    find_existing_software,
    find_existing_vendor,
    find_existing_vuln,
    normalize_cwe_id,
    normalize_name,
    normalize_vendor,
    normalize_vuln_id,
    register_alias,
    write_same_as,
)
from .models import CanonicalEntity, CanonicalRelation


DB_PATH = os.path.join(os.path.dirname(__file__), "..", "ai_vuln_kb.db")


def _stat_keys() -> list[str]:
    return [
        "vendors_inserted", "vendors_reused", "vendors_aliased",
        "software_inserted", "software_reused", "software_aliased",
        "versions_inserted", "versions_reused",
        "licenses_inserted", "licenses_reused",
        "vulnerabilities_inserted", "vulnerabilities_reused",
        "vuln_types_inserted", "vuln_types_reused",
        "attacks_inserted", "attacks_reused",
        "impacts_inserted", "impacts_reused",
        "vulnerable_to_links", "is_a_links",
        "produce_links", "has_version_links", "depends_on_links",
        "exploits_links", "results_in_links",
        "same_as_edges_written",
        "skipped_partial", "skipped_no_id",
    ]


def _configure_connection(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")


def _has_stale_vulnerability_fk(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type='table'
          AND name IN (
            'vulnerability_is_a',
            'sw_version_vulnerable_to',
            'hw_version_vulnerable_to',
            'vulnerability_external_id'
          )
          AND sql LIKE '%vulnerability_new%'
        LIMIT 1
        """
    ).fetchone()
    return row is not None


def _repair_stale_vulnerability_fk(conn: sqlite3.Connection) -> None:
    conn.commit()
    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS vulnerability_is_a_fix (
                vuln_id TEXT NOT NULL REFERENCES vulnerability(vuln_id),
                type_id TEXT NOT NULL REFERENCES vulnerability_type(id),
                PRIMARY KEY (vuln_id, type_id)
            );
            INSERT OR IGNORE INTO vulnerability_is_a_fix
            SELECT vuln_id, type_id FROM vulnerability_is_a;
            DROP TABLE vulnerability_is_a;
            ALTER TABLE vulnerability_is_a_fix RENAME TO vulnerability_is_a;

            CREATE TABLE IF NOT EXISTS sw_version_vulnerable_to_fix (
                sw_version_id INTEGER NOT NULL REFERENCES sw_version(id),
                vuln_id       TEXT NOT NULL REFERENCES vulnerability(vuln_id),
                PRIMARY KEY (sw_version_id, vuln_id)
            );
            INSERT OR IGNORE INTO sw_version_vulnerable_to_fix
            SELECT sw_version_id, vuln_id FROM sw_version_vulnerable_to;
            DROP TABLE sw_version_vulnerable_to;
            ALTER TABLE sw_version_vulnerable_to_fix RENAME TO sw_version_vulnerable_to;

            CREATE TABLE IF NOT EXISTS hw_version_vulnerable_to_fix (
                hw_version_id INTEGER NOT NULL REFERENCES hw_version(id),
                vuln_id       TEXT NOT NULL REFERENCES vulnerability(vuln_id),
                PRIMARY KEY (hw_version_id, vuln_id)
            );
            INSERT OR IGNORE INTO hw_version_vulnerable_to_fix
            SELECT hw_version_id, vuln_id FROM hw_version_vulnerable_to;
            DROP TABLE hw_version_vulnerable_to;
            ALTER TABLE hw_version_vulnerable_to_fix RENAME TO hw_version_vulnerable_to;

            CREATE TABLE IF NOT EXISTS vulnerability_external_id_fix (
                vuln_id     TEXT NOT NULL REFERENCES vulnerability(vuln_id),
                source      TEXT NOT NULL,
                external_id TEXT NOT NULL,
                PRIMARY KEY (vuln_id, source, external_id)
            );
            INSERT OR IGNORE INTO vulnerability_external_id_fix
            SELECT vuln_id, source, external_id FROM vulnerability_external_id;
            DROP TABLE vulnerability_external_id;
            ALTER TABLE vulnerability_external_id_fix RENAME TO vulnerability_external_id;

            CREATE INDEX IF NOT EXISTS idx_vuln_ext_source
            ON vulnerability_external_id(source, external_id);
            """
        )
        conn.commit()
    finally:
        conn.execute("PRAGMA foreign_keys=ON")


def ensure_persist_schema(
    *, db_path: str | None = None, conn: sqlite3.Connection | None = None
) -> None:
    own_conn = conn is None
    db = conn or sqlite3.connect(db_path or DB_PATH, timeout=30)
    try:
        _configure_connection(db)
        from build_db import SCHEMA

        db.executescript(SCHEMA)
        ensure_same_as_schema(db.cursor())
        if _has_stale_vulnerability_fk(db):
            _repair_stale_vulnerability_fk(db)
    finally:
        if own_conn:
            db.close()


def persist_canonical(
    entities: list[CanonicalEntity],
    relations: list[CanonicalRelation],
    *,
    source_url: str | None = None,
    include_partial: bool = False,
    db_path: str | None = None,
    detect_same_as: bool = True,
) -> dict[str, int]:
    """Insert canonical entities + relations into SQLite with dedup."""
    stats = dict.fromkeys(_stat_keys(), 0)

    path = db_path or DB_PATH
    conn = sqlite3.connect(path, timeout=30)
    try:
        _configure_connection(conn)
        ensure_persist_schema(conn=conn)
        cur = conn.cursor()

        # canonical_key -> primary-key in SQLite
        pk_of: dict[str, Any] = {}

        by_class: dict[str, list[CanonicalEntity]] = {}
        for e in entities:
            if not include_partial and e.is_partial:
                stats["skipped_partial"] += 1
                continue
            by_class.setdefault(e.class_name, []).append(e)

        # ── Entity handlers (Level 1 + Level 2 lookup before INSERT) ────────────

        def _ensure_vendor(e: CanonicalEntity) -> int | None:
            name = (e.attributes.get("name") or "").strip()
            if not name:
                return None
            norm = normalize_vendor(name)
            existing = find_existing_vendor(cur, name)
            if existing is not None:
                pk_of[e.canonical_key] = existing
                # Still register alias if spelling differs
                cur.execute("SELECT name FROM vendor WHERE id = ?", (existing,))
                row = cur.fetchone()
                if row and normalize_vendor(row[0]) == norm and row[0] != name:
                    register_alias(cur, "Vendor", norm, existing)
                    stats["vendors_aliased"] += 1
                stats["vendors_reused"] += 1
                return existing
            cur.execute("INSERT INTO vendor (name) VALUES (?)", (name,))
            pk_of[e.canonical_key] = cur.lastrowid
            register_alias(cur, "Vendor", norm, cur.lastrowid)
            stats["vendors_inserted"] += 1
            return cur.lastrowid

        def _ensure_software_type(e: CanonicalEntity) -> int | None:
            name = (e.attributes.get("name") or "").strip()
            if not name:
                return None
            norm = normalize_name(name)
            cur.execute("SELECT id, name FROM software_type")
            for sid, sname in cur.fetchall():
                if normalize_name(sname) == norm:
                    pk_of[e.canonical_key] = sid
                    return sid
            cur.execute(
                "INSERT INTO software_type (name, is_ai) VALUES (?, ?)",
                (name, 1 if e.attributes.get("is_ai") else 0),
            )
            pk_of[e.canonical_key] = cur.lastrowid
            return cur.lastrowid

        def _ensure_license(e: CanonicalEntity) -> int | None:
            name = (e.attributes.get("name") or "").strip()
            if not name:
                return None
            existing = find_existing_license(cur, name)
            if existing is not None:
                pk_of[e.canonical_key] = existing
                stats["licenses_reused"] += 1
                return existing
            cur.execute("INSERT INTO license (name) VALUES (?)", (name,))
            pk_of[e.canonical_key] = cur.lastrowid
            stats["licenses_inserted"] += 1
            return cur.lastrowid

        def _ensure_vuln_type(e: CanonicalEntity) -> str | None:
            raw = (e.attributes.get("id") or "").strip()
            if not raw:
                return None
            vid = normalize_cwe_id(raw)
            cur.execute("SELECT id FROM vulnerability_type WHERE UPPER(id) = UPPER(?)", (vid,))
            row = cur.fetchone()
            if row:
                pk_of[e.canonical_key] = row[0]
                stats["vuln_types_reused"] += 1
                return row[0]
            cur.execute(
                "INSERT OR IGNORE INTO vulnerability_type (id, description) VALUES (?, ?)",
                (vid, e.attributes.get("description")),
            )
            if cur.rowcount:
                stats["vuln_types_inserted"] += 1
            pk_of[e.canonical_key] = vid
            return vid

        def _ensure_named(e: CanonicalEntity, table: str, ins_key: str, reuse_key: str) -> int | None:
            """Upsert a simple name-identified node (attack / impact) by normalized name."""
            name = (e.attributes.get("name") or "").strip()
            if not name:
                return None
            norm = normalize_name(name)
            for rid, rname in cur.execute(f"SELECT id, name FROM {table}").fetchall():
                if normalize_name(rname) == norm:
                    pk_of[e.canonical_key] = rid
                    stats[reuse_key] += 1
                    return rid
            cur.execute(
                f"INSERT INTO {table} (name, description) VALUES (?, ?)",
                (name, e.attributes.get("description")),
            )
            pk_of[e.canonical_key] = cur.lastrowid
            stats[ins_key] += 1
            return cur.lastrowid

        def _ensure_attack(e: CanonicalEntity) -> int | None:
            return _ensure_named(e, "attack", "attacks_inserted", "attacks_reused")

        def _ensure_impact(e: CanonicalEntity) -> int | None:
            return _ensure_named(e, "impact", "impacts_inserted", "impacts_reused")

        def _vendor_pk_for_software(sw_key: str) -> int | None:
            # Software canonical key layout: "Software::<vendor_norm>::<name_norm>"
            parts = sw_key.split("::")
            if len(parts) < 3:
                return None
            v_name_norm = parts[1]
            if not v_name_norm:
                return None
            for ve in by_class.get("Vendor", []):
                if normalize_vendor(ve.attributes.get("name", "")) == v_name_norm:
                    return pk_of.get(ve.canonical_key)
            return None

        def _software_pk_for_version(ver_key: str) -> int | None:
            # Version layout: "Version::<entire Software canonical key>::<version_string>"
            # The Software key itself contains "::" so we must rejoin parts[1:-1].
            parts = ver_key.split("::")
            if len(parts) < 4:  # Version, Software, vendor, name, version_string
                return None
            sw_key = "::".join(parts[1:-1])
            return pk_of.get(sw_key)

        def _ensure_software(e: CanonicalEntity) -> int | None:
            name = (e.attributes.get("name") or "").strip()
            if not name:
                return None
            vendor_pk = _vendor_pk_for_software(e.canonical_key)
            existing = find_existing_software(cur, name, vendor_pk)
            if existing is not None:
                pk_of[e.canonical_key] = existing
                stats["software_reused"] += 1
                return existing
            is_ai_raw = e.attributes.get("is_ai")
            is_ai = 1 if is_ai_raw is True else (0 if is_ai_raw is False else None)
            cur.execute(
                "INSERT INTO software (name, vendor_id, is_ai) VALUES (?, ?, ?)",
                (name, vendor_pk, is_ai),
            )
            pk_of[e.canonical_key] = cur.lastrowid
            stats["software_inserted"] += 1
            return cur.lastrowid

        def _ensure_version(e: CanonicalEntity) -> int | None:
            vs = (e.attributes.get("version_string") or "").strip()
            if not vs:
                return None
            sw_pk = _software_pk_for_version(e.canonical_key)
            if not sw_pk:
                return None
            cur.execute(
                "SELECT id FROM sw_version WHERE version_string = ? AND software_id = ?",
                (vs, sw_pk),
            )
            row = cur.fetchone()
            if row:
                pk_of[e.canonical_key] = row[0]
                stats["versions_reused"] += 1
                return row[0]
            cur.execute(
                "INSERT INTO sw_version (version_string, software_id) VALUES (?, ?)",
                (vs, sw_pk),
            )
            pk_of[e.canonical_key] = cur.lastrowid
            stats["versions_inserted"] += 1
            return cur.lastrowid

        def _ensure_vuln(e: CanonicalEntity) -> str | None:
            raw = (e.attributes.get("vuln_id") or "").strip()
            if not raw:
                stats["skipped_no_id"] += 1
                return None
            vid = normalize_vuln_id(raw)
            existing = find_existing_vuln(cur, vid)
            attrs = e.attributes
            refs = attrs.get("references")
            refs_json = json.dumps(refs) if isinstance(refs, list) and refs else None
            if existing is not None:
                pk_of[e.canonical_key] = existing
                stats["vulnerabilities_reused"] += 1
                # Enrich: fill blanks without overwriting existing values
                cur.execute(
                    """
                    UPDATE vulnerability SET
                        title = COALESCE(title, ?),
                        description = COALESCE(description, ?),
                        date_published = COALESCE(date_published, ?),
                        date_updated = COALESCE(date_updated, ?),
                        cvss_base_score = COALESCE(cvss_base_score, ?),
                        cvss_severity = COALESCE(cvss_severity, ?),
                        cvss_vector = COALESCE(cvss_vector, ?),
                        references_json = COALESCE(references_json, ?),
                        credit = COALESCE(credit, ?),
                        source = COALESCE(source, ?)
                    WHERE vuln_id = ?
                    """,
                    (
                        attrs.get("title"), attrs.get("description"),
                        attrs.get("date_published"), attrs.get("date_updated"),
                        attrs.get("cvss_base_score"), attrs.get("cvss_severity"),
                        attrs.get("cvss_vector"), refs_json, attrs.get("credit"),
                        source_url, existing,
                    ),
                )
                return existing
            cur.execute(
                """
                INSERT INTO vulnerability
                  (vuln_id, description, title, date_published, date_updated,
                   cvss_base_score, cvss_severity, cvss_vector,
                   references_json, credit, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vid, attrs.get("description"), attrs.get("title"),
                    attrs.get("date_published"), attrs.get("date_updated"),
                    attrs.get("cvss_base_score"), attrs.get("cvss_severity"),
                    attrs.get("cvss_vector"), refs_json, attrs.get("credit"),
                    source_url,
                ),
            )
            stats["vulnerabilities_inserted"] += 1
            pk_of[e.canonical_key] = vid
            return vid

        def _placeholder_version_for_software(sw_pk: int) -> int:
            """Return (creating if needed) an 'unspecified' version row for a
            software. Used when the extractor links a Software directly to a
            Vulnerability (no affected version in the source). Mirrors the
            placeholder convention in scripts/import_avid.py; the graph view
            collapses these into a direct Software→Vulnerability edge."""
            cur.execute(
                "SELECT id FROM sw_version WHERE software_id = ? AND version_string = 'unspecified'",
                (sw_pk,),
            )
            row = cur.fetchone()
            if row:
                return row[0]
            cur.execute(
                "INSERT INTO sw_version (version_string, software_id) VALUES ('unspecified', ?)",
                (sw_pk,),
            )
            stats["versions_inserted"] += 1
            return cur.lastrowid

        handlers = {
            "Vendor": _ensure_vendor,
            "SoftwareType": _ensure_software_type,
            "License": _ensure_license,
            "Software": _ensure_software,
            "Version": _ensure_version,
            "VulnerabilityType": _ensure_vuln_type,
            "Vulnerability": _ensure_vuln,
            "Attack": _ensure_attack,
            "Impact": _ensure_impact,
        }
        order = ["Vendor", "SoftwareType", "License", "Software", "Version",
                 "VulnerabilityType", "Vulnerability", "Attack", "Impact"]
        for cname in order:
            for e in by_class.get(cname, []):
                h = handlers.get(cname)
                if h:
                    h(e)

        # ── Relations ──

        for r in relations:
            subj_pk = pk_of.get(r.subject_key)
            obj_pk = pk_of.get(r.object_key)
            if subj_pk is None or obj_pk is None:
                continue

            if r.predicate == "vulnerableTo":
                if isinstance(subj_pk, int) and isinstance(obj_pk, str):
                    # The ontology defines vulnerableTo as Version→Vulnerability,
                    # but extractors often link a Software directly when no
                    # version is stated. In that case, attach via a placeholder
                    # version so the link is well-formed instead of writing a
                    # software id into the sw_version_id column.
                    sw_version_id = subj_pk
                    if r.subject_key.startswith("Software"):
                        sw_version_id = _placeholder_version_for_software(subj_pk)
                    cur.execute(
                        "INSERT OR IGNORE INTO sw_version_vulnerable_to (sw_version_id, vuln_id) VALUES (?, ?)",
                        (sw_version_id, obj_pk),
                    )
                    if cur.rowcount:
                        stats["vulnerable_to_links"] += 1

            elif r.predicate == "isA_vulnType":
                if isinstance(subj_pk, str) and isinstance(obj_pk, str):
                    cur.execute(
                        "INSERT OR IGNORE INTO vulnerability_is_a (vuln_id, type_id) VALUES (?, ?)",
                        (subj_pk, obj_pk),
                    )
                    if cur.rowcount:
                        stats["is_a_links"] += 1

            elif r.predicate == "produce":
                stats["produce_links"] += 1

            elif r.predicate == "hasVersion":
                stats["has_version_links"] += 1

            elif r.predicate == "dependsOn":
                if isinstance(subj_pk, int) and isinstance(obj_pk, int):
                    cur.execute(
                        "INSERT OR IGNORE INTO sw_version_depends_on (from_version_id, to_version_id) VALUES (?, ?)",
                        (subj_pk, obj_pk),
                    )
                    if cur.rowcount:
                        stats["depends_on_links"] += 1

            elif r.predicate == "exploits":
                # Attack --exploits--> Vulnerability (attack_id INTEGER, vuln_id TEXT)
                if isinstance(subj_pk, int) and isinstance(obj_pk, str):
                    cur.execute(
                        "INSERT OR IGNORE INTO attack_exploits_vuln (attack_id, vuln_id) VALUES (?, ?)",
                        (subj_pk, obj_pk),
                    )
                    if cur.rowcount:
                        stats["exploits_links"] += 1

            elif r.predicate == "resultsIn":
                # Vulnerability --resultsIn--> Impact (vuln_id TEXT, impact_id INTEGER)
                if isinstance(subj_pk, str) and isinstance(obj_pk, int):
                    cur.execute(
                        "INSERT OR IGNORE INTO vuln_results_in_impact (vuln_id, impact_id) VALUES (?, ?)",
                        (subj_pk, obj_pk),
                    )
                    if cur.rowcount:
                        stats["results_in_links"] += 1

        # ── Level 3: cross-identity same_as detection ─────────────────────────
        if detect_same_as:
            vulns = [
                {**e.attributes, "vuln_id": normalize_vuln_id(e.attributes.get("vuln_id", ""))}
                for e in by_class.get("Vulnerability", [])
            ]
            vendors = [{"name": e.attributes.get("name")} for e in by_class.get("Vendor", [])]

            pairs: list[SameAsPair] = []
            pairs.extend(detect_vuln_same_as(vulns))
            pairs.extend(detect_vendor_same_as(vendors))
            stats["same_as_edges_written"] = write_same_as(cur, pairs, source_url=source_url)

        conn.commit()
        return stats
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
