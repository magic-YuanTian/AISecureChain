#!/usr/bin/env python3
"""
Import AVID (AI Vulnerability Database) records into the AISecureChain SQLite KB.

Reads all JSON files from the cloned avid-db repository and maps them into:
  - vulnerability               (vuln_id as universal PK)
  - vulnerability_external_id   (cross-reference: CVE ↔ AVID ↔ GHSA …)
  - vulnerability_type / vulnerability_is_a  (from CWE in AVID impact)
  - vendor / software                        (from affects.developer/deployer + artifacts)
  - sw_version / sw_version_vulnerable_to    (placeholder version for software↔vuln link)

For CVE-type AVID reports whose CVE already exists in the DB, the record is *enriched*
(AVID metadata added) rather than duplicated.

Usage:
  cd query_engine && python3 scripts/import_avid.py
"""

from __future__ import annotations

import json
import glob
import os
import re
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
QE_ROOT = os.path.dirname(HERE)
PROJECT_ROOT = os.path.dirname(QE_ROOT)

DB_PATH = os.path.join(QE_ROOT, "ai_vuln_kb.db")
AVID_DB_DIR = os.path.join(PROJECT_ROOT, "avid-db")

CVE_RE = re.compile(r"(CVE-\d{4}-\d+)")

ARTIFACT_TYPE_TO_SW_TYPE: dict[str, str] = {
    "Model": "Model",
    "Dataset": "Dataset",
    "System": "Application",
}


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

def ensure_columns(conn: sqlite3.Connection) -> None:
    """Add AVID-specific columns to vulnerability if missing."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(vulnerability)")}
    new_cols = {
        "source": "TEXT",
        "risk_domain": "TEXT",
        "sep_view": "TEXT",
        "lifecycle_view": "TEXT",
        "avid_class": "TEXT",
    }
    for col, typ in new_cols.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE vulnerability ADD COLUMN {col} {typ}")
    conn.commit()


def ensure_external_id_table(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerability_external_id (
            vuln_id     TEXT NOT NULL,
            source      TEXT NOT NULL,
            external_id TEXT NOT NULL,
            PRIMARY KEY (vuln_id, source, external_id)
        )
    """)
    conn.commit()


# ---------------------------------------------------------------------------
# Lookup / upsert helpers
# ---------------------------------------------------------------------------

_vendor_cache: dict[str, int] = {}
_sw_cache: dict[tuple[str, int], int] = {}
_ver_cache: dict[tuple[int, str], int] = {}
_swtype_cache: dict[str, int] = {}


def _warm_caches(conn: sqlite3.Connection) -> None:
    _vendor_cache.clear()
    for r in conn.execute("SELECT id, name FROM vendor"):
        _vendor_cache[r[1]] = r[0]
    for r in conn.execute("SELECT id, name, vendor_id FROM software"):
        _sw_cache[(r[1], r[2])] = r[0]
    for r in conn.execute("SELECT id, version_string, software_id FROM sw_version"):
        _ver_cache[(r[2], r[1])] = r[0]
    for r in conn.execute("SELECT id, name FROM software_type"):
        _swtype_cache[r[1]] = r[0]


def get_or_create_vendor(conn: sqlite3.Connection, name: str) -> int:
    if name in _vendor_cache:
        return _vendor_cache[name]
    cur = conn.execute("INSERT OR IGNORE INTO vendor (name) VALUES (?)", (name,))
    if cur.lastrowid:
        _vendor_cache[name] = cur.lastrowid
        return cur.lastrowid
    row = conn.execute("SELECT id FROM vendor WHERE name = ?", (name,)).fetchone()
    _vendor_cache[name] = row[0]
    return row[0]


def get_or_create_software(
    conn: sqlite3.Connection, name: str, vendor_id: int, sw_type_name: str
) -> int:
    key = (name, vendor_id)
    if key in _sw_cache:
        return _sw_cache[key]
    type_id = _swtype_cache.get(sw_type_name)
    cur = conn.execute(
        "INSERT OR IGNORE INTO software (name, vendor_id, software_type_id, is_ai) "
        "VALUES (?, ?, ?, 1)",
        (name, vendor_id, type_id),
    )
    if cur.lastrowid:
        _sw_cache[key] = cur.lastrowid
        return cur.lastrowid
    row = conn.execute(
        "SELECT id FROM software WHERE name = ? AND vendor_id = ?", (name, vendor_id)
    ).fetchone()
    _sw_cache[key] = row[0]
    return row[0]


def get_or_create_version(
    conn: sqlite3.Connection, software_id: int, version_str: str = "unspecified"
) -> int:
    key = (software_id, version_str)
    if key in _ver_cache:
        return _ver_cache[key]
    cur = conn.execute(
        "INSERT OR IGNORE INTO sw_version (version_string, software_id) VALUES (?, ?)",
        (version_str, software_id),
    )
    if cur.lastrowid:
        _ver_cache[key] = cur.lastrowid
        return cur.lastrowid
    row = conn.execute(
        "SELECT id FROM sw_version WHERE software_id = ? AND version_string = ?",
        (software_id, version_str),
    ).fetchone()
    _ver_cache[key] = row[0]
    return row[0]


# ---------------------------------------------------------------------------
# CVE extraction
# ---------------------------------------------------------------------------

def extract_cve_id(record: dict) -> str | None:
    desc = record.get("problemtype", {}).get("description", {}).get("value", "")
    m = CVE_RE.search(desc)
    if m:
        return m.group(1)
    for ref in record.get("references", []):
        m = CVE_RE.search(ref.get("url", ""))
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Core import logic
# ---------------------------------------------------------------------------

def import_record(
    conn: sqlite3.Connection, record: dict, record_type: str
) -> tuple[str, bool]:
    """Import one AVID JSON record. Returns (action, ok)."""
    meta = record.get("metadata", {})
    avid_id = meta.get("report_id") or meta.get("vuln_id", "")

    cve_id = extract_cve_id(record)
    primary_id = cve_id if cve_id else avid_id
    if not primary_id:
        return "skip", False

    # ── fields ──
    desc = record.get("description", {}).get("value", "")
    title = record.get("problemtype", {}).get("description", {}).get("value", "")
    avid_class = record.get("problemtype", {}).get("classof", "")

    refs = [r["url"] for r in record.get("references", []) if r.get("url")]
    refs_json = json.dumps(refs) if refs else None

    credit_parts = record.get("credit", [])
    credit = "; ".join(c.get("value", "") for c in credit_parts) if credit_parts else None

    reported_date = record.get("reported_date") or record.get("published_date", "")
    modified_date = record.get("last_modified_date", "")

    cvss = record.get("impact", {}).get("cvss", {})
    cvss_score = cvss.get("baseScore")
    cvss_severity = cvss.get("baseSeverity")
    cvss_vector = cvss.get("vectorString")

    avid_imp = record.get("impact", {}).get("avid", {})
    risk_domain = ", ".join(avid_imp.get("risk_domain", []))
    sep_view = ", ".join(avid_imp.get("sep_view", []))
    lifecycle_view = ", ".join(avid_imp.get("lifecycle_view", []))

    source_tag = f"AVID-{record_type}"

    existing = conn.execute(
        "SELECT vuln_id, source FROM vulnerability WHERE vuln_id = ?", (primary_id,)
    ).fetchone()

    if existing:
        old_src = existing[1] or ""
        new_src = old_src if source_tag in old_src else f"{old_src},{source_tag}".strip(",")
        conn.execute(
            """UPDATE vulnerability SET
                source        = ?,
                risk_domain   = COALESCE(risk_domain, NULLIF(?, '')),
                sep_view      = COALESCE(sep_view, NULLIF(?, '')),
                lifecycle_view = COALESCE(lifecycle_view, NULLIF(?, '')),
                avid_class    = COALESCE(avid_class, NULLIF(?, '')),
                cvss_base_score = COALESCE(cvss_base_score, ?),
                cvss_severity   = COALESCE(cvss_severity, ?),
                cvss_vector     = COALESCE(cvss_vector, ?)
            WHERE vuln_id = ?""",
            (new_src, risk_domain, sep_view, lifecycle_view,
             avid_class, cvss_score, cvss_severity, cvss_vector, primary_id),
        )
        action = "enrich"
    else:
        conn.execute(
            """INSERT OR IGNORE INTO vulnerability (
                vuln_id, description, title, date_published, date_updated,
                cvss_base_score, cvss_severity, cvss_vector,
                references_json, credit,
                source, risk_domain, sep_view, lifecycle_view, avid_class
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (primary_id, desc, title, reported_date, modified_date,
             cvss_score, cvss_severity, cvss_vector, refs_json, credit,
             source_tag, risk_domain, sep_view, lifecycle_view, avid_class),
        )
        action = "insert"

    # ── External IDs ──
    if cve_id:
        conn.execute(
            "INSERT OR IGNORE INTO vulnerability_external_id (vuln_id, source, external_id) VALUES (?,?,?)",
            (primary_id, "CVE", cve_id),
        )
    if avid_id:
        conn.execute(
            "INSERT OR IGNORE INTO vulnerability_external_id (vuln_id, source, external_id) VALUES (?,?,?)",
            (primary_id, "AVID", avid_id),
        )

    # ── CWE → vulnerability_type + vulnerability_is_a ──
    for cwe in record.get("impact", {}).get("cwe", []):
        cwe_id = cwe.get("cweId", "")
        cwe_desc = cwe.get("description", "")
        if cwe_id:
            conn.execute(
                "INSERT OR IGNORE INTO vulnerability_type (id, description) VALUES (?,?)",
                (cwe_id, cwe_desc),
            )
            conn.execute(
                "INSERT OR IGNORE INTO vulnerability_is_a (vuln_id, type_id) VALUES (?,?)",
                (primary_id, cwe_id),
            )

    # ── Software / Vendor from affects ──
    affects = record.get("affects", {})
    developers = [d.strip() for d in affects.get("developer", []) if d and d.strip()]
    deployers = [d.strip() for d in affects.get("deployer", []) if d and d.strip()]
    primary_vendor_name = (developers[0] if developers else deployers[0] if deployers else "[UNKNOWN]")

    for artifact in affects.get("artifacts", []):
        art_name = (artifact.get("name") or "").strip()
        if not art_name:
            continue
        art_type = artifact.get("type", "System")
        sw_type_name = ARTIFACT_TYPE_TO_SW_TYPE.get(art_type, "Application")

        vendor_id = get_or_create_vendor(conn, primary_vendor_name)
        sw_id = get_or_create_software(conn, art_name, vendor_id, sw_type_name)
        ver_id = get_or_create_version(conn, sw_id)
        conn.execute(
            "INSERT OR IGNORE INTO sw_version_vulnerable_to (sw_version_id, vuln_id) VALUES (?,?)",
            (ver_id, primary_id),
        )

    return action, True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if not os.path.isdir(AVID_DB_DIR):
        print(f"avid-db not found at {AVID_DB_DIR}", file=sys.stderr)
        print("Run:  git clone https://github.com/avidml/avid-db.git", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(DB_PATH):
        print(f"DB not found at {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    print("Ensuring schema …")
    ensure_columns(conn)
    ensure_external_id_table(conn)

    print("Warming caches …")
    _warm_caches(conn)

    # ── Collect files ──
    report_files = sorted(
        f
        for f in glob.glob(os.path.join(AVID_DB_DIR, "reports", "**", "*.json"), recursive=True)
        if "/review/" not in f and "/img/" not in f
    )
    vuln_files = sorted(
        glob.glob(os.path.join(AVID_DB_DIR, "vulnerabilities", "**", "*.json"), recursive=True)
    )

    stats: dict[str, int] = {"insert": 0, "enrich": 0, "skip": 0, "error": 0}

    # ── Reports ──
    print(f"Importing {len(report_files)} AVID reports …")
    for fpath in report_files:
        try:
            with open(fpath) as fh:
                rec = json.load(fh)
            action, ok = import_record(conn, rec, "report")
            stats[action if ok else "skip"] += 1
        except Exception as exc:
            stats["error"] += 1
            print(f"  ERROR {os.path.basename(fpath)}: {exc}", file=sys.stderr)
    conn.commit()
    print(f"  inserted={stats['insert']}  enriched={stats['enrich']}  "
          f"skipped={stats['skip']}  errors={stats['error']}")

    stats = {"insert": 0, "enrich": 0, "skip": 0, "error": 0}

    # ── Vulnerability records ──
    print(f"Importing {len(vuln_files)} AVID vulnerability records …")
    for fpath in vuln_files:
        try:
            with open(fpath) as fh:
                rec = json.load(fh)
            action, ok = import_record(conn, rec, "vuln")
            stats[action if ok else "skip"] += 1
        except Exception as exc:
            stats["error"] += 1
            print(f"  ERROR {os.path.basename(fpath)}: {exc}", file=sys.stderr)
    conn.commit()
    print(f"  inserted={stats['insert']}  enriched={stats['enrich']}  "
          f"skipped={stats['skip']}  errors={stats['error']}")

    # ── Summary ──
    total_v = conn.execute("SELECT COUNT(*) FROM vulnerability").fetchone()[0]
    avid_v = conn.execute("SELECT COUNT(*) FROM vulnerability WHERE source LIKE '%AVID%'").fetchone()[0]
    total_sw = conn.execute("SELECT COUNT(*) FROM software").fetchone()[0]
    total_vnd = conn.execute("SELECT COUNT(*) FROM vendor").fetchone()[0]
    total_ver = conn.execute("SELECT COUNT(*) FROM sw_version").fetchone()[0]
    total_link = conn.execute("SELECT COUNT(*) FROM sw_version_vulnerable_to").fetchone()[0]
    total_vt = conn.execute("SELECT COUNT(*) FROM vulnerability_type").fetchone()[0]
    total_ext = conn.execute("SELECT COUNT(*) FROM vulnerability_external_id").fetchone()[0]

    print(f"\n{'='*50}")
    print(f"Vulnerabilities : {total_v}  (AVID-sourced/enriched: {avid_v})")
    print(f"Software        : {total_sw}")
    print(f"Vendors         : {total_vnd}")
    print(f"Versions        : {total_ver}")
    print(f"Version↔Vuln    : {total_link}")
    print(f"Vuln Types (CWE): {total_vt}")
    print(f"External IDs    : {total_ext}")
    print("Done.")

    conn.close()


if __name__ == "__main__":
    main()
