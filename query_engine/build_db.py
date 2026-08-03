"""
AISecureChain — Build Ontology Knowledge Base (SQLite)
======================================================
Strict ontology-only schema.  Non-ontology fields from MISP / CVE JSON
are stored as properties (extra columns) on the appropriate entity.

Data sources:
  - output/cve_details.json   (CVE 5.x records)
  - output/all_ai_events_full.json  (MISP events → threat level, tags, credit)
"""

import json
import os
import re
import sqlite3
import sys

DB_PATH = os.path.join(os.path.dirname(__file__), "ai_vuln_kb.db")
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "output")

SCHEMA = """
-- ═══════════════════════════════════════
--  ENTITY TABLES (9)
-- ═══════════════════════════════════════

CREATE TABLE IF NOT EXISTS vendor (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS software_type (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT NOT NULL UNIQUE,
    is_ai INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS software (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    vendor_id        INTEGER REFERENCES vendor(id),
    is_ai            INTEGER,
    software_type_id INTEGER REFERENCES software_type(id),
    UNIQUE(name, vendor_id)
);

CREATE TABLE IF NOT EXISTS license (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS sw_version (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    version_string TEXT NOT NULL,
    software_id    INTEGER NOT NULL REFERENCES software(id),
    license_id     INTEGER REFERENCES license(id)
);

CREATE TABLE IF NOT EXISTS hardware (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL,
    vendor_id INTEGER REFERENCES vendor(id),
    UNIQUE(name, vendor_id)
);

CREATE TABLE IF NOT EXISTS hw_version (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    version_string TEXT NOT NULL,
    hardware_id    INTEGER NOT NULL REFERENCES hardware(id)
);

CREATE TABLE IF NOT EXISTS vulnerability (
    vuln_id           TEXT PRIMARY KEY,
    description       TEXT,
    title             TEXT,
    date_published    TEXT,
    date_updated      TEXT,
    cvss_base_score   REAL,
    cvss_severity     TEXT,
    cvss_vector       TEXT,
    references_json   TEXT,
    credit            TEXT,
    misp_threat_level INTEGER,
    misp_event_date   TEXT,
    misp_tags         TEXT,
    source            TEXT,
    risk_domain       TEXT,
    sep_view          TEXT,
    lifecycle_view    TEXT,
    avid_class        TEXT,
    exploited_in_wild          INTEGER NOT NULL DEFAULT 0,
    exploitation_verified_date TEXT,
    ransomware_use             TEXT
);

CREATE TABLE IF NOT EXISTS vulnerability_type (
    id          TEXT PRIMARY KEY,
    description TEXT
);

-- ═══════════════════════════════════════
--  JUNCTION TABLES (5 — M:N edges only)
-- ═══════════════════════════════════════

CREATE TABLE IF NOT EXISTS sw_version_vulnerable_to (
    sw_version_id INTEGER NOT NULL REFERENCES sw_version(id),
    vuln_id       TEXT NOT NULL REFERENCES vulnerability(vuln_id),
    PRIMARY KEY (sw_version_id, vuln_id)
);

CREATE TABLE IF NOT EXISTS hw_version_vulnerable_to (
    hw_version_id INTEGER NOT NULL REFERENCES hw_version(id),
    vuln_id       TEXT NOT NULL REFERENCES vulnerability(vuln_id),
    PRIMARY KEY (hw_version_id, vuln_id)
);

CREATE TABLE IF NOT EXISTS vulnerability_is_a (
    vuln_id TEXT NOT NULL REFERENCES vulnerability(vuln_id),
    type_id TEXT NOT NULL REFERENCES vulnerability_type(id),
    PRIMARY KEY (vuln_id, type_id)
);

CREATE TABLE IF NOT EXISTS vulnerability_external_id (
    vuln_id     TEXT NOT NULL REFERENCES vulnerability(vuln_id),
    source      TEXT NOT NULL,
    external_id TEXT NOT NULL,
    PRIMARY KEY (vuln_id, source, external_id)
);

CREATE TABLE IF NOT EXISTS sw_version_depends_on (
    from_version_id INTEGER NOT NULL REFERENCES sw_version(id),
    to_version_id   INTEGER NOT NULL REFERENCES sw_version(id),
    PRIMARY KEY (from_version_id, to_version_id)
);

CREATE TABLE IF NOT EXISTS sw_version_operate_on (
    sw_version_id INTEGER NOT NULL REFERENCES sw_version(id),
    hw_version_id INTEGER NOT NULL REFERENCES hw_version(id),
    PRIMARY KEY (sw_version_id, hw_version_id)
);

CREATE INDEX IF NOT EXISTS idx_sw_version_software ON sw_version(software_id);
CREATE INDEX IF NOT EXISTS idx_software_vendor ON software(vendor_id);
CREATE INDEX IF NOT EXISTS idx_hardware_vendor ON hardware(vendor_id);
CREATE INDEX IF NOT EXISTS idx_hw_version_hardware ON hw_version(hardware_id);

-- ═══════════════════════════════════════
--  ATTACK / IMPACT LAYER  (our own classes; extracted from advisory text)
-- ═══════════════════════════════════════
-- A causal chain the weakness-type (CWE) layer lacks:
--     Attack ──exploits──▶ Vulnerability ──resultsIn──▶ Impact
-- Attack  = how the vulnerability is exploited (e.g. "Indirect Prompt Injection").
-- Impact  = the consequence of exploiting it  (e.g. "Remote Code Execution").
-- Both are name-identified and populated by the extraction pipeline per advisory.

CREATE TABLE IF NOT EXISTS attack (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS impact (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT
);

-- Attack ──exploits──▶ Vulnerability
CREATE TABLE IF NOT EXISTS attack_exploits_vuln (
    attack_id INTEGER NOT NULL REFERENCES attack(id),
    vuln_id   TEXT NOT NULL REFERENCES vulnerability(vuln_id),
    PRIMARY KEY (attack_id, vuln_id)
);

-- Vulnerability ──resultsIn──▶ Impact
CREATE TABLE IF NOT EXISTS vuln_results_in_impact (
    vuln_id   TEXT NOT NULL REFERENCES vulnerability(vuln_id),
    impact_id INTEGER NOT NULL REFERENCES impact(id),
    PRIMARY KEY (vuln_id, impact_id)
);

-- Generic provenance: which external catalog an entity's id came from. Lets us
-- reuse a source's identifier without naming a field after the source.
CREATE TABLE IF NOT EXISTS entity_external_id (
    entity_type TEXT NOT NULL,     -- e.g. 'Attack', 'Impact'
    entity_id   TEXT NOT NULL,
    source      TEXT NOT NULL,     -- e.g. 'ATLAS'
    external_id TEXT NOT NULL,
    PRIMARY KEY (entity_type, entity_id, source, external_id)
);

-- ═══════════════════════════════════════
--  SAME-AS EDGES (cross-type owl:sameAs-style links)
-- ═══════════════════════════════════════
-- Used by the extraction pipeline to link the SAME real-world entity that
-- appears under different identifiers (e.g. CVE-X and GHSA-Y describing the
-- same vulnerability, or 'OpenAI' vs 'Open AI' vs 'OpenAI Inc.').
-- left_key / right_key are stringified PKs of the referenced entity type.

CREATE TABLE IF NOT EXISTS entity_same_as (
    entity_type TEXT NOT NULL,
    left_key    TEXT NOT NULL,
    right_key   TEXT NOT NULL,
    confidence  REAL NOT NULL DEFAULT 1.0,
    reason      TEXT,
    source_url  TEXT,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (entity_type, left_key, right_key)
);

CREATE INDEX IF NOT EXISTS idx_same_as_right ON entity_same_as(entity_type, right_key);

-- Alias table for normalized name -> canonical entity (vendor/software/license).
-- Rows are added whenever we detect a near-duplicate name so future lookups hit.
CREATE TABLE IF NOT EXISTS entity_alias (
    entity_type TEXT NOT NULL,
    alias_norm  TEXT NOT NULL,
    entity_key  TEXT NOT NULL,
    PRIMARY KEY (entity_type, alias_norm)
);
"""


def _extract_cvss(metrics_list):
    """Return (base_score, severity, vector) from the best available CVSS block."""
    for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
        for m in metrics_list:
            block = m.get(key)
            if block:
                return (
                    block.get("baseScore"),
                    block.get("baseSeverity", ""),
                    block.get("vectorString", ""),
                )
    return None, "", ""


def _build_misp_index(misp_raw):
    """CVE-ID → {threat_level, event_date, tags, credit, references}."""
    index = {}
    for ev_wrapper in misp_raw:
        ev = ev_wrapper.get("Event", ev_wrapper)
        threat = ev.get("threat_level_id")
        date = ev.get("date", "")
        tags = [t.get("name", "") for t in ev.get("Tag", [])]

        cve_ids = []
        credit = ""
        refs = []
        for obj in ev.get("Object", []):
            for a in obj.get("Attribute", []):
                rel = a.get("object_relation", "")
                val = a.get("value", "")
                if rel == "id" and val.startswith("CVE"):
                    cve_ids.append(val)
                elif rel == "credit" and val:
                    credit = val
                elif rel == "references" and val:
                    refs.append(val)

        for cid in cve_ids:
            if cid not in index:
                index[cid] = {
                    "threat_level": int(threat) if threat else None,
                    "event_date": date,
                    "tags": ",".join(t for t in tags if t),
                    "credit": credit,
                    "references": refs,
                }
    return index


def build():
    misp_path = os.path.join(DATA_DIR, "all_ai_events_full.json")
    cve_path = os.path.join(DATA_DIR, "cve_details.json")
    for p in (misp_path, cve_path):
        if not os.path.exists(p):
            print(f"ERROR: {p} not found.")
            sys.exit(1)

    print("Loading MISP events …")
    with open(misp_path) as f:
        misp_raw = json.load(f)
    print("Loading CVE details …")
    with open(cve_path) as f:
        cve_raw = json.load(f)

    print("Building MISP CVE index …")
    misp_index = _build_misp_index(misp_raw)
    print(f"  {len(misp_index)} CVEs found in MISP")

    # Create DB
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    cur = conn.cursor()
    cur.executescript(SCHEMA)

    vendor_cache = {}
    sw_cache = {}

    print(f"Processing {len(cve_raw)} CVE records …")
    for cve_id, rec in cve_raw.items():
        if "error" in rec:
            continue
        cna = rec.get("containers", {}).get("cna", {})
        meta = rec.get("cveMetadata", {})

        # --- Description ---
        desc = ""
        for d in cna.get("descriptions", []):
            if d.get("lang", "en") == "en":
                desc = d.get("value", "")
                break

        # --- Title ---
        title = cna.get("title", "")

        # --- Dates from cveMetadata ---
        date_published = meta.get("datePublished", "")
        date_updated = meta.get("dateUpdated", "")

        # --- CVSS ---
        cvss_score, cvss_severity, cvss_vector = _extract_cvss(cna.get("metrics", []))

        # --- References (from CVE + MISP) ---
        ref_urls = [r.get("url", "") for r in cna.get("references", []) if r.get("url")]
        misp_info = misp_index.get(cve_id, {})
        for mref in misp_info.get("references", []):
            if mref and mref not in ref_urls:
                ref_urls.append(mref)
        refs_json = json.dumps(ref_urls) if ref_urls else None

        # --- MISP enrichment ---
        credit = misp_info.get("credit", "") or None
        misp_threat = misp_info.get("threat_level") if misp_info else None
        misp_date = misp_info.get("event_date") or None
        misp_tags = misp_info.get("tags") or None

        # --- Insert vulnerability ---
        cur.execute(
            """INSERT OR IGNORE INTO vulnerability
               (vuln_id, description, title, date_published, date_updated,
                cvss_base_score, cvss_severity, cvss_vector,
                references_json, credit, misp_threat_level, misp_event_date, misp_tags)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (cve_id, desc, title or None, date_published or None, date_updated or None,
             cvss_score, cvss_severity or None, cvss_vector or None,
             refs_json, credit, misp_threat, misp_date, misp_tags),
        )

        # --- Vulnerability Type + junction ---
        for pt in cna.get("problemTypes", []):
            for d in pt.get("descriptions", []):
                tid = d.get("cweId", "")
                if not tid:
                    continue
                cur.execute("INSERT OR IGNORE INTO vulnerability_type (id, description) VALUES (?,?)",
                            (tid, d.get("description", "")))
                cur.execute("INSERT OR IGNORE INTO vulnerability_is_a (vuln_id, type_id) VALUES (?,?)",
                            (cve_id, tid))

        # --- Affected: Vendor → Software → SW Version → vulnerable_to ---
        for af in cna.get("affected", []):
            v_name = (af.get("vendor") or "").strip()
            p_name = (af.get("product") or "").strip()
            if v_name.lower() in ("n/a", "") and p_name.lower() in ("n/a", ""):
                continue

            vk = v_name.lower()
            if vk not in vendor_cache:
                cur.execute("INSERT OR IGNORE INTO vendor (name) VALUES (?)", (v_name,))
                cur.execute("SELECT id FROM vendor WHERE name=?", (v_name,))
                vendor_cache[vk] = cur.fetchone()[0]
            vid = vendor_cache[vk]

            sk = (vid, p_name.lower())
            if sk not in sw_cache:
                cur.execute("SELECT id FROM software WHERE name=? AND vendor_id=?", (p_name, vid))
                row = cur.fetchone()
                if row:
                    sw_cache[sk] = row[0]
                else:
                    cur.execute("INSERT INTO software (name, vendor_id) VALUES (?,?)", (p_name, vid))
                    sw_cache[sk] = cur.lastrowid
            sid = sw_cache[sk]

            for ver in af.get("versions", []):
                ver_str = ver.get("version", "")
                if not ver_str:
                    continue
                cur.execute("INSERT INTO sw_version (version_string, software_id) VALUES (?,?)",
                            (ver_str, sid))
                svid = cur.lastrowid
                cur.execute("INSERT OR IGNORE INTO sw_version_vulnerable_to (sw_version_id, vuln_id) VALUES (?,?)",
                            (svid, cve_id))

    conn.commit()

    # --- Stats ---
    all_tables = [
        "vendor", "software", "software_type", "sw_version", "license",
        "hardware", "hw_version", "vulnerability", "vulnerability_type",
        "sw_version_vulnerable_to", "hw_version_vulnerable_to",
        "vulnerability_is_a", "sw_version_depends_on", "sw_version_operate_on",
    ]
    print(f"\n{'='*55}")
    print(f"  {DB_PATH}")
    print(f"{'='*55}")
    for t in all_tables:
        n = cur.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
        kind = "junction" if "_vulnerable_to" in t or "_is_a" in t or "_depends_on" in t or "_operate_on" in t else "entity"
        mark = "" if n > 0 else " (empty)"
        print(f"  {kind:8s}  {t:30s} {n:>6}{mark}")

    # Enrichment stats
    enriched = cur.execute("SELECT COUNT(*) FROM vulnerability WHERE title IS NOT NULL").fetchone()[0]
    with_cvss = cur.execute("SELECT COUNT(*) FROM vulnerability WHERE cvss_base_score IS NOT NULL").fetchone()[0]
    with_misp = cur.execute("SELECT COUNT(*) FROM vulnerability WHERE misp_threat_level IS NOT NULL").fetchone()[0]
    total_vuln = cur.execute("SELECT COUNT(*) FROM vulnerability").fetchone()[0]
    print(f"\n  Enrichment:")
    print(f"    title:       {enriched}/{total_vuln}")
    print(f"    CVSS:        {with_cvss}/{total_vuln}")
    print(f"    MISP data:   {with_misp}/{total_vuln}")
    print()
    conn.close()


if __name__ == "__main__":
    build()
