#!/usr/bin/env python3
"""
Migrate vulnerability schema: cve_id → vuln_id (universal identifier).

Changes:
  1. vulnerability.cve_id        → vulnerability.vuln_id
  2. vulnerability_is_a.cve_id   → vulnerability_is_a.vuln_id
  3. sw_version_vulnerable_to.cve_id → sw_version_vulnerable_to.vuln_id
  4. hw_version_vulnerable_to.cve_id → hw_version_vulnerable_to.vuln_id
  5. NEW TABLE: vulnerability_external_id  (vuln_id, source, external_id)
     — one row per external identifier (CVE, AVID, GHSA, OSV, etc.)
  6. Drop avid_id column (moved to external_id table)

The migration re-creates tables because SQLite cannot rename column + re-key in place.
A backup is created at ai_vuln_kb.db.bak before any changes.

Usage:
  cd query_engine && python3 scripts/migrate_vuln_id.py
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
QE_ROOT = os.path.dirname(HERE)
DB_PATH = os.path.join(QE_ROOT, "ai_vuln_kb.db")
BACKUP_PATH = DB_PATH + ".bak"


def migrate(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()

    # ── 1. vulnerability ──
    cur.execute("""
        CREATE TABLE vulnerability_new (
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
            avid_class        TEXT
        )
    """)
    cur.execute("""
        INSERT INTO vulnerability_new
        SELECT cve_id, description, title, date_published, date_updated,
               cvss_base_score, cvss_severity, cvss_vector,
               references_json, credit,
               misp_threat_level, misp_event_date, misp_tags,
               source, risk_domain, sep_view, lifecycle_view, avid_class
        FROM vulnerability
    """)

    # ── 2. vulnerability_is_a ──
    cur.execute("""
        CREATE TABLE vulnerability_is_a_new (
            vuln_id TEXT NOT NULL REFERENCES vulnerability_new(vuln_id),
            type_id TEXT NOT NULL REFERENCES vulnerability_type(id),
            PRIMARY KEY (vuln_id, type_id)
        )
    """)
    cur.execute("""
        INSERT INTO vulnerability_is_a_new
        SELECT cve_id, type_id FROM vulnerability_is_a
    """)

    # ── 3. sw_version_vulnerable_to ──
    cur.execute("""
        CREATE TABLE sw_version_vulnerable_to_new (
            sw_version_id INTEGER NOT NULL REFERENCES sw_version(id),
            vuln_id       TEXT    NOT NULL REFERENCES vulnerability_new(vuln_id),
            PRIMARY KEY (sw_version_id, vuln_id)
        )
    """)
    cur.execute("""
        INSERT INTO sw_version_vulnerable_to_new
        SELECT sw_version_id, cve_id FROM sw_version_vulnerable_to
    """)

    # ── 4. hw_version_vulnerable_to ──
    cur.execute("""
        CREATE TABLE hw_version_vulnerable_to_new (
            hw_version_id INTEGER NOT NULL REFERENCES hw_version(id),
            vuln_id       TEXT    NOT NULL REFERENCES vulnerability_new(vuln_id),
            PRIMARY KEY (hw_version_id, vuln_id)
        )
    """)
    cur.execute("""
        INSERT INTO hw_version_vulnerable_to_new
        SELECT hw_version_id, cve_id FROM hw_version_vulnerable_to
    """)

    # ── 5. vulnerability_external_id (new) ──
    cur.execute("""
        CREATE TABLE vulnerability_external_id (
            vuln_id     TEXT NOT NULL,
            source      TEXT NOT NULL,
            external_id TEXT NOT NULL,
            PRIMARY KEY (vuln_id, source, external_id),
            FOREIGN KEY (vuln_id) REFERENCES vulnerability_new(vuln_id)
        )
    """)

    # Populate from existing data:
    #   a) every vuln_id that looks like CVE-xxxx → source='CVE'
    cur.execute("""
        INSERT OR IGNORE INTO vulnerability_external_id (vuln_id, source, external_id)
        SELECT vuln_id, 'CVE', vuln_id FROM vulnerability_new
        WHERE vuln_id LIKE 'CVE-%'
    """)
    #   b) every vuln_id that looks like AVID-xxxx → source='AVID'
    cur.execute("""
        INSERT OR IGNORE INTO vulnerability_external_id (vuln_id, source, external_id)
        SELECT vuln_id, 'AVID', vuln_id FROM vulnerability_new
        WHERE vuln_id LIKE 'AVID-%'
    """)
    #   c) cross-reference: records whose vuln_id is a CVE but also have an avid_id
    #      (from the old avid_id column before we drop it)
    existing_cols = {r[1] for r in cur.execute("PRAGMA table_info(vulnerability)")}
    if "avid_id" in existing_cols:
        cur.execute("""
            INSERT OR IGNORE INTO vulnerability_external_id (vuln_id, source, external_id)
            SELECT cve_id, 'AVID', avid_id FROM vulnerability
            WHERE avid_id IS NOT NULL AND avid_id != ''
        """)

    # ── Drop old tables, rename new ──
    cur.execute("DROP TABLE sw_version_vulnerable_to")
    cur.execute("DROP TABLE hw_version_vulnerable_to")
    cur.execute("DROP TABLE vulnerability_is_a")
    cur.execute("DROP TABLE vulnerability")

    cur.execute("ALTER TABLE vulnerability_new RENAME TO vulnerability")
    cur.execute("ALTER TABLE vulnerability_is_a_new RENAME TO vulnerability_is_a")
    cur.execute("ALTER TABLE sw_version_vulnerable_to_new RENAME TO sw_version_vulnerable_to")
    cur.execute("ALTER TABLE hw_version_vulnerable_to_new RENAME TO hw_version_vulnerable_to")

    cur.execute("CREATE INDEX idx_vuln_ext_source ON vulnerability_external_id(source, external_id)")

    conn.commit()


def verify(conn: sqlite3.Connection) -> None:
    counts = {}
    for tbl in ["vulnerability", "vulnerability_is_a",
                "sw_version_vulnerable_to", "hw_version_vulnerable_to",
                "vulnerability_external_id"]:
        counts[tbl] = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]

    print("\n=== Post-migration verification ===")
    for t, c in counts.items():
        print(f"  {t:40s} {c}")

    # Check external ID distribution
    print("\n  External ID sources:")
    for row in conn.execute(
        "SELECT source, COUNT(*) FROM vulnerability_external_id GROUP BY source ORDER BY COUNT(*) DESC"
    ):
        print(f"    {row[0]:10s} {row[1]}")

    # Sanity: sample
    print("\n  Sample vuln_id values:")
    for row in conn.execute("SELECT vuln_id FROM vulnerability ORDER BY RANDOM() LIMIT 5"):
        print(f"    {row[0]}")


def main() -> None:
    if not os.path.isfile(DB_PATH):
        print(f"DB not found: {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    # Check if already migrated
    conn = sqlite3.connect(DB_PATH)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(vulnerability)")}
    if "vuln_id" in cols:
        print("Already migrated (vuln_id column exists). Skipping.")
        conn.close()
        return

    conn.close()

    # Backup
    shutil.copyfile(DB_PATH, BACKUP_PATH)
    print(f"Backup → {BACKUP_PATH}")

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=OFF")

    print("Migrating cve_id → vuln_id …")
    migrate(conn)
    verify(conn)

    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA integrity_check")
    print("\nIntegrity check passed.")
    conn.close()
    print("Done.")


if __name__ == "__main__":
    main()
