#!/usr/bin/env python3
"""
Enrich the KB with CISA's Known Exploited Vulnerabilities (KEV) catalog.

KEV (https://www.cisa.gov/known-exploited-vulnerabilities-catalog) lists CVEs
with *verified* in-the-wild exploitation. This importer does NOT add new
vulnerability rows (the catalog is mostly non-AI); it enriches vulnerabilities
already in the KB:

  - vulnerability.exploited_in_wild          1 for every KB vuln found in KEV
  - vulnerability.exploitation_verified_date KEV dateAdded (when CISA verified it)
  - vulnerability.ransomware_use             KEV knownRansomwareCampaignUse (Known/Unknown)
  - vulnerability_external_id                (vuln_id, 'KEV', CVE id) provenance row

Per the source-neutral schema rule, the columns are generic exploitation
attributes; the KEV provenance lives only in the external-reference table.

Matching: KEV cveID against vulnerability.vuln_id AND against CVE ids in
vulnerability_external_id (covers AVID/GHSA-keyed vulns cross-referenced to a CVE).

Re-running is idempotent and handles catalog updates: flags are recomputed from
the current feed on every run.

Usage:
  cd query_engine && python3 scripts/import_kev.py            # download + import
  python3 scripts/import_kev.py --kev-file kev.json           # use a local copy
  python3 scripts/import_kev.py --dry-run                     # report matches only
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
QE_ROOT = os.path.dirname(HERE)

DB_PATH = os.path.join(QE_ROOT, "ai_vuln_kb.db")
KEV_FEED_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

def ensure_columns(conn: sqlite3.Connection) -> None:
    """Add generic exploitation columns to vulnerability if missing."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(vulnerability)")}
    new_cols = {
        "exploited_in_wild": "INTEGER NOT NULL DEFAULT 0",
        "exploitation_verified_date": "TEXT",
        "ransomware_use": "TEXT",
    }
    for col, typ in new_cols.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE vulnerability ADD COLUMN {col} {typ}")
    conn.commit()


# ---------------------------------------------------------------------------
# Feed
# ---------------------------------------------------------------------------

def load_kev(kev_file: str | None) -> dict:
    if kev_file:
        with open(kev_file, encoding="utf-8") as f:
            return json.load(f)
    resp = requests.get(KEV_FEED_URL, timeout=60)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Matching + enrichment
# ---------------------------------------------------------------------------

def cve_to_vuln_map(conn: sqlite3.Connection) -> dict[str, str]:
    """Map CVE id -> KB vuln_id, via the primary key and the external-id table."""
    mapping: dict[str, str] = {}
    for (ext_id, vuln_id) in conn.execute(
            "SELECT external_id, vuln_id FROM vulnerability_external_id "
            "WHERE external_id LIKE 'CVE-%'"):
        mapping[ext_id.upper()] = vuln_id
    # Primary key wins over cross-references.
    for (vuln_id,) in conn.execute(
            "SELECT vuln_id FROM vulnerability WHERE vuln_id LIKE 'CVE-%'"):
        mapping[vuln_id.upper()] = vuln_id
    return mapping


def import_kev(conn: sqlite3.Connection, kev: dict, dry_run: bool = False) -> dict:
    entries = kev.get("vulnerabilities", [])
    mapping = cve_to_vuln_map(conn)

    matches: list[tuple[dict, str]] = []
    for e in entries:
        vuln_id = mapping.get((e.get("cveID") or "").upper())
        if vuln_id:
            matches.append((e, vuln_id))

    stats = {
        "catalog_version": kev.get("catalogVersion"),
        "kev_entries": len(entries),
        "kb_matches": len(matches),
        "flagged": 0,
        "unflagged": 0,
    }
    if dry_run:
        stats["matched"] = [(e["cveID"], v) for e, v in matches]
        return stats

    # Recompute from the current feed: clear stale flags, then set matches.
    matched_ids = {v for _e, v in matches}
    cur = conn.execute(
        "UPDATE vulnerability SET exploited_in_wild = 0, "
        "exploitation_verified_date = NULL, ransomware_use = NULL "
        "WHERE exploited_in_wild = 1 AND vuln_id NOT IN (%s)"
        % ",".join("?" * len(matched_ids)), tuple(matched_ids))
    stats["unflagged"] = cur.rowcount

    for e, vuln_id in matches:
        conn.execute(
            """UPDATE vulnerability
               SET exploited_in_wild = 1,
                   exploitation_verified_date = ?,
                   ransomware_use = ?
               WHERE vuln_id = ?""",
            (e.get("dateAdded"), e.get("knownRansomwareCampaignUse"), vuln_id))
        conn.execute(
            """INSERT OR IGNORE INTO vulnerability_external_id
               (vuln_id, source, external_id) VALUES (?, 'KEV', ?)""",
            (vuln_id, e["cveID"]))
        stats["flagged"] += 1

    conn.commit()
    return stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Enrich KB vulns from the CISA KEV catalog.")
    ap.add_argument("--db", default=DB_PATH, help=f"SQLite DB path (default {DB_PATH})")
    ap.add_argument("--kev-file", help="Local KEV JSON instead of downloading the feed")
    ap.add_argument("--dry-run", action="store_true", help="Report matches, change nothing")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"error: DB not found at {args.db} (run build_db.py first)", file=sys.stderr)
        raise SystemExit(1)

    kev = load_kev(args.kev_file)
    conn = sqlite3.connect(args.db)
    try:
        conn.execute("PRAGMA busy_timeout = 10000")
        ensure_columns(conn)
        stats = import_kev(conn, kev, dry_run=args.dry_run)
    finally:
        conn.close()

    print(f"KEV catalog {stats['catalog_version']}: {stats['kev_entries']} entries")
    print(f"KB matches: {stats['kb_matches']}")
    if args.dry_run:
        for cve, vuln_id in stats["matched"]:
            print(f"  {cve} -> {vuln_id}")
    else:
        print(f"flagged exploited_in_wild=1: {stats['flagged']}"
              f"  (stale flags cleared: {stats['unflagged']})")


if __name__ == "__main__":
    main()
