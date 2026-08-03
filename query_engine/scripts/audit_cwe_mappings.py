"""Audit and repair VulnerabilityType (CWE) mappings written by the old mapper.

Why this exists
---------------
`validator.py::_candidate_types` used to fall through to raw token-overlap
scoring, and ties were broken by *string-sorted CWE id*. One shared generic
word was therefore enough to let an arbitrary low-numbered CWE win — e.g.
CVE-2025-3108 ("unsafe deserialization … remote code execution") was stored as
CWE-1112 "Incomplete Documentation of Program Execution", because both texts
contain "execution" and "CWE-1112" sorts before the correct "CWE-502".

The scorer is fixed (keyword rules + a >=2 shared-token floor), but rows
written by the old code remain in the database. This script repairs them.

Why the corrections are hand-curated
------------------------------------
Re-running the *current* scorer and taking its top-1 was tried and rejected: it
proposed CWE-94 for plain denial-of-service records and wanted to replace
CWE-1385 ("Missing Origin Validation in WebSockets") — the precise, correct
type for two WebSocket-hijacking CVEs — with the vaguer CWE-346. An automatic
rewrite would have made those rows worse. So each change below was reviewed
against the record's own title/description, and records whose stored type is
already correct or merely arguable are explicitly KEPT.

Usage
-----
    cd query_engine
    python -m scripts.audit_cwe_mappings            # show the plan (default)
    python -m scripts.audit_cwe_mappings --apply    # write it
    python -m scripts.audit_cwe_mappings --scan     # re-scan for NEW suspects

Re-running after --apply is safe: a correction is skipped unless the row still
holds the exact `from` value.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
QUERY_ENGINE = os.path.dirname(HERE)
sys.path.insert(0, QUERY_ENGINE)

from extract_pipeline.validator import (  # noqa: E402
    _candidate_types,
    predefined_vulnerability_types,
)

DB_PATH = os.path.join(QUERY_ENGINE, "ai_vuln_kb.db")

# (vuln_id, from_type, to_type, why) — reviewed one by one against the record.
CORRECTIONS: list[tuple[str, str, str, str]] = [
    ("CVE-2025-3108", "CWE-1112", "CWE-502",
     "unsafe deserialization in JsonPickleSerializer; CWE-1112 (documentation) is unrelated"),
    ("CVE-2024-12777", "CWE-1088", "CWE-400",
     "denial of service via resource consumption, not a missing-timeout issue"),
    ("CVE-2024-8061", "CWE-1088", "CWE-400", "denial of service in aimhubio/aim"),
    ("CVE-2024-8062", "CWE-1088", "CWE-400", "denial of service in h2oai/h2o-3"),
    ("CVE-2025-0190", "CWE-1049", "CWE-400", "denial of service in aimhubio/aim"),
    ("CVE-2022-39366", "CWE-303", "CWE-347",
     "DataHub omits the JWT signature check — improper verification of a cryptographic signature"),
    ("CVE-2024-8143", "CWE-1057", "CWE-862",
     "chat history reachable without an authorization check"),
    ("AISC-2026-FE584E", "CWE-265", "CWE-451",
     "fake help page tricking users into installing malware — UI misrepresentation, not a sandbox issue"),
]

# Rows the scan flags but that must NOT be rewritten, with the reason. Keeping
# these documented stops the next person from "fixing" them.
KEEP: list[tuple[str, str, str]] = [
    ("CVE-2023-2886", "CWE-1385",
     "cross-site WebSocket hijacking — CWE-1385 is the precise type; CWE-346 would be vaguer"),
    ("CVE-2025-52882", "CWE-1385",
     "IDE extension accepts WebSocket connections from arbitrary origins — CWE-1385 is exactly right"),
    ("CVE-2025-5321", "CWE-265",
     "RestrictedPython sandbox bypass — 'Sandbox Issue' is defensible; no clearly better type"),
    ("CVE-2026-27007", "CWE-1254",
     "config-hash comparison granularity flaw — stored type is arguable, leave to a human"),
    ("CVE-2022-36022", "CWE-344",
     "unclaimed S3 bucket used by tests; no in-registry type is clearly better"),
]

# Types the old tie-break favoured. CWE-1385 is deliberately ABSENT: it is a
# legitimate, precise type (see KEEP above).
LOW_SIGNAL = {
    "CWE-1112", "CWE-1049", "CWE-1057", "CWE-1088", "CWE-1254",
    "CWE-344", "CWE-303", "CWE-265",
}


def show_plan(conn: sqlite3.Connection) -> list[tuple[str, str, str, str]]:
    registry = predefined_vulnerability_types()
    conn.row_factory = sqlite3.Row
    pending = []
    print(f"\n{'vuln_id':<20}{'from':<11}{'to':<11}reason")
    print("-" * 108)
    for vuln_id, frm, to, why in CORRECTIONS:
        row = conn.execute(
            "SELECT 1 FROM vulnerability_is_a WHERE vuln_id=? AND type_id=?", (vuln_id, frm)
        ).fetchone()
        if not row:
            print(f"{vuln_id:<20}{frm:<11}{to:<11}(already applied or row absent — skipped)")
            continue
        if to not in registry:
            print(f"{vuln_id:<20}{frm:<11}{to:<11}!! target not in registry — skipped")
            continue
        pending.append((vuln_id, frm, to, why))
        print(f"{vuln_id:<20}{frm:<11}{to:<11}{why}")
    print(f"\nKEEP (flagged by the scan but correct as stored):")
    for vuln_id, typ, why in KEEP:
        print(f"  {vuln_id:<20}{typ:<11}{why}")
    return pending


def apply(conn: sqlite3.Connection, pending) -> int:
    for vuln_id, frm, to, _why in pending:
        conn.execute(
            "UPDATE vulnerability_is_a SET type_id=? WHERE vuln_id=? AND type_id=?",
            (to, vuln_id, frm),
        )
    conn.commit()
    return len(pending)


def scan(conn: sqlite3.Connection) -> None:
    """Re-scan the whole KB for mappings the current scorer no longer supports."""
    registry = predefined_vulnerability_types()
    conn.row_factory = sqlite3.Row
    known = {v for v, *_ in CORRECTIONS} | {v for v, *_ in KEEP}
    rows = conn.execute(
        """SELECT v.vuln_id, v.title, v.description, vi.type_id
           FROM vulnerability_is_a vi JOIN vulnerability v ON v.vuln_id = vi.vuln_id"""
    ).fetchall()
    hits = 0
    for row in rows:
        current = (row["type_id"] or "").strip().upper()
        if current not in LOW_SIGNAL or row["vuln_id"] in known:
            continue
        text = "\n".join(str(row[k] or "") for k in ("vuln_id", "title", "description"))
        ranked = _candidate_types(text, registry)
        if current in {vt.id for vt in ranked[:3]}:
            continue
        hits += 1
        print(f"  NEW SUSPECT {row['vuln_id']:<20}{current:<11}{(row['title'] or '')[:60]}")
        print(f"{'':<34}current scorer prefers: {[vt.id for vt in ranked[:3]]}")
    print(f"\n{hits} unreviewed suspect(s).")


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit/repair stored CWE mappings.")
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--apply", action="store_true", help="Write the corrections")
    ap.add_argument("--scan", action="store_true", help="Look for new, unreviewed suspects")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db, timeout=30)
    if args.scan:
        scan(conn)
        conn.close()
        return

    pending = show_plan(conn)
    if args.apply and pending:
        n = apply(conn, pending)
        print(f"\n{n} mapping(s) rewritten.")
    elif pending:
        print(f"\n{len(pending)} pending — re-run with --apply to write them.")
    else:
        print("\nnothing to do.")
    conn.close()


if __name__ == "__main__":
    main()
