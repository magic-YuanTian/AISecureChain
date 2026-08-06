#!/usr/bin/env python3
"""Wipe local KB (SQLite + TTL) and recreate empty schema + schema-only RDF.

Track A (extract quality — validate skipped):
  python scripts/reset_kb.py

Track B (validate runs — seed CWEs into the TTL registry):
  python scripts/reset_kb.py --seed-cwes CWE-346,CWE-284,CWE-940,CWE-1427

Restart Flask after running this.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

QE_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = QE_ROOT / "ai_vuln_kb.db"
TTL_PATH = QE_ROOT / "ai_vuln_kb.ttl"

# ClaudeBleed / SecurityWeek gold set — useful default for Track B demos
DEFAULT_SEED_CWES = [
    ("CWE-346", "Origin Validation Error"),
    ("CWE-284", "Improper Access Control"),
    ("CWE-940", "Improper Verification of Source of a Communication Channel"),
    ("CWE-1427", "Improper Neutralization of Input Used for LLM Prompting"),
]


def _wipe() -> None:
    for path in (DB_PATH, TTL_PATH, QE_ROOT / "ai_vuln_kb.db-wal", QE_ROOT / "ai_vuln_kb.db-shm"):
        if path.exists():
            path.unlink()
            print(f"removed {path.name}")


def _init_schema() -> None:
    sys.path.insert(0, str(QE_ROOT))
    from build_db import SCHEMA
    from extract_pipeline.persist import ensure_persist_schema
    from sources.schema import ensure_schema

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(SCHEMA)
        ensure_persist_schema(conn=conn)
        ensure_schema(conn)
        conn.commit()
    finally:
        conn.close()
    print(f"empty schema → {DB_PATH.name}")


def _seed_cwes(ids: list[str] | None) -> int:
    """Insert VulnerabilityType rows. Unknown ids get id-as-description."""
    catalog = {cwe_id: desc for cwe_id, desc in DEFAULT_SEED_CWES}
    if ids is None:
        rows = list(DEFAULT_SEED_CWES)
    else:
        rows = [(i.upper(), catalog.get(i.upper(), i.upper())) for i in ids if i.strip()]

    if not rows:
        return 0

    conn = sqlite3.connect(DB_PATH)
    try:
        for cwe_id, desc in rows:
            conn.execute(
                "INSERT OR REPLACE INTO vulnerability_type (id, description) VALUES (?, ?)",
                (cwe_id, desc),
            )
        conn.commit()
    finally:
        conn.close()
    print(f"seeded {len(rows)} VulnerabilityType(s): {', '.join(r[0] for r in rows)}")
    return len(rows)


def _build_rdf() -> None:
    sys.path.insert(0, str(QE_ROOT))
    import build_rdf

    build_rdf.build()
    print(f"RDF → {TTL_PATH.name}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--seed-cwes",
        nargs="?",
        const="DEFAULT",
        default=None,
        metavar="IDS",
        help=(
            "Seed VulnerabilityType registry so validate runs. "
            "Omit IDS to use ClaudeBleed defaults; or pass comma-separated CWE ids."
        ),
    )
    p.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")
    args = p.parse_args()

    if not args.yes:
        reply = input(f"Wipe {DB_PATH.name} + {TTL_PATH.name} and reset? [y/N] ").strip().lower()
        if reply not in ("y", "yes"):
            print("aborted")
            return 1

    _wipe()
    _init_schema()

    if args.seed_cwes is not None:
        if args.seed_cwes == "DEFAULT":
            _seed_cwes(None)
        else:
            _seed_cwes([x.strip() for x in args.seed_cwes.split(",") if x.strip()])

    _build_rdf()
    print("\nDone. Restart Flask (python app.py) before extracting.")
    if args.seed_cwes is None:
        print("Mode: Track A — empty CWE registry → validate skipped, findings kept.")
    else:
        print("Mode: Track B — CWE registry seeded → validate will run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
