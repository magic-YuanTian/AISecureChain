#!/usr/bin/env python3
"""CLI for advisory CWE lookup (NVD CVE / GitHub GHSA).

Usage
-----
  cd query_engine
  ./myenv/bin/python scripts/lookup_advisory_cwe.py CVE-2021-44228
  ./myenv/bin/python scripts/lookup_advisory_cwe.py GHSA-jfh8-c2jp-5v3q --follow-cve --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

QE_ROOT = Path(__file__).resolve().parents[1]
if str(QE_ROOT) not in sys.path:
    sys.path.insert(0, str(QE_ROOT))

from extract_pipeline.advisory_cwe import lookup  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ids", nargs="+", help="One or more CVE-… and/or GHSA-… ids")
    ap.add_argument(
        "--follow-cve",
        action="store_true",
        help="For GHSA with no CWE but a linked CVE, also query NVD",
    )
    ap.add_argument("--json", action="store_true", help="Print full JSON results")
    args = ap.parse_args()

    results = [lookup(i, follow_cve=args.follow_cve) for i in args.ids]

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
        return 0

    for r in results:
        cwes = ", ".join(r.get("cwes") or []) or "(none)"
        err = r.get("error")
        line = f"{r.get('id')}: {cwes}"
        if err:
            line += f"  [{err}]"
        print(line)
        if r.get("cves") and r.get("source") == "github":
            print(f"  linked CVEs: {', '.join(r['cves'])}")
        if r.get("nvd"):
            print(f"  nvd follow-up: {', '.join(r['nvd'].get('cwes') or []) or '(none)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
