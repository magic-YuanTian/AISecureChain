"""
AISecureChain — Ontology Knowledge Base Query Tool
===================================================
Usage:
    python query_engine/query_kb.py                 # interactive
    python query_engine/query_kb.py "SELECT ..."    # one-shot
    python query_engine/query_kb.py --examples
"""

import os, sqlite3, sys, textwrap

DB_PATH = os.path.join(os.path.dirname(__file__), "ai_vuln_kb.db")

EXAMPLES = {
    "overview": {
        "title": "Row counts for all tables",
        "sql": """
            SELECT 'vendor' AS tbl, COUNT(*) AS n FROM vendor
            UNION ALL SELECT 'software', COUNT(*) FROM software
            UNION ALL SELECT 'software_type', COUNT(*) FROM software_type
            UNION ALL SELECT 'sw_version', COUNT(*) FROM sw_version
            UNION ALL SELECT 'license', COUNT(*) FROM license
            UNION ALL SELECT 'hardware', COUNT(*) FROM hardware
            UNION ALL SELECT 'hw_version', COUNT(*) FROM hw_version
            UNION ALL SELECT 'vulnerability', COUNT(*) FROM vulnerability
            UNION ALL SELECT 'vulnerability_type', COUNT(*) FROM vulnerability_type
            UNION ALL SELECT '---', NULL
            UNION ALL SELECT 'sw_version_vulnerable_to', COUNT(*) FROM sw_version_vulnerable_to
            UNION ALL SELECT 'hw_version_vulnerable_to', COUNT(*) FROM hw_version_vulnerable_to
            UNION ALL SELECT 'vulnerability_is_a', COUNT(*) FROM vulnerability_is_a
            UNION ALL SELECT 'sw_version_depends_on', COUNT(*) FROM sw_version_depends_on
            UNION ALL SELECT 'sw_version_operate_on', COUNT(*) FROM sw_version_operate_on
        """,
    },
    "top_type": {
        "title": "Top 15 types (CWE) by CVE count",
        "sql": """
            SELECT vt.id, vt.description, COUNT(*) AS cnt
            FROM vulnerability_is_a via JOIN vulnerability_type vt ON via.type_id=vt.id
            GROUP BY vt.id ORDER BY cnt DESC LIMIT 15
        """,
    },
    "top_vendor": {
        "title": "Top 15 vendors by vulnerability count",
        "sql": """
            SELECT v.name, COUNT(DISTINCT svt.vuln_id) AS vulns
            FROM vendor v
            JOIN software s ON s.vendor_id=v.id
            JOIN sw_version sv ON sv.software_id=s.id
            JOIN sw_version_vulnerable_to svt ON svt.sw_version_id=sv.id
            GROUP BY v.id ORDER BY vulns DESC LIMIT 15
        """,
    },
    "top_product": {
        "title": "Top 15 products by vulnerability count",
        "sql": """
            SELECT s.name, v.name AS vendor, COUNT(DISTINCT svt.vuln_id) AS vulns
            FROM software s
            JOIN vendor v ON s.vendor_id=v.id
            JOIN sw_version sv ON sv.software_id=s.id
            JOIN sw_version_vulnerable_to svt ON svt.sw_version_id=sv.id
            GROUP BY s.id ORDER BY vulns DESC LIMIT 15
        """,
    },
    "full_path": {
        "title": "Vendor → Software → Version → Vulnerability → Type",
        "sql": """
            SELECT v.name AS vendor, s.name AS software, sv.version_string,
                   vuln.vuln_id, vt.id AS type_id
            FROM vendor v
            JOIN software s ON s.vendor_id=v.id
            JOIN sw_version sv ON sv.software_id=s.id
            JOIN sw_version_vulnerable_to svt ON svt.sw_version_id=sv.id
            JOIN vulnerability vuln ON svt.vuln_id=vuln.vuln_id
            JOIN vulnerability_is_a via ON via.vuln_id=vuln.vuln_id
            JOIN vulnerability_type vt ON via.type_id=vt.id
            LIMIT 20
        """,
    },
}


def print_table(headers, rows, max_w=60):
    if not rows: print("  (no results)"); return
    sr = [[textwrap.shorten(str(v) if v is not None else "", width=max_w, placeholder="…") for v in r] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in sr)) for i, h in enumerate(headers)]
    sep = "+-" + "-+-".join("-"*w for w in widths) + "-+"
    print(sep)
    print("| " + " | ".join(h.ljust(w) for h, w in zip(headers, widths)) + " |")
    print(sep)
    for r in sr: print("| " + " | ".join(c.ljust(w) for c, w in zip(r, widths)) + " |")
    print(sep)
    print(f"  ({len(rows)} rows)")


def run_query(conn, sql):
    cur = conn.execute(sql)
    print_table([d[0] for d in cur.description], cur.fetchall())


def interactive(conn):
    print("="*50)
    print("  AISecureChain KB — !examples, !run <name>, !schema, !quit")
    print("="*50)
    while True:
        try: line = input("kb> ").strip()
        except (EOFError, KeyboardInterrupt): print(); break
        if not line: continue
        if line.lower() in ("!quit","!exit","quit","exit"): break
        if line.lower() in ("!examples","!ex"):
            for n, e in EXAMPLES.items(): print(f"  {n:15s} — {e['title']}")
            print(); continue
        if line.lower().startswith("!run "):
            n = line[5:].strip()
            if n in EXAMPLES:
                print(f"\n  >> {EXAMPLES[n]['title']}\n")
                try: run_query(conn, EXAMPLES[n]["sql"])
                except Exception as e: print(f"  ERROR: {e}")
                print()
            else: print(f"  Unknown: {n}")
            continue
        if line.lower() == "!schema":
            for (sql,) in conn.execute("SELECT sql FROM sqlite_master WHERE type='table' ORDER BY name"):
                if sql: print(sql+";\n")
            continue
        try: run_query(conn, line)
        except Exception as e: print(f"  ERROR: {e}")
        print()


def main():
    if not os.path.exists(DB_PATH):
        print(f"Not found: {DB_PATH}"); sys.exit(1)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=ON")
    if len(sys.argv) > 1:
        arg = " ".join(sys.argv[1:])
        if arg == "--examples":
            for n, e in EXAMPLES.items():
                print(f"\n{'='*50}\n  [{n}] {e['title']}\n{'='*50}")
                run_query(conn, e["sql"]); print()
        else: run_query(conn, arg)
    else: interactive(conn)
    conn.close()


if __name__ == "__main__":
    main()
