"""
Classify each software_type as AI-related (is_ai = 1) or not (is_ai = 0)
using LLM, then persist results into the database.
"""

import json
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "ai_vuln_kb.db")

SYSTEM_PROMPT = """You are an AI/ML domain expert. Given a list of software category names, classify each as AI-related or not.

A category is AI-related if it is primarily about artificial intelligence, machine learning, deep learning, NLP, computer vision, autonomous agents, or data science.

Respond with a JSON array. Each element: {"name": "<category_name>", "is_ai": true/false}.
Return ONLY the JSON array, no explanation, no markdown fences."""


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=ON")
    cur = conn.cursor()

    rows = cur.execute("SELECT id, name FROM software_type").fetchall()
    if not rows:
        print("No software_type rows found. Run build_db.py and classify_software.py first.")
        return

    print(f"Classifying {len(rows)} software types …")
    names = [{"name": r[1]} for r in rows]
    id_by_name = {r[1].lower(): r[0] for r in rows}

    from utils.openai_api import get_response

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(names)},
    ]
    raw = get_response(messages, temperature=0).strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
        raw = raw.rsplit("```", 1)[0]
    results = json.loads(raw)

    for r in results:
        rname = r.get("name", "")
        is_ai = 1 if r.get("is_ai") else 0
        tid = id_by_name.get(rname.lower())
        if tid is None:
            print(f"  WARNING: '{rname}' not found in DB, skipping")
            continue
        cur.execute("UPDATE software_type SET is_ai = ? WHERE id = ?", (is_ai, tid))
        print(f"  {rname:25s} → is_ai={is_ai}")

    conn.commit()

    print("\nFinal distribution:")
    for row in cur.execute("SELECT name, is_ai FROM software_type ORDER BY is_ai DESC, name"):
        label = "AI" if row[1] else "non-AI"
        print(f"  {row[0]:25s} {label}")

    conn.close()


if __name__ == "__main__":
    main()
