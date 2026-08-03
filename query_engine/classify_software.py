"""
Classify each software into one of the 8 predefined software_type categories
using LLM, then persist results into the database.
"""

import json
import os
import sqlite3
import sys
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "ai_vuln_kb.db")

TYPES = [
    "Agent",
    "Model",
    "Dataset",
    "ML infrastructure",
    "Skill",
    "Application",
    "Library",
    "Database",
]

TYPES_LOWER = {t.lower(): t for t in TYPES}

SYSTEM_PROMPT = f"""You are a careful software taxonomy and AI-specificity classifier. Given a list of software products (name + vendor), classify each into exactly ONE category and also decide whether that specific software should be marked AI-related.

{chr(10).join(f'- {t}' for t in TYPES)}

Rules:
- Respond with a JSON array. Each element must be {{"name": "<software_name>", "vendor": "<vendor_name>", "type": "<category>", "is_ai": true/false}}.
- The "type" value MUST be exactly one of the categories listed above (case-sensitive).
- The "name" and "vendor" in your output must match the input item you are classifying.
- Use the software's PRIMARY role in practice, not a minor feature.
- Prefer reducing overlap by following the definitions and tie-break rules below.
- Classify `is_ai` for the specific software product itself, not for the whole software_type category.
- `is_ai = true` if the software is primarily built for AI/ML/LLM/agent/model/dataset/inference/training/evaluation/vector-retrieval workflows.
- `is_ai = false` if the software is mainly generic software infrastructure, general web app tooling, traditional databases, non-AI libraries, or generic developer tools.
- A product can be `Application` and still have `is_ai = true` if it is an AI-native end-user product.
- A product can be `Library` and still have `is_ai = false` if it is a general-purpose non-AI library.
- `Skill` products are usually `is_ai = true` when they are agent skills, MCP tools, prompt/workflow tools, or LLM-facing connectors.

Category definitions:
- "Agent" = frameworks, runtimes, or platforms whose main purpose is building/running autonomous or semi-autonomous agents that plan, call tools, coordinate steps, or orchestrate agent workflows.
- "Model" = model providers, model APIs, model weights, inference endpoints, or model-hosting services where the core product is the model itself.
- "Dataset" = data corpora, benchmark suites, labeled collections, evaluation sets, annotation datasets, or dataset-hosting/catalog products where the core artifact is data.
- "ML infrastructure" = platforms for training, serving, orchestration, experiment tracking, evaluation pipelines, vectorization pipelines, feature stores, or MLOps infra. These are infrastructure products, not end-user apps.
- "Skill" = small reusable capability units such as agent skills, MCP tools/servers, plugins, workflow modules, connectors, prompt packs, or tool-like add-ons. Modern agent skills belong here.
- "Application" = complete end-user products (web, desktop, mobile, SaaS) used directly by end users, even if they are AI-powered internally.
- "Library" = developer SDKs, frameworks, packages, or code libraries primarily meant to be imported into another codebase.
- "Database" = databases, vector stores, search engines, retrieval stores, caches, or data persistence/query engines.

Tie-break / anti-overlap rules:
- If it is a full product used directly by end users, choose "Application" over "Library".
- If it is imported as code by developers, choose "Library" over "Application".
- If it is specifically about agents/planning/tool-use runtimes, choose "Agent" over "Library".
- If it is a small reusable tool, MCP server, agent skill, plugin, or connector, choose "Skill" over "Agent".
- If it is mainly a data collection / benchmark / corpus, choose "Dataset" even if it has APIs.
- If it is a serving/training/platform layer, choose "ML infrastructure" over "Library".
- If it is fundamentally a store/index/vector DB/search engine/cache, choose "Database" over "ML infrastructure".
- There is NO separate "AI component" category. Former catch-all AI plugins / integrations should usually become "Skill", sometimes "Application" or "Library" depending on whether they are reusable modules or full products.

Examples:
- LangChain -> Library
- LangChain -> Library, is_ai=true
- OpenAI API / GPT-4 / Llama models -> Model, is_ai=true
- AutoGen / CrewAI / agent runtimes -> Agent, is_ai=true
- MCP servers / agent skills / workflow tools -> Skill, is_ai=true
- HuggingFace datasets / benchmark corpora -> Dataset, is_ai=true
- MLflow / Kubeflow / model serving platforms -> ML infrastructure, is_ai=true
- Cursor / ChatGPT / Dify as complete products -> Application, typically is_ai=true
- Milvus / Pinecone / Weaviate -> Database, usually is_ai=true because they are widely used as vector/AI retrieval stores
- PostgreSQL / MySQL / generic Redis usage -> Database, often is_ai=false unless the product itself is positioned primarily for AI/vector retrieval
- React / Flask / generic SDKs -> Library, usually is_ai=false
- Generic plugin marketplace tools or workflow helpers not specifically AI-centric -> Skill or Application, but often is_ai=false

- Return ONLY the JSON array, no explanation, no markdown fences.
"""

BATCH_SIZE = 40


def ensure_software_is_ai_column(conn):
    cols = [r[1] for r in conn.execute("PRAGMA table_info(software)").fetchall()]
    if "is_ai" not in cols:
        conn.execute("ALTER TABLE software ADD COLUMN is_ai INTEGER")
        conn.commit()
        print("Added software.is_ai column to database.")


def seed_types(conn):
    cur = conn.cursor()
    for t in TYPES:
        cur.execute("INSERT OR IGNORE INTO software_type (name) VALUES (?)", (t,))
    conn.commit()
    type_map = {}
    for row in cur.execute("SELECT id, name FROM software_type"):
        type_map[row[1]] = row[0]
    return type_map


def load_software(conn):
    rows = conn.execute("""
        SELECT s.id, s.name, COALESCE(v.name, '') AS vendor
        FROM software s LEFT JOIN vendor v ON s.vendor_id = v.id
        ORDER BY s.id
    """).fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


def classify_batch(batch):
    from utils.openai_api import get_response
    items = [{"name": name, "vendor": vendor} for _, name, vendor in batch]
    user_msg = json.dumps(items)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_msg},
    ]
    raw = get_response(messages, temperature=0)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
        raw = raw.rsplit("```", 1)[0]
    results = json.loads(raw)
    return results


def validate_type(predicted):
    if predicted in TYPES:
        return predicted
    low = predicted.lower().strip()
    if low in TYPES_LOWER:
        return TYPES_LOWER[low]
    return None


def remove_deprecated_ai_component_type(conn):
    cur = conn.cursor()
    row = cur.execute("SELECT id FROM software_type WHERE name = ?", ("AI component",)).fetchone()
    if not row:
        return
    rid = row[0]
    cnt = cur.execute("SELECT COUNT(*) FROM software WHERE software_type_id = ?", (rid,)).fetchone()[0]
    if cnt > 0:
        print(f"\nWarning: {cnt} software rows still reference 'AI component'; skipping row delete. Re-run after fixing.")
        return
    cur.execute("DELETE FROM software_type WHERE id = ?", (rid,))
    conn.commit()
    print("Removed deprecated software_type 'AI component' from database.")


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=ON")
    ensure_software_is_ai_column(conn)

    print("Seeding software_type table …")
    type_map = seed_types(conn)
    print(f"  Types: {list(type_map.keys())}")

    software = load_software(conn)
    print(f"\nClassifying {len(software)} software products (batch size={BATCH_SIZE}) …\n")

    classified = 0
    failed = 0
    cur = conn.cursor()

    for i in range(0, len(software), BATCH_SIZE):
        batch = software[i : i + BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1
        total_batches = (len(software) + BATCH_SIZE - 1) // BATCH_SIZE
        print(f"  Batch {batch_num}/{total_batches} ({len(batch)} items) …", end=" ", flush=True)

        try:
            results = classify_batch(batch)
        except Exception as e:
            print(f"LLM ERROR: {e}")
            failed += len(batch)
            continue

        key_to_id = {(name.lower().strip(), vendor.lower().strip()): sid for sid, name, vendor in batch}
        name_to_ids = {}
        for sid, name, vendor in batch:
            name_to_ids.setdefault(name.lower().strip(), []).append((sid, vendor))
        matched_in_batch = set()

        for r in results:
            rname = r.get("name", "")
            rvendor = r.get("vendor", "")
            rtype = r.get("type", "")
            ris_ai = r.get("is_ai", None)
            valid_type = validate_type(rtype)

            if not valid_type:
                print(f"\n    INVALID type '{rtype}' for '{rname}', defaulting to 'Application'")
                valid_type = "Application"

            sid = key_to_id.get((rname.lower().strip(), rvendor.lower().strip()))
            if sid is None:
                candidates = name_to_ids.get(rname.lower().strip(), [])
                if len(candidates) == 1:
                    sid = candidates[0][0]
                else:
                    for bsid, bvendor in candidates:
                        if bvendor.lower().strip() == rvendor.lower().strip():
                            sid = bsid
                            break
            if sid is None:
                failed += 1
                continue

            stid = type_map[valid_type]
            if isinstance(ris_ai, bool):
                is_ai_val = 1 if ris_ai else 0
            else:
                # Fallback heuristic if model omits the field.
                is_ai_val = 1 if valid_type in {"Agent", "Model", "Dataset", "ML infrastructure", "Skill"} else 0
            cur.execute("UPDATE software SET software_type_id=?, is_ai=? WHERE id=?", (stid, is_ai_val, sid))
            matched_in_batch.add(sid)
            classified += 1

        for sid, bname, _ in batch:
            if sid not in matched_in_batch:
                print(f"\n    No LLM row matched for id={sid} name={bname!r}, defaulting to Application")
                cur.execute(
                    "UPDATE software SET software_type_id=?, is_ai=? WHERE id=?",
                    (type_map["Application"], 0, sid),
                )
                classified += 1

        conn.commit()
        print(f"OK ({classified} classified so far)")
        time.sleep(0.5)

    unclassified = conn.execute("SELECT COUNT(*) FROM software WHERE software_type_id IS NULL").fetchone()[0]
    print(f"\nDone. Classified: {classified}, Failed/unmatched: {failed}, Still null: {unclassified}")

    remove_deprecated_ai_component_type(conn)

    print("\nDistribution:")
    for row in conn.execute("""
        SELECT st.name, COUNT(*) as cnt
        FROM software s JOIN software_type st ON s.software_type_id = st.id
        GROUP BY st.name ORDER BY cnt DESC
    """).fetchall():
        print(f"  {row[0]:25s} {row[1]}")

    print("\nAI distribution on software:")
    for row in conn.execute("""
        SELECT COALESCE(is_ai, 0) AS is_ai, COUNT(*) as cnt
        FROM software
        GROUP BY COALESCE(is_ai, 0)
        ORDER BY is_ai DESC
    """).fetchall():
        label = "AI" if row[0] else "non-AI"
        print(f"  {label:25s} {row[1]}")

    conn.close()


if __name__ == "__main__":
    main()
