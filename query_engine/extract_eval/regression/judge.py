"""LLM judge for the regression benchmark — an ADVISORY gold-set auditor.

What it is for
--------------
The scorer matches predictions to gold labels by normalized string / alias
matching. That is fast, free and perfectly reproducible, but it cannot know
that "Data Exfiltration" and "Data Leak" are the same harm. When the gold
alias lists fall behind, correct extractions are counted as false positives —
an audit of the Impact class found ~73% of its FPs were label gaps rather than
extraction errors, and closing them by hand took an afternoon.

That audit is exactly what an LLM is good at. This module automates it.

What it is deliberately NOT
---------------------------
It is **not** the scorer. Metrics stay deterministic:

* the judge only ever looks at entities the string matcher already called FP;
* it cannot create a true positive, cannot change recall, cannot move F1;
* its output is a *proposed patch* to `gold.yaml` for a human to read and
  apply.

Letting a model decide its own score is how a benchmark stops meaning
anything — the extraction model and the judge would be the same family, and
self-preference bias is well documented. Keeping the judge advisory buys the
synonym understanding without giving up reproducibility.

Usage
-----
    python -m extract_eval.regression.evaluate_regression \
        --out report.json --audit-fps proposed_gold.yaml

    # or over an existing report
    python -m extract_eval.regression.judge report.json proposed_gold.yaml

Read the proposals, delete the ones you disagree with, then merge them into
`gold.yaml`. The rule to apply while reading: an entity belongs in
`acceptable` only if its own evidence sentence supports its name.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
QUERY_ENGINE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, QUERY_ENGINE)

FIXTURES_DIR = os.path.join(HERE, "fixtures")
MANIFEST_PATH = os.path.join(FIXTURES_DIR, "manifest.json")

VERDICTS = ("alias", "acceptable", "false_positive")

SYSTEM_PROMPT = """You audit the gold labels of an information-extraction benchmark.

You are given: a page's text, one ontology class, the gold labels already \
recorded for that class, and ONE entity the pipeline extracted that matched no \
gold label. Decide which of these the entity is:

- "alias": it means the SAME THING as one of the existing gold labels, just \
worded differently (e.g. "Data Exfiltration" vs a gold label "Data Leak"). \
Return the gold label it should be an alias of in `alias_of`.
- "acceptable": it is a DIFFERENT but genuine entity of this class that the \
page really states, and that a careful annotator could reasonably have listed. \
It must be supported by the page text.
- "false_positive": it is not supported, is the wrong ontology class, is \
self-contradictory, or is derived from a mitigation / recommendation sentence \
rather than from a description of the attack or its consequences.

Be strict. "false_positive" is the correct answer whenever you are unsure or \
the support is only implicit. Never justify an entity by general knowledge — \
only by what this page says.

Quote the sentence that supports your decision in `evidence`, verbatim from \
the page, or leave it empty for false_positive.

Reply with JSON only:
{"verdict": "alias|acceptable|false_positive", "alias_of": "<gold label or empty>", \
"evidence": "<verbatim quote or empty>", "reason": "<one short sentence>"}"""


def _load_fixture(doc_id: str, manifest: dict) -> str:
    entry = manifest.get(doc_id, {})
    path = os.path.join(FIXTURES_DIR, entry.get("fixture_file", f"{doc_id}.md"))
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8") as f:
        return f.read()


def _parse(raw: str) -> dict | None:
    text = raw.strip()
    if "```" in text:
        import re
        m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
        if m:
            text = m.group(1).strip()
    s, e = text.find("{"), text.rfind("}")
    if s < 0 or e <= s:
        return None
    try:
        out = json.loads(text[s:e + 1])
    except Exception:
        return None
    return out if isinstance(out, dict) else None


async def _judge_one(doc_text: str, class_name: str, gold_labels: list[str], entity: dict) -> dict:
    from utils.openai_api import get_judge_response

    payload = {
        "ontology_class": class_name,
        "existing_gold_labels": gold_labels,
        "extracted_entity": entity,
        "page_text": doc_text[:24000],
    }
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
    ]
    try:
        raw = await asyncio.to_thread(get_judge_response, messages, 0.0)
    except Exception as exc:  # noqa: BLE001
        return {"verdict": "false_positive", "reason": f"judge call failed: {exc}"}
    parsed = _parse(raw) or {}
    if parsed.get("verdict") not in VERDICTS:
        parsed["verdict"] = "false_positive"
        parsed.setdefault("reason", "unparseable judge reply")
    return parsed


async def audit_report(report: dict, *, concurrency: int = 4) -> dict:
    """Judge every FP in the report. Returns {doc_id: {class: [proposals]}}."""
    manifest = {}
    if os.path.exists(MANIFEST_PATH):
        with open(MANIFEST_PATH, encoding="utf-8") as f:
            manifest = json.load(f)

    sem = asyncio.Semaphore(concurrency)
    jobs = []

    for doc_id, doc in report.get("per_doc", {}).items():
        details = (doc.get("meta") or {}).get("details") or {}
        text = _load_fixture(doc_id, manifest)
        if not text:
            continue
        for class_name, block in details.items():
            fps = [p for p in block.get("predicted", []) if p.get("verdict") == "FP"]
            if not fps:
                continue
            gold_labels = [g["label"] for g in block.get("gold", [])]

            for p in fps:
                async def _run(doc_id=doc_id, class_name=class_name, gold_labels=gold_labels,
                               p=p, text=text):
                    async with sem:
                        res = await _judge_one(text, class_name, gold_labels, p.get("attrs") or {})
                    return doc_id, class_name, p, res
                jobs.append(_run())

    results = await asyncio.gather(*jobs, return_exceptions=True)

    proposals: dict = {}
    counts = {v: 0 for v in VERDICTS}
    for r in results:
        if isinstance(r, Exception):
            continue
        doc_id, class_name, pred, verdict = r
        counts[verdict.get("verdict", "false_positive")] += 1
        if verdict.get("verdict") == "false_positive":
            continue
        proposals.setdefault(doc_id, {}).setdefault(class_name, []).append({
            "entity": pred.get("value"),
            "verdict": verdict.get("verdict"),
            "alias_of": verdict.get("alias_of") or "",
            "evidence": (verdict.get("evidence") or "")[:300],
            "reason": verdict.get("reason", ""),
        })
    return {"proposals": proposals, "counts": counts}


def write_yaml(audit: dict, path: str) -> None:
    """Emit a human-readable proposal file (comments, not machine-merged)."""
    lines = [
        "# PROPOSED gold.yaml additions — produced by extract_eval.regression.judge",
        "#",
        "# These are SUGGESTIONS from an LLM auditor that reviewed every entity the",
        "# string matcher scored as a false positive. Nothing here has affected any",
        "# metric. Read each one, drop what you disagree with, then hand-merge the",
        "# rest into gold.yaml.",
        "#",
        "# Rule of thumb while reviewing: an entity belongs in `acceptable` only if",
        "# its own evidence sentence supports its name. If the evidence is a",
        "# mitigation recommendation, a different concept, or absent — leave it as a",
        "# false positive; that number is supposed to hurt.",
        "#",
        f"# judge verdicts: {audit['counts']}",
        "",
    ]
    for doc_id, classes in sorted(audit["proposals"].items()):
        lines.append(f"{doc_id}:")
        for class_name, items in sorted(classes.items()):
            lines.append(f"  {class_name}:")
            for it in items:
                if it["verdict"] == "alias":
                    lines.append(f"    # ADD ALIAS to gold label {it['alias_of']!r}: {it['entity']!r}")
                else:
                    lines.append(f"    # ADD acceptable: {it['entity']!r}")
                lines.append(f"    #   reason:   {it['reason']}")
                if it["evidence"]:
                    lines.append(f"    #   evidence: {it['evidence']}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main() -> None:
    ap = argparse.ArgumentParser(description="LLM gold-set auditor (advisory only).")
    ap.add_argument("report", help="report JSON produced by evaluate_regression")
    ap.add_argument("out", help="where to write the proposed gold additions")
    ap.add_argument("--concurrency", type=int, default=4)
    args = ap.parse_args()

    with open(args.report, encoding="utf-8") as f:
        report = json.load(f)
    audit = asyncio.run(audit_report(report, concurrency=args.concurrency))
    write_yaml(audit, args.out)
    print(f"judge verdicts: {audit['counts']}")
    print(f"proposals written to {args.out}")


if __name__ == "__main__":
    main()
