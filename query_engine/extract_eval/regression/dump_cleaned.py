"""Dump cleaned fixture markdown (no extraction, no JSON report).

Usage
-----
    cd query_engine

    # regex clean → local_reports/cleaned_md/
    python -m extract_eval.regression.dump_cleaned \\
      --only thehackernews-new-chrome-vulnerability latimes-hacker-used-anthropic \\
             blog-agentic-ai-the blog-owasp-top-10 linkedin-kicking-off-the \\
             lakera-visual-prompt-injections thehackernews-zero-click-ai \\
             thehackernews-anthropic-mcp-design

    # Gemma LLM clean (same AISC_LLM_* as extraction)
    python -m extract_eval.regression.dump_cleaned --mode llm --only ...
"""
from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
QUERY_ENGINE = os.path.dirname(os.path.dirname(HERE))
REPO = os.path.dirname(QUERY_ENGINE)
sys.path.insert(0, QUERY_ENGINE)

from extract_pipeline.cleaner import (  # noqa: E402
    clean_markdown_llm,
    clean_markdown_regex,
)

FIXTURES_DIR = os.path.join(HERE, "fixtures")
DEFAULT_OUT = os.path.join(REPO, "local_reports", "cleaned_md")


def main() -> None:
    ap = argparse.ArgumentParser(description="Write cleaned fixture .md files (no extract/score).")
    ap.add_argument("--mode", choices=["regex", "llm"], default="regex")
    ap.add_argument("--only", nargs="*", help="doc ids (basename without .md)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="output directory for .md files")
    ap.add_argument("--model", help="sets AISC_LLM_MODEL for llm mode")
    args = ap.parse_args()

    if args.model:
        os.environ["AISC_LLM_MODEL"] = args.model
    os.environ["AISC_CLEAN_MODE"] = args.mode

    os.makedirs(args.out, exist_ok=True)
    ids = args.only
    if not ids:
        ids = [f[:-3] for f in os.listdir(FIXTURES_DIR) if f.endswith(".md")]

    clean = clean_markdown_llm if args.mode == "llm" else clean_markdown_regex

    for doc_id in ids:
        src = os.path.join(FIXTURES_DIR, f"{doc_id}.md")
        if not os.path.exists(src):
            print(f"skip missing: {doc_id}", file=sys.stderr)
            continue
        with open(src, encoding="utf-8") as f:
            raw = f.read()
        cleaned = clean(raw)
        if args.mode == "llm" and not cleaned:
            cleaned = clean_markdown_regex(raw)
            note = " (fell back to regex)"
        else:
            note = ""
        dst = os.path.join(args.out, f"{doc_id}.md")
        with open(dst, "w", encoding="utf-8") as f:
            f.write(cleaned)
            if cleaned and not cleaned.endswith("\n"):
                f.write("\n")
        print(f"{doc_id}: {len(raw)} -> {len(cleaned)} chars{note}  -> {dst}")


if __name__ == "__main__":
    main()
