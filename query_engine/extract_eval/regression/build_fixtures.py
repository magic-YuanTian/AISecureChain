"""
Build frozen crawl fixtures for the extraction-pipeline regression benchmark.

Why freeze? News/blog pages change over time and the crawler is non-deterministic
(network, JS rendering). A regression test must compare the pipeline against a
*fixed* input, otherwise gold labels rot and scores become noisy. So we crawl
each URL ONCE, clean the boilerplate exactly as the pipeline does, and save the
markdown to ``fixtures/<id>.md``. The evaluator then runs extraction over these
frozen files (``run_pipeline_from_markdown``) and only re-crawls when you ask it.

Usage:
    cd query_engine
    python -m extract_eval.regression.build_fixtures              # all rows in the CSV
    python -m extract_eval.regression.build_fixtures --only chrome-gemini latimes-claude
    python -m extract_eval.regression.build_fixtures --csv /path/to/links.csv
    python -m extract_eval.regression.build_fixtures --no-clean --fixtures-dir extract_eval/regression/fixtures_raw

Input CSV columns (header required): Category, Title, Source, Date, Link, Summary, Test
Only ``Link`` (URL) and ``Title``/``Category`` (metadata) are used.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
QUERY_ENGINE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, QUERY_ENGINE)

from extract_pipeline.cleaner import clean_markdown_boilerplate  # noqa: E402
from extract_pipeline.pipeline import crawl_url_to_markdown  # noqa: E402

FIXTURES_DIR = os.path.join(HERE, "fixtures")
MANIFEST_PATH = os.path.join(FIXTURES_DIR, "manifest.json")
DEFAULT_CSV = os.path.join(QUERY_ENGINE, "..", "test_links.csv")


def slugify(url: str, title: str) -> str:
    """Stable, human-readable id derived from domain + a few title words."""
    domain = re.sub(r"^www\.", "", re.sub(r"^https?://", "", url).split("/")[0])
    domain = domain.split(".")[0]
    words = re.findall(r"[a-z0-9]+", (title or "").lower())[:3]
    tail = "-".join(words)
    slug = f"{domain}-{tail}".strip("-")
    return re.sub(r"-+", "-", slug)


def read_rows(csv_path: str) -> list[dict]:
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    out = []
    seen = set()
    for r in rows:
        url = (r.get("Link") or "").strip()
        if not url:
            continue
        sid = slugify(url, r.get("Title", ""))
        base = sid
        i = 2
        while sid in seen:
            sid = f"{base}-{i}"; i += 1
        seen.add(sid)
        out.append({
            "id": sid,
            "url": url,
            "title": (r.get("Title") or "").strip(),
            "category": (r.get("Category") or "").strip(),
            "source": (r.get("Source") or "").strip(),
        })
    return out


async def build(
    rows: list[dict],
    only: set[str] | None,
    *,
    fixtures_dir: str,
    no_clean: bool = False,
) -> dict:
    os.makedirs(fixtures_dir, exist_ok=True)
    manifest_path = os.path.join(fixtures_dir, "manifest.json")
    manifest = {}
    if os.path.exists(manifest_path):
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)

    for row in rows:
        if only and row["id"] not in only:
            continue
        print(f"[crawl] {row['id']:<32} {row['url']}")
        md, err = await crawl_url_to_markdown(row["url"])
        entry = {k: row[k] for k in ("url", "title", "category", "source")}
        if err or not md.strip():
            entry["crawl_error"] = err or "empty markdown"
            entry["char_len"] = 0
            print(f"    ! {entry['crawl_error']}")
        else:
            text = md if no_clean else clean_markdown_boilerplate(md)
            fpath = os.path.join(fixtures_dir, f"{row['id']}.md")
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(text)
            entry["fixture_file"] = f"{row['id']}.md"
            entry["char_len"] = len(text)
            entry["crawl_error"] = None
            if no_clean:
                entry["note"] = "raw_crawl_no_clean"
            print(f"    ok  {len(text)} chars -> {entry['fixture_file']}")
        manifest[row["id"]] = entry

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print(f"\nmanifest -> {manifest_path} ({len(manifest)} entries)")
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description="Crawl + freeze fixtures for the regression benchmark.")
    ap.add_argument("--csv", default=DEFAULT_CSV, help="Source CSV of links (default: repo test_links.csv)")
    ap.add_argument("--only", nargs="*", help="Only (re)build these fixture ids")
    ap.add_argument(
        "--fixtures-dir",
        default=FIXTURES_DIR,
        help="Output directory for .md fixtures + manifest.json (default: extract_eval/regression/fixtures)",
    )
    ap.add_argument(
        "--no-clean",
        action="store_true",
        help="Save raw crawl markdown without clean_markdown_boilerplate",
    )
    args = ap.parse_args()

    fixtures_dir = os.path.abspath(args.fixtures_dir)
    rows = read_rows(args.csv)
    print(f"{len(rows)} rows in {args.csv}")
    print(f"fixtures_dir={fixtures_dir}  no_clean={bool(args.no_clean)}")
    asyncio.run(
        build(
            rows,
            set(args.only) if args.only else None,
            fixtures_dir=fixtures_dir,
            no_clean=bool(args.no_clean),
        )
    )

if __name__ == "__main__":
    main()
