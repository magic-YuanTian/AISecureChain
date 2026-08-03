"""Temporary driver: run the extraction pipeline on one URL without crawl4ai.

Fetches the page with requests + markdownify and monkeypatches the pipeline's
crawl stage, then runs the real chunk -> LLM extract -> merge -> validate ->
persist stages unchanged.
"""
import asyncio
import sys

import requests
from bs4 import BeautifulSoup
from markdownify import markdownify as html_to_md

import extract_pipeline.pipeline as pipeline

URL = sys.argv[1] if len(sys.argv) > 1 else "https://github.com/advisories/GHSA-6fvq-23cw-5628"
SKIP_DB = "--persist" not in sys.argv


async def fetch_md(url: str):
    try:
        r = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            timeout=30,
        )
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup(["script", "style", "noscript", "svg", "header", "footer"]):
            tag.decompose()
        main = soup.find("main") or soup.body or soup
        return html_to_md(str(main), heading_style="ATX"), None
    except Exception as e:  # noqa: BLE001
        return "", f"fetch error: {e}"


pipeline.crawl_url_to_markdown = fetch_md  # monkeypatch the crawl stage


async def main():
    print(f"URL: {URL}")
    print(f"persist: {not SKIP_DB}\n")
    res = await pipeline.run_pipeline(URL, skip_db=SKIP_DB)
    print("markdown_length:", res.markdown_length)
    print("chunks:", res.chunks_total, "extracted:", res.chunks_extracted)
    print("errors:", res.errors)
    print("warnings:", res.warnings[:6])
    print(f"\ncanonical entities: {len(res.canonical_entities)}")
    for e in res.canonical_entities:
        key = e.attributes.get("vuln_id") or e.attributes.get("name") or e.attributes.get("id") or e.attributes.get("version_string")
        flag = " [PARTIAL: %s]" % ",".join(e.partial_reasons) if e.is_partial else ""
        print(f"  - {e.class_name}: {key}{flag}")
        if e.class_name == "Vulnerability":
            for k, v in e.attributes.items():
                print(f"        {k}: {str(v)[:90]}")
    print(f"\ncanonical relations: {len(res.canonical_relations)}")
    for r in res.canonical_relations:
        print(f"  - {r.subject_key} --{r.predicate}--> {r.object_key}")
    if not SKIP_DB:
        print("\ndb_stats:", res.db_stats)


asyncio.run(main())
