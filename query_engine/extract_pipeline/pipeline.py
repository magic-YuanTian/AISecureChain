"""
Top-level orchestrator for the AISecureChain extraction pipeline.

Usage
-----

    from extract_pipeline import run_pipeline
    result = await run_pipeline("https://...", skip_db=False)

``result`` is a :class:`PipelineResult` with everything you need
(canonical entities, canonical relations, DB stats, UI-shaped view).

CLI
---
    python -m extract_pipeline.pipeline <url> [--skip-db] [--json out.json]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any

from .chunker import chunk_markdown
from .cleaner import clean_markdown_boilerplate
from .filters import apply_precision_filters
from .llm import build_system_prompt, extract_graph
from .merger import merge_graphs
from .models import ExtractionGraph, PipelineResult
from .persist import persist_canonical
from .validator import validate_and_map_vulnerability_types

# Cap concurrent per-chunk LLM calls. Unbounded gather hammered free-tier
# OpenRouter (12 parallel → RateLimitError storms). Override via CLI or
# AISC_MAX_PARALLEL_CHUNKS.
DEFAULT_MAX_PARALLEL_CHUNKS = 4


def resolve_max_parallel_chunks(explicit: int | None = None) -> int:
    """Return max in-flight chunk extracts (≥1).

    Precedence: explicit arg → ``AISC_MAX_PARALLEL_CHUNKS`` → default 4.
    """
    if explicit is not None:
        return max(1, int(explicit))
    raw = (os.environ.get("AISC_MAX_PARALLEL_CHUNKS") or "").strip()
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    return DEFAULT_MAX_PARALLEL_CHUNKS


# ── Fetch stage ────────────────────────────────────────────────────────────

async def crawl_url_to_markdown(url: str) -> tuple[str, str | None]:
    """Fetch a URL and return (markdown, error). Uses crawl4ai."""
    try:
        from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig
        from crawl4ai.async_configs import CacheMode
    except Exception as e:  # noqa: BLE001
        return "", f"crawl4ai not available: {e}"

    try:
        browser = BrowserConfig(headless=True, verbose=False)
        run_cfg = CrawlerRunConfig(cache_mode=CacheMode.BYPASS, verbose=False)
        async with AsyncWebCrawler(config=browser) as crawler:
            res = await crawler.arun(url=url, config=run_cfg)
            if not res.success:
                return "", f"crawl4ai: {res.error_message or 'unknown error'}"
            md = res.markdown or ""
            if hasattr(md, "raw_markdown"):
                md = md.raw_markdown  # crawl4ai returns a MarkdownGenerationResult sometimes
            return str(md), None
    except Exception as e:  # noqa: BLE001
        return "", f"crawl error: {e}"


# ── Orchestrator ───────────────────────────────────────────────────────────

async def run_pipeline(
    url: str,
    *,
    skip_db: bool = False,
    max_chunks: int = 12,
    max_chars_per_chunk: int = 6000,
    overlap: int = 300,
    include_partial_in_db: bool = False,
    max_parallel_chunks: int | None = None,
) -> PipelineResult:
    """Run the full pipeline for a single URL (crawl → … → persist)."""
    result = PipelineResult(url=url)

    # 1. Fetch
    md, err = await crawl_url_to_markdown(url)
    if err:
        result.errors.append(err)
        return result
    if not md.strip():
        result.errors.append("crawl4ai returned empty markdown")
        return result

    return await run_pipeline_from_markdown(
        md,
        url=url,
        skip_db=skip_db,
        max_chunks=max_chunks,
        max_chars_per_chunk=max_chars_per_chunk,
        overlap=overlap,
        include_partial_in_db=include_partial_in_db,
        max_parallel_chunks=max_parallel_chunks,
        result=result,
    )


async def run_pipeline_from_markdown(
    markdown: str,
    *,
    url: str = "",
    skip_db: bool = True,
    max_chunks: int = 12,
    max_chars_per_chunk: int = 6000,
    overlap: int = 300,
    include_partial_in_db: bool = False,
    already_clean: bool = False,
    max_parallel_chunks: int | None = None,
    result: PipelineResult | None = None,
) -> PipelineResult:
    """Run every post-fetch stage (clean → chunk → extract → merge → validate →
    persist) on pre-fetched markdown.

    This is the exact code path :func:`run_pipeline` uses after crawling, exposed
    separately so callers (e.g. the regression benchmark) can run extraction over
    *frozen* page content — making results reproducible and independent of network
    / crawler volatility. Set ``already_clean=True`` to skip boilerplate cleanup
    (e.g. when feeding a cached, already-cleaned fixture)."""
    result = result or PipelineResult(url=url)

    cleaned_md = markdown if already_clean else clean_markdown_boilerplate(markdown)
    if not cleaned_md.strip():
        result.errors.append("markdown cleanup removed all content")
        return result
    if len(cleaned_md) < len(markdown):
        result.warnings.append(
            f"Cleaned boilerplate from markdown ({len(markdown)} -> {len(cleaned_md)} chars)."
        )
    result.markdown = cleaned_md
    result.markdown_length = len(cleaned_md)

    # 2. Chunk
    chunks = chunk_markdown(
        cleaned_md, max_chars=max_chars_per_chunk, overlap=overlap
    )
    result.chunks_total = len(chunks)
    if len(chunks) > max_chunks:
        result.warnings.append(
            f"Page produced {len(chunks)} chunks; truncating to {max_chunks}."
        )
        chunks = chunks[:max_chunks]

    # 3. Extract (bounded parallelism — see resolve_max_parallel_chunks)
    system_prompt = build_system_prompt()
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from utils.openai_api import empty_usage, merge_usage  # type: ignore

    extract_usage = empty_usage()
    parallel = resolve_max_parallel_chunks(max_parallel_chunks)
    sem = asyncio.Semaphore(parallel)

    async def _one(ci: int, chunk: str) -> tuple[int, ExtractionGraph, str | None, dict]:
        async with sem:
            g, e, u = await extract_graph(chunk, system_prompt=system_prompt)
            return ci, g, e, u

    outs = await asyncio.gather(
        *[_one(i, c) for i, c in enumerate(chunks)],
        return_exceptions=True,
    )

    for out in outs:
        if isinstance(out, Exception):
            result.errors.append(f"chunk extraction failed: {out}")
            continue
        ci, g, e, u = out  # type: ignore[assignment]
        extract_usage = merge_usage(extract_usage, u)
        if e:
            result.warnings.append(f"chunk {ci}: {e}")
        if g.entities or g.relations:
            result.chunks_extracted += 1
            result.raw_graphs.append(g)

    if not result.raw_graphs:
        result.errors.append("No extractions from any chunk.")
        result.llm_usage = {
            "extraction": extract_usage,
            "validation": empty_usage(),
            "total": extract_usage,
        }
        return result

    # 4. Merge
    canonical_entities, canonical_relations = merge_graphs(result.raw_graphs)
    result.canonical_entities = canonical_entities
    result.canonical_relations = canonical_relations

    # 5. Self-validate and force Vulnerability -> predefined VulnerabilityType
    (
        canonical_entities,
        canonical_relations,
        validation_warnings,
        validation_usage,
    ) = await validate_and_map_vulnerability_types(
        canonical_entities,
        canonical_relations,
        source_text=cleaned_md,
        source_url=url,
    )
    result.canonical_entities = canonical_entities
    result.canonical_relations = canonical_relations
    result.warnings.extend(validation_warnings)
    result.llm_usage = {
        "extraction": extract_usage,
        "validation": validation_usage,
        "total": merge_usage(extract_usage, validation_usage),
    }

    # 5.5 Deterministic precision filters (generic categories, CVSS labels,
    #     defense-only software, unlinked non-standard Attack/Impact)
    canonical_entities, canonical_relations, filter_notes = apply_precision_filters(
        canonical_entities, canonical_relations
    )
    result.canonical_entities = canonical_entities
    result.canonical_relations = canonical_relations
    result.warnings.extend(filter_notes)

    # 6. Persist (optional)
    if not skip_db:
        try:
            stats = persist_canonical(
                canonical_entities,
                canonical_relations,
                source_url=url,
                include_partial=include_partial_in_db,
            )
            result.db_stats = stats
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"DB persist failed: {e}")

    return result


# ── CLI ────────────────────────────────────────────────────────────────────

def _cli() -> None:
    ap = argparse.ArgumentParser(description="AISecureChain extraction pipeline.")
    ap.add_argument("url")
    ap.add_argument("--skip-db", action="store_true", help="Do not write to SQLite")
    ap.add_argument("--max-chunks", type=int, default=12)
    ap.add_argument(
        "--max-parallel-chunks",
        type=int,
        default=None,
        help=(
            "Max concurrent chunk LLM calls (default: AISC_MAX_PARALLEL_CHUNKS "
            f"or {DEFAULT_MAX_PARALLEL_CHUNKS})"
        ),
    )
    ap.add_argument("--json", dest="out_json", default=None, help="Write full result to JSON")
    args = ap.parse_args()

    result = asyncio.run(
        run_pipeline(
            args.url,
            skip_db=args.skip_db,
            max_chunks=args.max_chunks,
            max_parallel_chunks=args.max_parallel_chunks,
        )
    )

    summary: dict[str, Any] = {
        "url": result.url,
        "markdown_length": result.markdown_length,
        "chunks_total": result.chunks_total,
        "chunks_extracted": result.chunks_extracted,
        "entity_counts": result.entity_counts_by_class(),
        "partial_rate": result.partial_rate(),
        "db_stats": result.db_stats,
        "errors": result.errors,
        "warnings": result.warnings,
    }
    print(json.dumps(summary, indent=2, default=str))

    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(result.model_dump(mode="json"), f, indent=2, default=str)
        print(f"full result written to {args.out_json}", file=sys.stderr)


if __name__ == "__main__":
    _cli()
