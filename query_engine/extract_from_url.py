"""
Backward-compatibility shim for the AISecureChain extraction pipeline.

The real implementation lives in ``extract_pipeline/``. This file keeps the
old public API that existing callers (e.g. ``app.py``) import::

    from extract_from_url import (
        crawl_url_to_markdown,
        extract_with_llm,
        insert_extraction_results,
        ExtractionResult,  # legacy vuln-centric shape
    )

It is a thin wrapper around the new pipeline. Prefer using
``extract_pipeline.run_pipeline`` directly for new code.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from extract_pipeline import (
    crawl_url_to_markdown as _crawl_url_to_markdown,
    run_pipeline,
    PipelineResult,
)
from extract_pipeline.merger import merge_graphs
from extract_pipeline.llm import extract_graph, build_system_prompt
from extract_pipeline.chunker import chunk_markdown
from extract_pipeline.persist import persist_canonical


# ── Legacy wrapper for crawl_url_to_markdown ──────────────────────────────
#
# Historical signature: ``(url) -> (text_or_error, ok: bool)``

async def crawl_url_to_markdown(url: str) -> tuple[str, bool]:  # type: ignore[override]
    md, err = await _crawl_url_to_markdown(url)
    if err:
        return err, False
    return md, True


# ── Legacy ExtractionResult shape ─────────────────────────────────────────

@dataclass
class ExtractionResult:
    """Flat vuln-centric view, kept only for backward compatibility.

    New code should use :class:`extract_pipeline.PipelineResult`."""
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    source_url: str = ""
    _pipeline_result: PipelineResult | None = None

    def model_dump(self) -> dict[str, Any]:
        base = {
            "vulnerabilities": self.vulnerabilities,
            "source_url": self.source_url,
        }
        if self._pipeline_result:
            base["entity_counts"] = self._pipeline_result.entity_counts_by_class()
            base["partial_rate"] = self._pipeline_result.partial_rate()
            base["warnings"] = self._pipeline_result.warnings
        return base


async def extract_with_llm(markdown: str, source_url: str = "") -> ExtractionResult:
    """Legacy wrapper: run extraction on pre-crawled markdown."""
    if not markdown.strip():
        return ExtractionResult()

    chunks = chunk_markdown(markdown)
    system_prompt = build_system_prompt()

    graphs = []
    warnings: list[str] = []
    for i, chunk in enumerate(chunks):
        g, e = await extract_graph(chunk, system_prompt=system_prompt)
        if e:
            warnings.append(f"chunk {i}: {e}")
        if g.entities or g.relations:
            graphs.append(g)

    if not graphs:
        result = ExtractionResult(source_url=source_url)
        return result

    ents, rels = merge_graphs(graphs)
    pr = PipelineResult(
        url=source_url,
        markdown=markdown,
        markdown_length=len(markdown),
        chunks_total=len(chunks),
        chunks_extracted=len(graphs),
        raw_graphs=graphs,
        canonical_entities=ents,
        canonical_relations=rels,
        warnings=warnings,
    )
    ui = pr.to_ui_response()
    return ExtractionResult(
        vulnerabilities=ui["vulnerabilities"],
        source_url=source_url,
        _pipeline_result=pr,
    )


def insert_extraction_results(
    extraction: ExtractionResult,
    source_url: str,
) -> dict[str, int]:
    """Persist the ExtractionResult into SQLite."""
    if extraction._pipeline_result is None:
        return {"error": 1}  # type: ignore[dict-item]
    pr = extraction._pipeline_result
    return persist_canonical(
        pr.canonical_entities,
        pr.canonical_relations,
        source_url=source_url,
    )


# ── Re-exports for convenience ────────────────────────────────────────────

__all__ = [
    "crawl_url_to_markdown",
    "extract_with_llm",
    "insert_extraction_results",
    "ExtractionResult",
    "run_pipeline",
    "PipelineResult",
]


if __name__ == "__main__":
    import argparse, json

    ap = argparse.ArgumentParser(description="AISecureChain URL extraction (legacy CLI)")
    ap.add_argument("url")
    ap.add_argument("--skip-db", action="store_true")
    args = ap.parse_args()

    result = asyncio.run(run_pipeline(args.url, skip_db=args.skip_db))
    print(json.dumps({
        "url": result.url,
        "markdown_length": result.markdown_length,
        "entity_counts": result.entity_counts_by_class(),
        "db_stats": result.db_stats,
        "errors": result.errors,
        "warnings": result.warnings,
    }, indent=2))
