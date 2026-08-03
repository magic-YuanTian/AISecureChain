"""
AISecureChain — Information Extraction Pipeline (v2, ontology-driven)
=====================================================================

Public API
----------
    from extract_pipeline import run_pipeline, PipelineResult
    result = await run_pipeline("https://...")

Pipeline stages:
    1. Fetch    — URL -> Markdown (crawl4ai)
    2. Chunk    — Markdown -> semantic chunks
    3. Extract  — Each chunk -> ontology-aware graph (entities + relations)
    4. Merge    — Dedupe across chunks by canonical key
    5. Validate — Flag partial records, check ontology constraints
    6. Persist  — Ontology-aware SQLite upsert (optional)
"""

from .models import (
    ExtractedEntity,
    ExtractedRelation,
    ExtractionGraph,
    CanonicalEntity,
    CanonicalRelation,
    PipelineResult,
)
from .pipeline import run_pipeline, run_pipeline_from_markdown, crawl_url_to_markdown
from .ontology import load_ontology_schema, format_ontology_for_prompt

__all__ = [
    "run_pipeline",
    "run_pipeline_from_markdown",
    "crawl_url_to_markdown",
    "PipelineResult",
    "ExtractedEntity",
    "ExtractedRelation",
    "ExtractionGraph",
    "CanonicalEntity",
    "CanonicalRelation",
    "load_ontology_schema",
    "format_ontology_for_prompt",
]
