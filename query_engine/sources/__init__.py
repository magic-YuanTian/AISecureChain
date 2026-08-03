"""
AISecureChain — Data Source Manager
===================================

A subsystem that turns the extraction pipeline into a continuously-updated
knowledge base by tracking **data sources** (NVD, GHSA, OSV, AVID, ...),
their **URLs** (individual pages we've ingested or plan to ingest), and
their **freshness** (is the remote content newer than what we've stored?).

Public API
----------

    from sources.registry   import list_sources, get_source, seed_from_yaml
    from sources.freshness  import check_freshness_many
    from sources.discovery  import discover_urls
    from sources.ingest     import ingest_url_async, ingest_source_async

    # backend convenience
    from sources import ensure_schema
    ensure_schema(conn)

Layout
------
    seeds.yaml    — canonical list of recommended sources (Tier 1–5).
    schema.py     — idempotent CREATE TABLE for the 3 tables used here.
    registry.py   — load seeds, CRUD for data_source + source_url rows.
    freshness.py  — HEAD/ETag/Last-Modified/content-hash staleness checks.
    discovery.py  — RSS + HTML listing expansion for seed sources.
    ingest.py     — wrap extract_pipeline.run_pipeline + persist run logs.
"""

from .schema import ensure_schema  # noqa: F401
