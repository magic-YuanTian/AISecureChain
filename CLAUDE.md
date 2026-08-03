# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AISecureChain is an AI vulnerability knowledge base that collects, enriches, and queries AI/ML security vulnerability data. It ingests CVE records from MISP and cvelistV5, builds a structured ontology-based knowledge graph (SQLite + RDF/Turtle), and provides a Flask API with a React frontend for querying and exploring vulnerabilities.

## Architecture

### Data Flow

1. **Collection**: `explore_misp.py` and `fetch_cve_details.py` pull CVE data from MISP and cvelistV5 into `output/` JSON files
2. **Analysis**: `full_analysis.py`, `generate_charts.py`, `analyze_ontology.py` produce statistics and visualizations
3. **Knowledge Base Build** (`query_engine/`):
   - `build_db.py` — loads CVE + MISP JSON into SQLite (`ai_vuln_kb.db`, 9 entity + 5 junction tables)
   - `build_rdf.py` — serializes the DB into an OWL/RDF graph (`ai_vuln_kb.ttl`)
4. **Extraction Pipeline** (`query_engine/extract_pipeline/`): crawls URLs → chunks markdown → LLM extracts entities/relations per ontology → merges → persists to DB
5. **API + Frontend**: Flask serves both the relational DB and RDF/SPARQL graph; React frontend provides query, exploration, and extraction UI

### Ontology (namespace: `http://aisecurechain.org/ontology#`)

9 entity classes: Vendor, Software, SoftwareType, Version, License, Vulnerability, VulnerabilityType (CWE-style weakness), plus the attack/impact causal layer — Attack (how a vulnerability is exploited) and Impact (the consequence). Core chain: `Attack —exploits→ Vulnerability —resultsIn→ Impact`. Attack and Impact are name-identified and **LLM-extracted per advisory** (not seeded from a catalog).

The ontology schema is defined in `query_engine/ai_vuln_kb.ttl` and loaded dynamically by the extraction pipeline (`extract_pipeline/ontology.py`). Extraction hints for the LLM are defined in `CLASS_HINTS` in `ontology.py` — this is the main place to tune extraction behavior. Adding a class/property to the schema flows automatically into the extraction prompt, the RDF (`build_rdf.py`), and the API class/edge endpoints (`app.py` `CLASS_QUERIES`/`EDGE_QUERIES`).

**Source-neutral design**: the schema never names a field/class after a data source. External provenance (MISP, AVID, CVE/GHSA ids) is recorded in generic external-reference tables (e.g. `vulnerability_external_id`, `entity_external_id`), not source-branded columns.

### Extraction Pipeline (`query_engine/extract_pipeline/`)

Pipeline stages: `crawl → clean → chunk → LLM extract (per chunk) → merge → validate → persist`

Key modules: `pipeline.py` (orchestrator), `llm.py` (OpenAI-based extraction with retry/normalization), `merger.py` (cross-chunk dedup), `models.py` (Pydantic schemas: per-chunk `ExtractionGraph` and merged `CanonicalEntity`/`CanonicalRelation`), `validator.py`, `persist.py`, `cleaner.py`, `chunker.py`

### Data Sources Module (`query_engine/sources/`)

Manages external data source registration via `seeds.yaml`. Modules: `registry.py` (CRUD), `freshness.py` (staleness checks), `discovery.py`, `ingest.py`, `schema.py`.

### Vendored / Cloned Repos

- `cvelistV5/` — CVE List V5 (cloned repo, reference data)
- `avid-db/` — AVID vulnerability reports (cloned repo)
- `crawl4ai/` — web crawler library (local copy)
- `www-project-top-10-for-large-language-model-applications/` — OWASP LLM Top 10 (reference)
- `mit/` — MIT AI Risk Repository reference materials
- `query_engine/data/atlas.yaml` — vendored MITRE ATLAS dataset; reference-only (the former ATLAS import was removed when the ontology moved to the extracted Attack/Impact model)

## Commands

### Backend (Flask API)

```bash
# Install dependencies
pip install -r requirements.txt

# Run the Flask API server (listens on port 5093; also serves frontend/build)
cd query_engine && python app.py

# Build/rebuild the SQLite knowledge base from raw data
cd query_engine && python build_db.py

# Build/rebuild the RDF graph from the SQLite DB
cd query_engine && python build_rdf.py

# Run extraction pipeline on a URL
cd query_engine && python -m extract_pipeline.pipeline <url> [--skip-db] [--json out.json]
```

### Frontend (React)

```bash
cd query_engine/frontend
npm install
npm start        # dev server
npm run build    # production build
npm test         # run tests
```

**Serving note**: `frontend/src/api.ts` uses a relative `baseURL` (`/api`); Flask serves the production build from `frontend/build` on the same port (5093). After changing frontend code, run `npm run build` **and restart the Flask process** — a running server keeps serving old Python code until restarted.

### Tests

```bash
# Run all backend tests
cd query_engine && python -m pytest tests/

# Run a single test file
cd query_engine && python -m pytest tests/test_merger.py

# Run a specific test
cd query_engine && python -m pytest tests/test_merger.py::test_function_name -v
```

Tests are fully isolated: no network calls, no real LLM, no real DB (uses temp SQLite). See `tests/conftest.py`.

### Extraction Pipeline Evaluation

```bash
# Run evaluation over all URLs in extract_eval/urls.yaml (never touches ai_vuln_kb.db)
cd query_engine && python -m extract_eval.evaluate

# Limit scope or save results
python -m extract_eval.evaluate --max-urls 3
python -m extract_eval.evaluate --only nvd github
python -m extract_eval.evaluate --out report.json --concurrency 4
```

The evaluator measures per-URL recall, partial_rate, coverage, and forbidden-hit rate. Use it when iterating on ontology hints (`extract_pipeline/ontology.py::CLASS_HINTS`), the extraction prompt (`llm.py::build_system_prompt`), or merge rules (`merger.py`).

### Extraction Regression Benchmark (entity-level P/R/F1)

`extract_eval/regression/` is a stricter, oracle-labeled benchmark: it runs the real pipeline over **frozen** page fixtures and reports precision/recall/F1 per ontology class. See `extract_eval/regression/README.md`.

```bash
cd query_engine
python -m extract_eval.regression.build_fixtures          # one-time: crawl+freeze fixtures/
python -m extract_eval.regression.evaluate_regression     # score current pipeline
python -m extract_eval.regression.evaluate_regression --repeat 3   # mean ± stdev (use this to judge a change)
python -m extract_eval.regression.evaluate_regression --out r.json --audit-fps proposed_gold.yaml  # LLM gold auditor
python -m extract_eval.regression.evaluate_regression --model gpt-4.1-mini --out run.json  # A/B an LLM
```

**Never judge a pipeline change on a single run.** Aggregate F1 has stdev
~0.007 but per-class F1 reaches 0.067 — a class-level "improvement" from one
run is usually noise. `--audit-fps` runs an LLM judge over the false positives
and writes *proposed* gold fixes; it is advisory and never changes the score
(see the README for the cases where its proposals were wrong).

Fixtures are frozen markdown so results are reproducible; the evaluator calls `run_pipeline_from_markdown` (the post-crawl half of `run_pipeline`, exposed for this). `gold.yaml` uses a `required`/`acceptable` label model so precision stays fair for fuzzy classes; `VulnerabilityType` is informational (validator-driven, excluded from the headline).

### Utility Scripts

```bash
# Import AVID vulnerability reports into the DB
cd query_engine && python scripts/import_avid.py

# Enrich KB vulns from CISA KEV (verified in-the-wild exploitation);
# sets vulnerability.exploited_in_wild / exploitation_verified_date / ransomware_use
cd query_engine && python scripts/import_kev.py

# Migrate vulnerability IDs
cd query_engine && python scripts/migrate_vuln_id.py

# Audit / repair CWE (VulnerabilityType) mappings written by the old mapper.
# Carries a hand-reviewed correction table; --scan finds new suspects.
cd query_engine && python -m scripts.audit_cwe_mappings          # show plan
cd query_engine && python -m scripts.audit_cwe_mappings --apply  # write it
```

**After changing `vulnerability_is_a` (or any table the graph exposes), re-run
`python build_rdf.py`** — the SPARQL endpoints read `ai_vuln_kb.ttl`, not the DB,
so corrections are invisible to the graph API until it is regenerated.

## Environment

Requires a `.env` file (copy from `.env.example`) for MISP data collection:
- `MISP_URL`, `MISP_API_KEY`, `MISP_VERIFY_SSL`

**LLM config lives in `utils/openai_api.py`** — defaults to Azure OpenAI (GPT-4o via `make_gpt_4()`). Every value is overridable by environment variable (no code edit needed): `AISC_LLM_MODEL`, `AISC_LLM_ENDPOINT`, `AISC_LLM_API_KEY`, `AISC_LLM_API_VERSION`, `AISC_LLM_PROVIDER` (`azure`|`openai`). `get_response()` re-reads the env per call, so you can A/B base models per run. The `.env.example` does not cover LLM config.

## Key Patterns

- `extract_from_url.py` is a backward-compatibility shim; prefer `extract_pipeline.run_pipeline` for new code
- The LLM extraction prompt is built dynamically from the TTL ontology, so adding classes/properties to the ontology auto-updates extraction
- SQLite uses WAL mode with busy_timeout for concurrent read/write access
- `extract_pipeline/dedup.py` handles cross-entity deduplication: after each persist it detects near-duplicate entities (by name normalization and alias matching) and writes edges into the `entity_same_as` junction table rather than creating duplicate rows
- The extraction pipeline is fully async (`asyncio`); `run_pipeline` is a coroutine — use `asyncio.run()` or `await` it from an async context
