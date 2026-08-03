# Extraction Pipeline Evaluation

This folder holds the curated test URLs and the evaluation harness for the
AISecureChain extraction pipeline (see `../extract_pipeline/`).

## Files

- `urls.yaml` — the living list of test URLs + gold expectations.
- `evaluate.py` — runs the pipeline over every URL and reports metrics.

## How to run

From `query_engine/`:

```bash
# evaluate every URL in urls.yaml
python -m extract_eval.evaluate

# only run the first 3
python -m extract_eval.evaluate --max-urls 3

# only run URLs matching a keyword
python -m extract_eval.evaluate --only nvd github

# persist the full JSON report
python -m extract_eval.evaluate --out report.json

# higher parallelism (default 2)
python -m extract_eval.evaluate --concurrency 4
```

The evaluator always runs with `skip_db=True` — it never touches your SQLite
knowledge base.

## Adding a new URL

Just append to `urls.yaml`:

```yaml
- url: https://example.com/cve-2025-xxxx
  source: Example
  category: single-cve
  expected:
    vulnerability_ids: [CVE-2025-XXXX]
    must_have_classes: [Vulnerability, Software]
    max_partial_rate: 0.5
```

Every `expected.*` field is optional. The checker only enforces what you
specify, so you can start permissive and tighten over time.

## Metrics reported

Per URL:
- `recall` — fraction of `expected_ids` the pipeline found
- `partial_rate` — fraction of extracted entities flagged as missing required attrs
- `coverage` — fraction of required attrs actually filled on non-partial entities
- `forbidden_hits` — IDs the pipeline hallucinated that should never appear
- `failed_checks` — human-readable list of what went wrong
- `entity_counts` — per-class entity count

Aggregate:
- `pass_rate` — fraction of URLs where all checks passed
- `vuln_micro_recall` / `vuln_macro_recall` — recall over `vulnerability_ids`
- `mean_partial_rate`, `mean_coverage`

## Iteration workflow

1. Run `python -m extract_eval.evaluate --out report.json`.
2. Look at `report.json` for URLs where `status != "pass"`.
3. Tweak either:
   - the ontology hints in `extract_pipeline/ontology.py::CLASS_HINTS`,
   - the prompt rules in `extract_pipeline/llm.py::build_system_prompt`, or
   - the identity/merge rules in `extract_pipeline/merger.py`.
4. Re-run. Metrics should move in the right direction.
