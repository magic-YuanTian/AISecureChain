# AISecureChain — Information Extraction Pipeline

*Presentation report — current state, accuracy, performance, next steps*

---

## 1. What we built

An **ontology-driven information extraction pipeline** that turns any public
web page into structured facts in our AI security knowledge base.

```
  URL  →  Markdown  →  Chunks  →  Ontology Graph  →  Canonical Records  →  SQLite + same_as
        (crawl4ai)   (semantic)    (LLM, per chunk)     (merge + dedup)        (upsert)
```

**Why this design.** The extraction schema is generated *at runtime* from the
project ontology (`ai_vuln_kb.ttl` + per-class hints), so whenever we refine
the ontology, extraction follows automatically. No hard-coded prompts.

---

## 2. Pipeline stages

| # | Stage | What it does | Key property |
|---|-------|-------------|--------------|
| 1 | **Fetch** | `crawl4ai` renders the page (headless browser) to Markdown | Handles JS-heavy pages |
| 2 | **Chunk** | Split by `##/#/###` headers with size caps + overlap | Multi-record pages become N chunks |
| 3 | **Extract** | Per-chunk LLM call; prompt generated from ontology | Outputs a typed graph: entities + relations |
| 4 | **Merge** | Dedupe across chunks using class-specific canonical keys | Attributes are union-merged |
| 5 | **Validate** | Flag records missing required attributes | `is_partial = True` + reasons |
| 6 | **Persist** | Ontology-aware SQLite upsert with duplication checks | Never writes a duplicate |

### Graph-shaped output, not vuln-centric
The LLM emits any ontology entity (`Vendor`, `Software`, `SoftwareType`,
`Version`, `License`, `Vulnerability`, `VulnerabilityType`) plus typed
relations (`produce`, `hasVersion`, `vulnerableTo`, `isA_vulnType`, …).
This means we can extract product metadata from pages that have no CVE.

---

## 3. Duplication handling — 3 levels

Every insert passes through three checks before a new row is created:

| Level | Trigger | Action |
|-------|---------|--------|
| **L1 — Exact** | Same normalized identity already exists | Reuse PK. For vulnerabilities: `COALESCE` fills blanks but never overwrites. |
| **L2 — Alias** | Name differs in case/whitespace/aliases (`OpenAI` ≡ `Open AI` ≡ `OpenAI Inc.`) | Reuse PK; record new spelling in `entity_alias`. |
| **L3 — Same-as** | Different canonical IDs describe the same real-world thing (e.g. CVE-X mentions GHSA-Y) | Keep both; write `entity_same_as (left, right, confidence, reason)`. |

**Same-as heuristics** (each emits an auditable `reason` + `confidence`):
- **H1 (conf 0.95)** — one record's text/references mentions the other's ID
- **H2 (conf 0.85)** — identical title *and* identical CVSS base score
- **H3 (conf 0.90)** — identical CVSS vector *and* identical publish date

### New tables (idempotent CREATE IF NOT EXISTS)
```sql
entity_same_as (entity_type, left_key, right_key, confidence, reason, source_url, created_at)
entity_alias   (entity_type, alias_norm, entity_key)
```

---

## 4. Accuracy — current numbers

### Evaluation on 7 curated URLs (`extract_eval/urls.yaml`)

| Metric | Value | Meaning |
|--------|-------|---------|
| `pass_rate` | **1.00** | All 7 URLs pass all gold checks |
| `vuln_micro_recall` | **1.00** | Every expected CVE/GHSA/AVID id was found |
| `vuln_macro_recall` | **1.00** | Per-URL average also 1.00 |
| `mean_coverage` | **0.996** | Required attributes filled on nearly every entity |
| `mean_partial_rate` | **0.004** | Under 0.5% of entities lack required attrs |

Coverage includes: NVD CVE detail pages, GitHub Security Advisories,
AVID records, the OWASP LLM Top 10 (taxonomy / no-CVE case).

### Concrete extraction examples
| Page | Found |
|------|-------|
| NVD CVE-2024-5184 | 1 Vuln + 2 Vendors + 5 Software + 1 CWE |
| NVD CVE-2023-36258 (LangChain, wide-impact) | 1 Vuln + 1 Vendor + **11 Software** + 2 Versions |
| GHSA-56xg-wfcc-g829 (multi-record page) | **3 Vulns + 18 Software + 5 Vendors + 3 CWEs** |
| OWASP LLM Top 10 (taxonomy, no CVE) | 9 VulnerabilityTypes + 10 Software + 11 Vendors |

---

## 5. Performance

Per-stage timing on 4 representative URLs (`extract_eval/benchmark.py`):

| Stage | Mean | Median | p95 | Notes |
|-------|------|--------|-----|-------|
| crawl | 7.21 s | 5.63 s | 15.12 s | **bottleneck #1** — JS-heavy pages |
| chunk | <1 ms | <1 ms | <1 ms | negligible |
| extract (LLM) | 4.18 s | 3.77 s | 5.89 s | **bottleneck #2** — parallelised across chunks |
| merge | <1 ms | <1 ms | <1 ms | negligible |
| persist | <1 ms | <1 ms | <1 ms | negligible |
| **total** | **11.40 s** | 10.22 s | 18.53 s | throughput **≈ 5.3 URLs/min** single-stream |

Throughput scales linearly with concurrency; `--concurrency 4` ≈ 20 URLs/min.

---

## 6. Testing — 48 pytest cases, < 2 seconds

All tests are **hermetic**: no network, no LLM calls, no writes to the real DB.

| File | Tests | Focus |
|------|-------|-------|
| `test_chunker.py` | 6 | Header splits, size caps, overlap, listings |
| `test_merger.py` | 7 | Canonical keys, cross-chunk dedup, attribute union, partial flag |
| `test_llm_normalization.py` | 13 | JSON extraction, null handling, key-aliasing |
| `test_dedup.py` | 12 | Name normalization + same-as heuristics |
| `test_persist.py` | 6 | Idempotency, alias reuse, same-as edges, enrichment |
| `test_pipeline_mocked.py` | 5 | Full pipeline with mocked crawler + LLM |

### Reliability guarantees verified by tests
- Re-running the same URL produces **0 new rows** (idempotent).
- `OpenAI` / `Open AI` / `OpenAI Inc.` collapse to **one vendor row**.
- Cross-reference vulns emit a `same_as` edge (not duplicate rows).
- Re-extraction of a vulnerability **enriches blanks** but **never overwrites** existing values.
- Malformed LLM JSON or crawler failure produces a graceful error, not a crash.

---

## 7. Recommended data sources

Priority order for onboarding. All have been considered for crawling feasibility.

### Tier 1 — high-yield, structured, stable

| Source | URL | Why | Format |
|--------|-----|-----|--------|
| **NVD CVE Database** | `nvd.nist.gov` | Canonical CVE source; rich CVSS + CPE | HTML + JSON API |
| **GitHub Security Advisory DB** | `github.com/advisories` | Heavy AI-framework coverage (LangChain, LlamaIndex, vLLM, HF, Ollama) | HTML + GraphQL API |
| **OSV.dev** | `osv.dev` | Aggregates GHSA + NVD + PyPI + Go + Rust; excellent API | JSON API |
| **MITRE CVE** | `cve.org` | Upstream of NVD, earlier availability | HTML + JSON |

### Tier 2 — AI-specific, essential for our scope

| Source | URL | Why |
|--------|-----|-----|
| **AVID** (AI Vulnerability Database) | `avidml.org/database/` | Only DB dedicated to AI failure modes |
| **AI Incident Database (AIID)** | `incidentdatabase.ai` | Non-CVE real-world AI incidents |
| **MITRE ATLAS** | `atlas.mitre.org` | Adversarial ML tactics + techniques (TTPs) |
| **OWASP LLM Top 10** | `owasp.org/www-project-top-10-for-large-language-model-applications/` | Weakness taxonomy for LLM apps |
| **OWASP ML Top 10** | `owasp.org/www-project-machine-learning-security-top-10/` | Weakness taxonomy for classical ML |

### Tier 3 — bounty / disclosure reports (high-quality detail, lower volume)

| Source | URL | Notes |
|--------|-----|-------|
| **huntr.com** | `huntr.com/bounties` | AI/ML-focused bounty reports, many with reproducers |
| **Protect AI Threat Research** | `protectai.com/threat-research` | MLSecOps-oriented CVE writeups |
| **Patchstack** | `patchstack.com/database` | WordPress-AI plugin vulns but good cross-references |
| **Snyk Vulnerability DB** | `security.snyk.io` | Adds severity + exploit maturity info |

### Tier 4 — vendor-authored advisories

| Source | URL |
|--------|-----|
| LangChain | `github.com/langchain-ai/langchain/security/advisories` |
| HuggingFace | `huggingface.co/blog/tags/security` |
| vLLM / Ollama / LlamaIndex security tabs on GitHub |
| NVIDIA PSIRT | `nvidia.com/en-us/security/` |
| OpenAI Trust Portal | `trust.openai.com` |

### Tier 5 — academic / fresh intel (best via RSS or arxiv-sanity)

- **arXiv cs.CR** filtered by keywords: `prompt injection`, `jailbreak`, `LLM security`, `model extraction`, `adversarial examples`
- **USENIX Security / IEEE S&P / CCS / NDSS** proceedings
- Security vendor blogs: **Wiz**, **Lakera**, **Robust Intelligence**, **HiddenLayer**

### Recommended ingestion strategy
1. **Bulk seed** from OSV.dev + NVD JSON API → ~95% of known AI-related CVEs in one import.
2. **Supplement** with AVID + huntr for AI-native issues not in CVE.
3. **Ontology-enrich** via ATLAS / OWASP taxonomies (load as `VulnerabilityType` rows).
4. **Continuous feed** via GHSA RSS → daily incremental extraction.

---

## 8. What's next

Short-term (this sprint):
- Expand `urls.yaml` from 7 → ~50 curated URLs across all Tier 1–3 sources
- Add **batch ingestion CLI** (read a URL list file, persist all with one report)
- Surface `same_as` edges + partial flags in the UI

Medium-term:
- **Schema-guided JSON mode** (Azure OpenAI `response_format: json_schema`) to cut LLM error rate
- **Negative cache** so re-crawling a known-404/paywall URL is instant
- **Active-learning loop**: push disagreements (partial records, low-confidence same_as) to a human review queue

Long-term:
- Automated weekly crawl of all Tier 1–2 sources; populate the KB continuously
- Cross-source reconciliation via `same_as` to measure coverage overlap between OSV, NVD, GHSA, AVID
- Export the enriched KB as an RDF endpoint for the research community

---

## Appendix — how to reproduce every number in this deck

```bash
cd query_engine

# unit + integration tests (48 cases, < 2 s)
python -m pytest tests/ -v

# end-to-end accuracy eval (7 URLs, ~45 s with LLM)
python -m extract_eval.evaluate --out extract_eval/report.json

# per-stage performance benchmark
python -m extract_eval.benchmark --max-urls 4 --out extract_eval/bench.json

# one URL, full pipeline:
python -m extract_pipeline.pipeline \
    https://nvd.nist.gov/vuln/detail/CVE-2024-5184 --skip-db
```

Code layout:
- `extract_pipeline/`  core pipeline (8 modules, ~1.2k LoC)
- `extract_eval/`      evaluation harness + urls.yaml + benchmark
- `tests/`             pytest suite, no network
