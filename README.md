# AISecureChain

An AI/ML vulnerability knowledge base. It collects security advisories, uses an
LLM to extract a structured ontology from them, stores the result as both a
relational database and an RDF graph, and serves it through a REST/SPARQL API
with a React front end.

The extraction quality is measured by an oracle-labeled regression benchmark
that is part of this repository — see [Evaluation](#5-evaluation-optional).

---

## What is in here

| Path | What it is |
|------|------------|
| `query_engine/app.py` | Flask API + serves the production front-end build |
| `query_engine/build_db.py` | Builds the SQLite knowledge base from collected JSON |
| `query_engine/build_rdf.py` | Serializes the database into an OWL/RDF graph |
| `query_engine/extract_pipeline/` | crawl → clean → chunk → LLM extract → merge → validate → filter → persist |
| `query_engine/utils/openai_api.py` | **The only place the project calls an LLM.** Ships without credentials — you configure it |
| `query_engine/frontend/` | React UI (query, graph exploration, extraction) |
| `query_engine/extract_eval/regression/` | The extraction benchmark: frozen fixtures, gold labels, scorer |
| `explore_misp.py`, `fetch_cve_details.py` | Data collection from MISP and cvelistV5 |

Ontology namespace `http://aisecurechain.org/ontology#`, nine classes. The core
causal chain is `Attack —exploits→ Vulnerability —resultsIn→ Impact`, with
`Vendor → Software → Version` on the asset side.

---

## Deployment, step by step

### Prerequisites

- Python 3.10+ (3.11 recommended)
- Node.js 18+ and npm (only if you want to rebuild the front end)
- An LLM endpoint — Azure OpenAI, OpenAI, or **any OpenAI-compatible server**
  (vLLM, Ollama, LM Studio). Required for extraction; not needed just to browse
  an existing database.

### 1. Get the code and install dependencies

```bash
git clone https://github.com/magic-YuanTian/AISecureChain.git
cd AISecureChain

python -m venv .venv && source .venv/bin/activate    # or conda create -n aisecurechain python=3.11
pip install -r requirements.txt
```

### 2. Configure credentials

**No credentials are committed to this repository.** Create your own:

```bash
cp .env.example .env
```

Then edit `.env`. The LLM block is the only part required to run the system:

```ini
AISC_LLM_ENDPOINT=https://<your-endpoint>/   # empty → api.openai.com
AISC_LLM_API_KEY=<your-key>
AISC_LLM_MODEL=gpt-4o
```

Azure endpoints are detected automatically; anything else is treated as an
OpenAI-compatible server.

`.env` is git-ignored. Anything already exported in your shell overrides it,
which is how you point a single run at a different model:

```bash
AISC_LLM_MODEL=gpt-4.1-mini python -m extract_eval.regression.evaluate_regression
```

<details>
<summary>Using a local open-weight model instead (vLLM)</summary>

```bash
vllm serve Qwen/Qwen3.5-9B --port 8000 --max-model-len 16384 --max-num-seqs 8

# .env
AISC_LLM_ENDPOINT=http://localhost:8000/v1
AISC_LLM_API_KEY=dummy
AISC_LLM_MODEL=Qwen/Qwen3.5-9B
```

Two things worth knowing if you go this route:

- **Reasoning models** (Qwen3.x, DeepSeek-R1) emit chain of thought before the
  answer, and that text contains braces which break JSON parsing. Fix it on the
  server, not in the client: `vllm serve … --reasoning-parser qwen3` puts the
  reasoning in a separate field. (`extract_pipeline/llm.py` also strips stray
  `<think>` blocks as a backstop.)
- **Declared context size costs memory.** vLLM reserves KV cache per sequence,
  so `--max-model-len 32768` under concurrency will OOM a 24GB card. The real
  prompt here is ~5k tokens; 16384 is ample.
</details>

Verify the LLM layer before going further:

```bash
cd query_engine && python -m utils.openai_api
# prints the active config and the model's reply, or a clear message telling you
# what is missing
```

The MISP block in `.env` is only needed for step 3.

### 3. Build the knowledge base

The database (`ai_vuln_kb.db`) and graph (`ai_vuln_kb.ttl`) are **not** in the
repository — they are generated. You have two ways to get one:

**Option A — start empty and populate through the UI.** Skip to step 4; the
extraction page will create the schema on first write. Best for trying the
system out.

**Option B — build from bulk sources.** Requires MISP credentials in `.env` and
a local clone of the CVE list:

```bash
git clone --depth 1 https://github.com/CVEProject/cvelistV5.git   # ~5GB
python explore_misp.py          # → output/all_ai_events_full.json
python fetch_cve_details.py     # → output/cve_details.json
cd query_engine
python build_db.py              # → ai_vuln_kb.db
python build_rdf.py             # → ai_vuln_kb.ttl  (SPARQL endpoints read THIS)
```

> Whenever you change data the graph exposes, re-run `build_rdf.py`. The SPARQL
> endpoints read the `.ttl` file, not the database, so corrections are invisible
> to the graph API until it is regenerated.

### 4. Run the system

**Back end** (listens on `0.0.0.0:5093`, also serves `frontend/build` if present):

```bash
cd query_engine
python app.py
```

**Front end.** For development with hot reload:

```bash
cd query_engine/frontend
npm install
npm start                       # http://localhost:3000, proxies /api to :5093
```

For production, build once and let Flask serve it from the same port:

```bash
npm run build
# then restart the Flask process — it serves frontend/build at http://localhost:5093
```

> `frontend/src/api.ts` uses a relative `/api` base URL, so the built front end
> is served from the same origin as the API. After changing Python code you must
> restart Flask; a running server keeps executing the old module.

### 5. Extract from a URL

Through the UI, or from the command line:

```bash
cd query_engine
python -m extract_pipeline.pipeline https://example.com/some-advisory --skip-db
# drop --skip-db to persist into ai_vuln_kb.db
```

### 6. Evaluation (optional)

The benchmark runs the real pipeline over **frozen** page fixtures, so scores
are reproducible and independent of the network:

```bash
cd query_engine
python -m pytest tests/                                     # 87 unit tests, no network, no LLM
python -m extract_eval.regression.evaluate_regression       # score the pipeline
python -m extract_eval.regression.evaluate_regression --repeat 3   # mean ± stdev
```

Judge a change on `--repeat 3`, never a single run: aggregate F1 has a standard
deviation of ~0.007 across identical runs, but per-class F1 reaches 0.067.
`extract_eval/regression/README.md` documents the scoring model, the labeling
discipline, and a table of tuning ideas that were measured and rejected.

Comparing two models:

```bash
python -m extract_eval.regression.compare_models a=report_a.json b=report_b.json --csv out.csv
```

---

## Security notes

- **Never commit `.env`.** It is git-ignored; keep it that way.
- `query_engine/utils/openai_api.py` contains no endpoint or key. If you add
  one "just for testing", it will end up in the history.
- The generated database, the RDF graph, crawled output and benchmark run
  reports are all git-ignored — they are derived artifacts, not source.

## Configuration reference

| Variable | Purpose |
|----------|---------|
| `AISC_LLM_ENDPOINT` | Base URL. Azure endpoints are auto-detected; empty → api.openai.com |
| `AISC_LLM_API_KEY` | API key (`dummy` is fine for a local vLLM/Ollama) |
| `AISC_LLM_MODEL` | Deployment / model name |
| `MISP_URL`, `MISP_API_KEY`, `MISP_VERIFY_SSL` | Only for `explore_misp.py` |
| `AISC_SHEET_ID`, `AISC_SHEET_GID` | Optional: push benchmark results to a Google Sheet |

Need a provider that does not speak the OpenAI protocol (Anthropic, Bedrock, an
internal gateway)? Rewrite the body of `get_response()` in
`query_engine/utils/openai_api.py`. It is the only LLM call site in the project,
and its contract is documented in that function's docstring.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `LLMNotConfigured` | `.env` missing or `AISC_LLM_API_KEY` empty — see step 2 |
| Front end loads but API calls 404 | Flask not running, or `npm run build` was not re-run after a front-end change |
| Code changes have no effect | Flask caches imported modules — restart `python app.py` |
| Graph/SPARQL results look stale | Re-run `python build_rdf.py` after changing the database |
| `database is locked` | SQLite uses WAL with a busy timeout; a long write is in progress — retry |
