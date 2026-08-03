# Extraction-pipeline regression benchmark

A small, **oracle-labeled** benchmark for the extraction pipeline. It runs the
real extraction component (the same `run_pipeline` code path the UI/API use)
against **frozen** web-page fixtures and reports **precision / recall / F1** per
ontology class, per document, and overall.

Use it to:
- catch regressions when you change `extract_pipeline/*` (chunker, cleaner,
  merger, validator, prompt, ontology hints);
- A/B different base LLMs;
- see exactly which entities the pipeline misses / hallucinates.

## Layout

```
extract_eval/regression/
  build_fixtures.py        # crawl + clean URLs → frozen markdown (run once)
  fixtures/                # *.md frozen pages + manifest.json   (the test INPUT)
  gold.yaml                # oracle ground-truth labels          (the ANSWER KEY)
  scorer.py                # matching + P/R/F1
  evaluate_regression.py   # runner: pipeline → score → report
  report_gpt4o.json        # last run's full report
```

## Running

```bash
cd query_engine
# (Python env must have the pipeline deps: crawl4ai, openai, pydantic, rdflib, pyyaml …)

# 1. one-time: build the frozen fixtures from the link list
python -m extract_eval.regression.build_fixtures

# 2. score the current pipeline
python -m extract_eval.regression.evaluate_regression

# subset / save a report
python -m extract_eval.regression.evaluate_regression --only research-caught-in-the --out report.json

# judge a CHANGE: repeat the suite and read mean ± stdev, never a single run
python -m extract_eval.regression.evaluate_regression --repeat 3 --out report.json

# have an LLM audit every false positive and propose gold fixes (advisory only)
python -m extract_eval.regression.evaluate_regression --out report.json --audit-fps proposed_gold.yaml

# export an Excel workbook (links + ground truth + predictions) in the same run
python -m extract_eval.regression.evaluate_regression --out report.json --xlsx results.xlsx

# push per-doc P/R/F1 to the team Google Sheet after the run
python -m extract_eval.regression.evaluate_regression --out report.json --sheet
# or push an existing report
python -m extract_eval.regression.push_sheet report.json
```

## Google Sheet upload

`push_sheet.py` writes the per-doc `task | link | precision | recall | f1`
table (plus an OVERALL and an info row) to the shared results sheet. Google
requires OAuth for all sheet writes, so a ONE-TIME setup is needed — either an
Apps Script web app (`AISC_SHEET_WEBAPP_URL`, simplest) or a service-account
key shared on the sheet (`AISC_GSA_FILE`). Setup steps, including the Apps
Script snippet to paste, are in the `push_sheet.py` docstring. Target sheet /
tab default to the team sheet and can be overridden with `AISC_SHEET_ID` /
`AISC_SHEET_GID` or `--sheet-id` / `--gid`.

## Excel export

`--xlsx <file>` (or stand-alone `python -m extract_eval.regression.export_excel report.json results.xlsx`)
writes a workbook with four sheets, made for manual testing:

| Sheet | Contents |
|-------|----------|
| **Summary** | run config (model, source, date) + overall and per-class P/R/F1 |
| **Per-Document** | one row per page: **clickable link**, title, category, P/R/F1, entity & relation counts, pipeline errors |
| **Ground Truth** | every oracle label (required/acceptable) per doc×class, with the link and whether the pipeline **matched** it (required misses highlighted red) |
| **Predicted** | every entity the pipeline produced, with **verdict** (TP=green / acceptable=yellow / FP=red), full attributes, and the link |

Requires `openpyxl` (in `requirements.txt`).

### One-file combined export

`--combined <base>` (or `python -m extract_eval.regression.export_combined report.json <base>`)
writes **everything in one table** — `<base>.csv` and a single-sheet `<base>.xlsx` —
where one `section` column distinguishes the row type:

| section | row is | key columns |
|---|---|---|
| `info` | run config | key, ground_truth(=value) |
| `task` | a project task | key(id), ground_truth(subject), details(group), verdict(status) |
| `summary` | overall / per-class metric | key(name), precision…fn |
| `document` | per-document metric | key(doc_id), link, precision…fn |
| `detail` | **a gold label aligned with its matching prediction** | doc_id, link, class, kind, ground_truth, matched, prediction, verdict, attributes |

So in one sheet you can read each task, each ground-truth label, the corresponding
prediction (or `MISS` / `(no matching gold)` → `FP`), and the metrics. Filter the
`section` column to focus on one view.

### Why fixtures are frozen

News/blog pages change and the crawler is network-bound and non-deterministic.
A regression test needs a **fixed input**, so we crawl each URL once, clean it
exactly as the pipeline does, and store the markdown under `fixtures/`. The
evaluator then runs only the post-crawl stages (`run_pipeline_from_markdown`,
added to `pipeline.py`) — the identical code the UI runs after a crawl.

To also exercise the live crawler:
```bash
python -m extract_eval.regression.evaluate_regression --source live
```

## Swapping the base LLM

`utils/openai_api.py` reads its config from the environment (defaults to the
project's Azure GPT-4o). The benchmark sweeps models with no code change:

```bash
python -m extract_eval.regression.evaluate_regression --model gpt-4.1-mini --out gpt41mini.json
# or set the env directly (also affects the live app):
AISC_LLM_MODEL=gpt-4o AISC_LLM_ENDPOINT=... AISC_LLM_API_KEY=... \
  python -m extract_eval.regression.evaluate_regression --out run.json
```

Env vars: `AISC_LLM_MODEL`, `AISC_LLM_ENDPOINT`, `AISC_LLM_API_KEY`,
`AISC_LLM_API_VERSION`, `AISC_LLM_PROVIDER` (`azure` | `openai`).

## Scoring model

For each document × ontology class, `gold.yaml` lists:

- **`required`** — entities that *should* be extracted → drive **recall**.
- **`acceptable`** — entities legitimately on the page but optional. A predicted
  entity matching an acceptable item is **neutral**: never a false positive,
  never adds recall. This keeps **precision fair** for fuzzy free-text classes
  (Attack/Impact): we only penalize predictions that are *neither* required nor
  acceptable — i.e. genuine over-extraction or hallucination.

```
tp = required items with ≥1 matching prediction
fn = required items with no match
fp = predictions matching neither required nor acceptable
precision = tp/(tp+fp)   recall = tp/(tp+fn)   F1 = 2PR/(P+R)
```

Matching is normalized (lowercase, depunctuated, singularized) with whole-token
subset matching and per-item `aliases`. Vulnerabilities match by `vuln_id`
(`{id: CVE-…}`) or, for no-CVE findings, by keyword (`{title_any: […]}`).

`VulnerabilityType` is marked **informational** (`*`) and **excluded from the
headline** metric: CWE types are assigned by the separate validator/CWE-mapper
stage, not lifted from the page text, so they're a different concern.

An empty `required` **and** empty `acceptable` for a class is an
**anti-hallucination** check — any prediction there is a false positive (e.g. a
page with no CWE id must yield no `VulnerabilityType`).

## Extending the gold set

29 fixtures are cached; **23** are oracle-labeled in `gold.yaml` (the rest are
listed as comments at the end of that file, with the reason they are excluded).
To add one:
1. append a row to `test_links.csv` (columns: Category, Title, Source, Date,
   Link, Summary, Test);
2. `python -m extract_eval.regression.build_fixtures --only <id>` — the id is
   `<domain>-<first three title words>`, e.g.
   `securityweek-vulnerability-in-claude`;
3. read the fixture `fixtures/<id>.md` yourself (be the oracle — label from the
   frozen text, not the CSV summary);
4. add a `docs.<id>` block with `required`/`acceptable` per class;
5. put on-page-but-optional entities in `acceptable` so precision stays fair;
6. re-run. Re-label if you rebuild a fixture (page content changed).

## Current baseline (GPT-4o, source=fixture, 23 docs, 2026-07-30)

Measured over **3 repeats** (`--repeat 3`), headline excludes informational
VulnerabilityType:

| metric | mean | stdev |
|--------|------|-------|
| precision | **0.834** | 0.022 |
| recall | **0.895** | 0.018 |
| **F1** | **0.863** | 0.007 |

| class | F1 mean | F1 stdev |
|-------|---------|----------|
| Vendor | 0.928 | 0.034 |
| Software | 0.910 | 0.028 |
| Vulnerability | 0.889 | 0.025 |
| Impact | 0.830 | 0.021 |
| Attack | 0.829 | 0.012 |

### Always judge a change with `--repeat`, and mind which number you read

The aggregate F1 is far more stable (stdev **0.007**) than any single class
(0.012–0.034). Errors trade *between* classes — a misclassified entity is one
class's FP and another's FN — so the micro-average absorbs noise its own
components do not.

Practical rule:
- **headline F1**: a move of >0.015 is real;
- **a single class**: never trust one run — per-class stdev has been as high as
  0.067, so "Impact improved 0.05" from a single pair of runs means nothing.

Earlier notes in this file quoted "±0.03 headline noise". That figure came from
comparing runs at *different* configurations and was wrong; the measured value
is above.

History of the precision-fix iteration (all 22 docs, same gold):

| run | P | R | F1 | change |
|-----|-----|-----|-----|--------|
| `report_expanded.json` | 0.38 | 0.84 | 0.52 | old recall-oriented prompt |
| `report_precision_fix.json` | 0.58 | 0.82 | 0.68 | negative constraints + `role` attr + deterministic filters |
| `report_precision_fix2.json` | 0.58 | 0.90 | 0.71 | minted-id drop, advisory-page rules, specificity-first impacts |
| `report_precision_fix3.json` | 0.72 | 0.88 | 0.79 | listicle enumeration cap, descriptive-name filter |
| `report_precision_fix4.json`* | 0.70 | 0.92 | 0.79 | + CWE-candidate fix, `vulnerableTo` rule, relation type-check/repair; **23 docs** (adds `securityweek-vulnerability-in-claude`) |
| `report_impact_fix.json` | 0.81 | 0.88 | 0.84 | Impact gold audit + mitigation-evidence filter |
| `report_hybrid.json` (3x) | 0.796 | 0.902 | 0.845 | + `id_any`, Vendor framework/self-name guard |
| `report_final.json` (3x) | **0.834** | 0.895 | **0.863** | + descriptive-org Vendor filter, judge-reviewed gold |

The last step is a **verified** improvement: ΔF1 +0.018 against a 2σ threshold
of 0.016, with recall unchanged. It also *halved the noise* where it mattered —
Impact F1 stdev 0.067 → 0.021, Vendor F1 0.843 → 0.928. Single-run entries
above the 3x rows are historical and should not be compared to them directly.

<sub>* superseded file name; the run is described in the git history of this README.</sub>

The final row is the best recall recorded on this suite (0.92) at the same F1 as
the previous best. The newly added SecurityWeek fixture scores **P 1.00 / R 0.86
/ F1 0.92** — zero false positives on a page carrying ad markup, four "Related:"
links, an author bio and a newsletter form. Its single miss is the
'Malicious Browser Extension' delivery vector, a known and deliberately-labeled
gap (two attempts to fix it by prompt both cost more precision than they bought
— see the negative-results table).

### Measured negative results — do not re-try these

Three changes were tried against this benchmark and **reverted** because they
lost more than they gained. Recorded so nobody re-implements them:

| tried | result | why it failed |
|-------|--------|---------------|
| "emit every technique in the attack chain" (rule 14) | P 0.72 → 0.63, TP unchanged | +13 Impact FPs, zero new TPs; did not even recover the delivery-vector miss that motivated it |
| synonym normalization hint ("information theft" → "Data Exfiltration") | P 0.72 → 0.65 | couples badly with `filters.py`: the gate passes anything with a *standard* name, so pushing the model toward standard vocabulary let junk through wearing standard names |
| `filters.py` gate requiring a relation link (no standard-name bypass) | P 0.74 / **R 0.77** / F1 0.76 | best precision seen, but the model often forgets to wire an edge, so real Attacks/Impacts were dropped (Attack FN 4 → 9) |
| repairing mis-wired **causal** edges (`exploits` / `resultsIn`) | F1 0.78 → 0.74, Impact FP 28 → 32 | those edges are the filter's own gate: repairing one rescues an entity the filter would rightly have dropped. Repair is now scoped to structural edges (`_REPAIRABLE_PREDICATES` in `llm.py`) |

Lesson: `CLASS_HINTS` wording, the `filters.py` gates, and the relation graph are
all **coupled** — the filters decide what to keep by reading entity *names* and
*edges*, so anything that changes naming or edges silently changes filtering.
Always re-run the benchmark after touching any of the three.

What changed: per-class negative constraints + standard-name vocabularies in
`extract_pipeline/ontology.py::CLASS_HINTS`, stricter extraction rules in
`llm.py::build_system_prompt` (Attack=method vs Impact=outcome, no CVSS metric
labels, relation-linking required), a deterministic post-filter stage
(`extract_pipeline/filters.py`), and a validator fix so minted `AISC-…` ids
are collapsed/dropped when an official CVE/GHSA id covers the finding.

Remaining known weaknesses:
- **Impact precision (~0.69)** is still the lowest class. The 11 surviving FPs
  were each checked against the frozen text and left deliberately: entities
  whose own evidence contradicts their name (lakera 'System Prompt Disclosure'
  supported by a sentence about misdescribing people), an Attack name emitted
  as an Impact ('Supply Chain Attack'), and impacts still lifted from
  mitigation prose that the regex does not catch.
- Multi-incident roundup pages (welivesecurity) still under-recall.
- 'Malicious Browser Extension' as a delivery vector is missed on both pages
  that describe one — the one labeled recall gap left standing on purpose (two
  prompt attempts to close it cost more precision than they bought).

## Model ablation: GPT-4o vs Qwen3.5-4B (2026-07-30, 23 docs, 1 run each)

Run with the evaluation pipeline untouched — only the LLM env vars change:

```bash
# serve the open model (6-way data parallel; see scratchpad/serve_qwen.sh)
vllm serve Qwen/Qwen3.5-4B --data-parallel-size 6 --max-model-len 16384 --max-num-seqs 16

AISC_LLM_PROVIDER=openai AISC_LLM_ENDPOINT=http://localhost:8077/v1 \
AISC_LLM_MODEL=Qwen/Qwen3.5-4B AISC_LLM_MAX_TOKENS=4096 \
AISC_LLM_EXTRA_BODY='{"chat_template_kwargs":{"enable_thinking":false}}' \
python -m extract_eval.regression.evaluate_regression --out report_qwen35_4b.json
python -m extract_eval.regression.compare_models GPT-4o=report_rerun.json Qwen3.5-4B=report_qwen35_4b.json
```

| | GPT-4o | Qwen3.5-4B | Qwen3.5-9B |
|---|---|---|---|
| precision | **0.796** | 0.603 | 0.619 |
| recall | 0.905 | 0.768 | 0.874 |
| F1 | **0.847** | 0.676 | 0.725 |
| Vulnerability F1 | 0.914 | **0.974** | 0.973 |
| Vendor F1 | 0.696 | 0.593 | 0.692 |
| Software F1 | **0.909** | 0.722 | 0.682 |
| Attack F1 | **0.880** | 0.591 | 0.627 |
| Impact F1 | **0.806** | 0.571 | 0.704 |

Findings:
- Both open models **match or beat GPT-4o on Vulnerability** (F1 ≈ 0.97) —
  pulling CVE/GHSA ids is pattern matching, which 4B already handles.
- The gap is **precision, not recall**. 9B recall (0.874) is close to GPT-4o's
  (0.905); its precision (0.619) is not. The open models find the right things
  and then keep going — Software FP 8→14 and Impact FP 24→20 while GPT-4o sits
  at 3 and 11. The prompt's *negative* constraints ("do NOT emit generic
  categories / defensive benefits / CVSS labels") are what they follow least.
- **Scaling 4B→9B buys recall, not precision**: R +0.106, P +0.016. Impact F1
  +0.133 and the zero-extraction collapses mostly disappear, but no class
  reaches GPT-4o's precision.
- **Format compliance was never the problem** for either: no JSON parse
  failures. Disabling Qwen's default thinking mode (`enable_thinking:false`)
  plus the `<think>` stripper in `llm.py::_extract_json_blob` sufficed.
- **4B's real weakness is instability.** Documents collapse to zero usable
  entities (sometimes only `SoftwareType`), *not reproducibly*:
  `adversa-top-ai-security` scored 0.0 in one run and 0.800 in another at
  identical settings. `max_tokens` 4096→8192 did not help (worse), so
  truncation is ruled out. 9B scores 0.909 on that same document.

Consequence for anyone repeating this: **a single run understates and mis-ranks
the open models**, 4B especially. Use `--repeat 3` before quoting a number.
`compare_models.py` prints all of the above side by side.

## The LLM judge (`judge.py`) — an auditor, never the scorer

String matching cannot know that "Data Exfiltration" and "Data Leak" are the
same harm, so gold alias lists rot and correct extractions get scored as false
positives. Auditing those by hand is slow. `--audit-fps out.yaml` hands exactly
that job to an LLM:

```bash
python -m extract_eval.regression.evaluate_regression --out r.json --audit-fps proposed_gold.yaml
python -m extract_eval.regression.judge r.json proposed_gold.yaml   # or over an existing report
```

It sees only entities the string matcher already called FP, and answers: alias
of an existing label / genuinely acceptable / really a false positive. Output is
a commented proposal file for a human to merge. **It cannot create a true
positive, change recall, or move F1.**

Why it must stay advisory — from the first real run (45 FPs → 29 upheld, 16
proposals, of which **5 were rejected on review**):

| judge proposed | why it was rejected |
|---|---|
| "Logistics SaaS platform" / "Machine-learning system for firmware verification" as `Software` | descriptive phrases, not product names — the pipeline deliberately filters these; accepting them would reward what we suppress |
| "Remote Code Execution" as an `Attack` | RCE is an outcome; this breaks the Attack/Impact split the prompt works hard to enforce |
| "Privilege Escalation" as an alias of "Malicious Browser Extension" | an impact aliased to a delivery vector — incoherent |

The judge only knows "does the page mention this". It does not know the class
definitions or the filtering policy. Had it been allowed to write the score,
all five would have passed, inflating the metric *and* pointing later tuning in
the wrong direction. Self-preference bias (same model family judging its own
output) is the second reason. Determinism is the third — the extraction LLM
already supplies all the variance this suite can absorb.

### Labeling discipline

`acceptable` is for entities **the page genuinely contains**; it is not a
dumping ground for anything the pipeline happens to emit. When auditing FPs,
the test is whether the entity's own evidence sentence supports its name. If it
does, label it. If the evidence is a mitigation recommendation, a different
concept, or self-contradictory, leave it as a false positive — that number is
supposed to hurt.
- LLM extraction is not perfectly deterministic; compare deltas, not absolutes.
  Observed run-to-run swing on this suite is roughly ±0.03 F1, so treat
  differences below that as noise.

### What this benchmark does NOT measure

It scores **entities only**. Two real defects found by hand-checking a live
article (SecurityWeek "ClaudeBleed", 2026-07-30) were invisible to it:
- a Vulnerability left with **no `vulnerableTo` edge**, so the affected product
  was disconnected in the KB (fixed: `llm.py` rule 13b);
- a **type-invalid relation** (`Vulnerability --produce--> Software`) corrupting
  the Software canonical key (fixed: ontology domain/range check in
  `llm.py::_normalize_graph`).

`VulnerabilityType` is also excluded from the headline, which hid a wrong-CWE
bug: candidate scoring fell back to token overlap and broke ties by *string-
sorted id*, so CWE-1112 beat CWE-346 on the shared word "execution" (fixed:
`validator.py`, keyword rules + require ≥2 shared tokens). Rows already written
to the KB by the old mapper were repaired separately — see
`scripts/audit_cwe_mappings.py`, which carries the hand-reviewed correction
table and a `--scan` mode for finding new suspects.

Relation-level and CWE-level scoring would be the highest-value additions to
this suite.

LLM extraction is not perfectly deterministic even at temperature 0; run 2–3×
if a single F1 looks borderline, and compare deltas rather than absolute values.
```
