# Extraction regression benchmark

Runs the real extraction pipeline against **frozen** page fixtures and reports
precision / recall / F1 per ontology class, per document, and overall. Because
the input is frozen, scores depend only on the pipeline — not on the network or
on a page having changed since yesterday.

Use it to catch regressions when changing `extract_pipeline/*`, and to compare
base LLMs.

## Layout

```
build_fixtures.py         crawl + clean URLs → frozen markdown (run once)
fixtures/                 *.md frozen pages + manifest.json    (the INPUT)
gold.yaml                 oracle ground-truth labels           (the ANSWER KEY)
scorer.py                 matching + P/R/F1
evaluate_regression.py    runner: pipeline → score → report
judge.py                  LLM auditor over false positives (advisory)
compare_models.py         side-by-side comparison of two reports
```

## Running

From `query_engine/`:

```bash
# one-time: build the frozen fixtures from the link list
python -m extract_eval.regression.build_fixtures

# score the current pipeline
python -m extract_eval.regression.evaluate_regression

# subset, or save a full report
python -m extract_eval.regression.evaluate_regression --only nvd-emailgpt-prompt-injection
python -m extract_eval.regression.evaluate_regression --out report.json
```

### Judging a change

Extraction is not deterministic even at temperature 0. Aggregate F1 varies by
roughly ±0.01 between identical runs, and per-class F1 by considerably more, so
a single pair of runs cannot tell an improvement from noise:

```bash
python -m extract_eval.regression.evaluate_regression --repeat 3
```

This reports mean ± standard deviation per metric plus a per-class stability
figure. Treat a change as real only when it moves the mean by more than twice
the standard deviation.

### Comparing two models

```bash
AISC_LLM_MODEL=gpt-4.1-mini python -m extract_eval.regression.evaluate_regression --out b.json
python -m extract_eval.regression.compare_models base=a.json alt=b.json --csv out.csv
```

Any OpenAI-compatible endpoint works — see the root README for serving an
open-weight model locally.

### Auditing the gold set

String matching cannot tell that "Data Exfiltration" and "Data Leak" are the
same harm, so gold alias lists drift out of date and correct extractions start
counting as false positives.

```bash
python -m extract_eval.regression.evaluate_regression --out r.json --audit-fps proposed.yaml
```

An LLM reviews every entity the scorer called a false positive and writes
proposed gold additions to `proposed.yaml`. It is **advisory**: it only ever
sees entities already scored as false positives, cannot create a true positive,
and never changes a metric. Read the proposals, drop the ones you disagree
with, then merge by hand.

### Exports

```bash
--xlsx results.xlsx          # summary + per-doc links + ground truth + predictions
--combined base              # everything in one table (base.csv + base.xlsx)
--sheet                      # push per-doc P/R/F1 to a Google Sheet (see push_sheet.py)
```

## Scoring model

For each document × ontology class, `gold.yaml` lists:

- **`required`** — entities that *should* be extracted → drive **recall**.
- **`acceptable`** — entities legitimately on the page but optional. A
  prediction matching one is **neutral**: never a false positive, never adds
  recall. This is what keeps precision fair for free-text classes like Attack
  and Impact — only predictions matching *neither* list are penalised.

```
tp = required items with ≥1 matching prediction
fn = required items with no match
fp = predictions matching neither required nor acceptable

precision = tp/(tp+fp)   recall = tp/(tp+fn)   F1 = 2PR/(P+R)
```

Matching is normalised (lowercase, depunctuated, singularised) with whole-token
subset matching plus per-item `aliases`. Vulnerabilities match by id
(`{id: CVE-…}`), by any of several equivalent ids (`{id_any: [GHSA-…, CVE-…]}`
— one advisory often carries both), or by keyword for findings with no public
id (`{title_any: [...]}`).

An empty `required` **and** empty `acceptable` is an anti-hallucination check:
any prediction in that class is a false positive.

`VulnerabilityType` is **excluded from the headline** metric. CWE types are
assigned by the validator's mapping stage rather than lifted from the page, so
they measure a different thing.

## Extending the gold set

1. Add a row to `../../../test_links.csv` (Category, Title, Source, Date, Link,
   Summary, Test).
2. `python -m extract_eval.regression.build_fixtures --only <id>` — the id is
   `<domain>-<first three title words>`.
3. **Read `fixtures/<id>.md` yourself** and label from the frozen text, not from
   the summary. You are the oracle.
4. Add a `docs.<id>` block with `required` / `acceptable` per class.
5. Re-run. Re-label if you ever rebuild that fixture.

### Labelling discipline

`acceptable` is for entities the page genuinely contains — not a place to park
anything the pipeline happened to emit. The test for a disputed entity is
whether its own evidence sentence supports its name. If the evidence is a
mitigation recommendation, a different concept, or absent, leave it a false
positive. That number is supposed to hurt.

## What this benchmark does not measure

It scores **entities only**. Relations are summarised but not scored, so a
vulnerability left unconnected to its affected product, or an edge wired to the
wrong endpoint, will not show up here. CWE mapping quality is likewise reported
but excluded from the headline. Relation-level and CWE-level scoring are the
highest-value additions to this suite.
