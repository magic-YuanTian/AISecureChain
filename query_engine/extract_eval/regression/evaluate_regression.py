"""
Extraction-pipeline regression benchmark.

Runs the REAL extraction component (the same one the UI/API call) against frozen,
oracle-labeled fixtures and reports precision / recall / F1 per ontology class,
per document, and overall. Use it to catch regressions when you change the
pipeline, and to A/B different base LLMs.

Quick start
-----------
    cd query_engine

    # 1. (once) build frozen fixtures from the link list
    python -m extract_eval.regression.build_fixtures

    # 2. score the current pipeline against the oracle gold labels
    python -m extract_eval.regression.evaluate_regression

    # only some docs / write a report
    python -m extract_eval.regression.evaluate_regression --only research-caught-in-the --out report.json

    # A/B a different base LLM (overrides utils.openai_api via env)
    AISC_LLM_MODEL=gpt-4.1-mini python -m extract_eval.regression.evaluate_regression --out gpt41mini.json
    python -m extract_eval.regression.evaluate_regression --model gpt-4o --out gpt4o.json

Sources
-------
    --source fixture  (default)  run extraction over the cached markdown
                                 (deterministic input → isolates pipeline/LLM changes)
    --source live                re-crawl each URL and run the full pipeline
                                 (also exercises crawl/clean; flakier, network-bound)

Determinism: extraction runs at temperature 0, but LLMs are not perfectly
deterministic — run a couple of times if a single F1 looks borderline.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
QUERY_ENGINE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, QUERY_ENGINE)

from extract_pipeline import run_pipeline, run_pipeline_from_markdown  # noqa: E402
from extract_eval.regression import scorer  # noqa: E402
from extract_eval.regression.scorer import (  # noqa: E402
    HEADLINE_CLASSES, INFORMATIONAL_CLASSES, SCORED_CLASSES, ClassScore,
    classify_prediction, item_label, item_matched, prf, score_class,
)

GOLD_PATH = os.path.join(HERE, "gold.yaml")
FIXTURES_DIR = os.path.join(HERE, "fixtures")
MANIFEST_PATH = os.path.join(FIXTURES_DIR, "manifest.json")


def _set_fixtures_dir(path: str) -> None:
    """Point fixture + manifest reads at an alternate directory (e.g. fixtures_llm_cleaned)."""
    global FIXTURES_DIR, MANIFEST_PATH
    FIXTURES_DIR = os.path.abspath(path)
    MANIFEST_PATH = os.path.join(FIXTURES_DIR, "manifest.json")


def load_gold() -> dict:
    with open(GOLD_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)["docs"]


def load_manifest() -> dict:
    if not os.path.exists(MANIFEST_PATH):
        return {}
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        return json.load(f)


def predicted_by_class(result) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {c: [] for c in SCORED_CLASSES}
    for e in result.canonical_entities:
        if e.class_name in out:
            out[e.class_name].append(dict(e.attributes))
    return out


async def run_one(doc_id: str, gold_doc: dict, manifest: dict, source: str, max_chunks: int):
    """Run extraction for one doc and score it. Returns (doc_id, per_class_scores, meta)."""
    meta = {"doc_id": doc_id, "source": source}
    entry = manifest.get(doc_id, {})

    if source == "live":
        url = entry.get("url") or gold_doc.get("url")
        if not url:
            return doc_id, None, {**meta, "error": "no url in manifest"}
        result = await run_pipeline(url, skip_db=True, max_chunks=max_chunks)
    else:  # fixture
        fname = entry.get("fixture_file", f"{doc_id}.md")
        fpath = os.path.join(FIXTURES_DIR, fname)
        if not os.path.exists(fpath):
            return doc_id, None, {**meta, "error": f"missing fixture {fname}"}
        with open(fpath, encoding="utf-8") as f:
            md = f.read()
        result = await run_pipeline_from_markdown(
            md, url=entry.get("url", ""), skip_db=True, already_clean=True, max_chunks=max_chunks
        )

    if result.errors:
        meta["pipeline_errors"] = result.errors
    meta["url"] = entry.get("url") or gold_doc.get("url", "")
    meta["title"] = entry.get("title", "")
    meta["category"] = entry.get("category", "")
    meta["source_name"] = entry.get("source", "")
    meta["char_len"] = entry.get("char_len")
    pred = predicted_by_class(result)
    scores: dict[str, ClassScore] = {}
    for cname in SCORED_CLASSES:
        gold_cls = (gold_doc.get("classes", {}) or {}).get(cname, {}) or {}
        scores[cname] = score_class(cname, gold_cls, pred.get(cname, []))
    meta["entity_counts"] = result.entity_counts_by_class()
    meta["relation_counts"] = _relation_counts(result)
    meta["llm_usage"] = result.llm_usage or {}
    meta["predicted"] = {c: [p.get("name") or p.get("vuln_id") or p.get("title") for p in pred[c]] for c in pred}
    meta["details"] = _build_details(gold_doc, pred)
    return doc_id, scores, meta


def _build_details(gold_doc: dict, pred: dict[str, list[dict]]) -> dict:
    """Per-class ground-truth items (with match status) + predicted items (with
    verdict). Drives the Excel 'Ground Truth' and 'Predicted' sheets."""
    out = {}
    for c in SCORED_CLASSES:
        gold_cls = (gold_doc.get("classes", {}) or {}).get(c, {}) or {}
        preds = pred.get(c, [])
        gold_items = []
        for kind in ("required", "acceptable"):
            for it in gold_cls.get(kind, []) or []:
                gold_items.append({
                    "kind": kind,
                    "label": item_label(c, it),
                    "aliases": it.get("aliases", []) or [],
                    "matched": item_matched(c, it, preds),
                })
        pred_items = [{
            "value": p.get("name") or p.get("vuln_id") or p.get("id") or p.get("title") or "",
            "verdict": classify_prediction(c, p, gold_cls),
            "attrs": p,
        } for p in preds]
        out[c] = {"gold": gold_items, "predicted": pred_items}
    return out


def _relation_counts(result) -> dict:
    counts: dict[str, int] = {}
    for r in result.canonical_relations:
        counts[r.predicate] = counts.get(r.predicate, 0) + 1
    return counts


def _fmt(x):
    return "  -  " if x is None else f"{x:5.3f}"


def aggregate(per_doc: dict) -> dict:
    """Micro-average tp/fp/fn across docs, overall and per class."""
    by_class = {c: {"tp": 0, "fp": 0, "fn": 0} for c in SCORED_CLASSES}
    for _doc, scores in per_doc.items():
        if not scores:
            continue
        for c, sc in scores.items():
            by_class[c]["tp"] += sc.tp
            by_class[c]["fp"] += sc.fp
            by_class[c]["fn"] += sc.fn
    per_class = {c: prf(**v) for c, v in by_class.items()}
    # Headline excludes informational (validator-driven) classes.
    tot = {"tp": sum(by_class[c]["tp"] for c in HEADLINE_CLASSES),
           "fp": sum(by_class[c]["fp"] for c in HEADLINE_CLASSES),
           "fn": sum(by_class[c]["fn"] for c in HEADLINE_CLASSES)}
    return {"overall": prf(**tot), "per_class": per_class}


def _doc_totals(scores: dict) -> dict:
    """Per-doc micro totals over headline classes only."""
    tp = sum(scores[c].tp for c in HEADLINE_CLASSES)
    fp = sum(scores[c].fp for c in HEADLINE_CLASSES)
    fn = sum(scores[c].fn for c in HEADLINE_CLASSES)
    return prf(tp, fp, fn)


def print_report(per_doc_meta: dict, per_doc_scores: dict, agg: dict, cfg: dict) -> None:
    print("\n" + "=" * 78)
    print(f" EXTRACTION REGRESSION BENCHMARK   source={cfg['source']}  model={cfg['model']}")
    print("=" * 78)

    # Per-class table
    print(f"\n{'class':<20}{'P':>7}{'R':>7}{'F1':>7}{'tp':>6}{'fp':>6}{'fn':>6}")
    print("-" * 59)
    for c in SCORED_CLASSES:
        m = agg["per_class"][c]
        tag = " *" if c in INFORMATIONAL_CLASSES else ""
        print(f"{c+tag:<20}{_fmt(m['precision']):>7}{_fmt(m['recall']):>7}{_fmt(m['f1']):>7}"
              f"{m['tp']:>6}{m['fp']:>6}{m['fn']:>6}")
    print("-" * 59)
    o = agg["overall"]
    print(f"{'OVERALL (micro)':<20}{_fmt(o['precision']):>7}{_fmt(o['recall']):>7}{_fmt(o['f1']):>7}"
          f"{o['tp']:>6}{o['fp']:>6}{o['fn']:>6}")
    if INFORMATIONAL_CLASSES:
        print(f"  * informational only — excluded from OVERALL "
              f"({', '.join(sorted(INFORMATIONAL_CLASSES))} is validator/mapper-driven)")

    # Per-doc F1 (headline classes only)
    print(f"\n{'document':<42}{'P':>7}{'R':>7}{'F1':>7}")
    print("-" * 63)
    for doc_id, scores in per_doc_scores.items():
        meta = per_doc_meta[doc_id]
        if not scores:
            print(f"{doc_id:<42}  (skipped: {meta.get('error')})")
            continue
        m = _doc_totals(scores)
        flag = "  ! " + ";".join(meta["pipeline_errors"])[:40] if meta.get("pipeline_errors") else ""
        print(f"{doc_id:<42}{_fmt(m['precision']):>7}{_fmt(m['recall']):>7}{_fmt(m['f1']):>7}{flag}")

    print("\nLLM usage (extract + validate; free-tier cost often 0)")
    print(f"{'document':<42}{'stage':<10}{'calls':>6}{'prompt':>8}{'compl':>8}{'total':>8}{'cost':>10}")
    print("-" * 92)
    tot_ext = tot_val = 0
    cost_ext = cost_val = 0.0
    saw_ext = saw_val = False
    for doc_id, scores in per_doc_scores.items():
        meta = per_doc_meta[doc_id]
        if not scores:
            continue
        usage = meta.get("llm_usage") or {}
        for stage, key in (("extract", "extraction"), ("validate", "validation")):
            u = usage.get(key) or {}
            calls = int(u.get("calls") or 0)
            prompt = int(u.get("prompt_tokens") or 0)
            compl = int(u.get("completion_tokens") or 0)
            total = int(u.get("total_tokens") or 0)
            cost = u.get("cost")
            cost_s = f"{float(cost):.4f}" if cost is not None else "-"
            print(f"{doc_id:<42}{stage:<10}{calls:>6}{prompt:>8}{compl:>8}{total:>8}{cost_s:>10}")
            if key == "extraction":
                tot_ext += total
                if cost is not None:
                    cost_ext += float(cost)
                    saw_ext = True
            else:
                tot_val += total
                if cost is not None:
                    cost_val += float(cost)
                    saw_val = True
    parts = [f"extract_tok={tot_ext}", f"validate_tok={tot_val}"]
    if saw_ext:
        parts.append(f"extract_cost={cost_ext:.6f}")
    if saw_val:
        parts.append(f"validate_cost={cost_val:.6f}")
    print(f"suite total: {'  '.join(parts)}")
    print("=" * 78 + "\n")


def _stats(values: list[float]) -> dict:
    """mean / min / max / sample stdev of a metric across repeats."""
    vals = [v for v in values if v is not None]
    if not vals:
        return {"mean": None, "min": None, "max": None, "stdev": None, "n": 0}
    n = len(vals)
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / (n - 1) if n > 1 else 0.0
    return {"mean": mean, "min": min(vals), "max": max(vals),
            "stdev": var ** 0.5, "n": n}


def print_repeat_report(runs: list[dict], cfg: dict) -> dict:
    """Aggregate several identical runs and print mean ± spread.

    A single run of this suite swings by roughly ±0.03 F1 for reasons that have
    nothing to do with the pipeline (the extraction LLM is not deterministic
    even at temperature 0). Judging a change on one run is therefore unsound —
    this reports the distribution instead, plus a per-class stability figure so
    you can see WHERE the noise lives.
    """
    summary = {}
    for key in ("precision", "recall", "f1"):
        summary[key] = _stats([r["overall"][key] for r in runs])
    per_class = {}
    for cname in SCORED_CLASSES:
        per_class[cname] = {
            k: _stats([r["per_class"][cname][k] for r in runs])
            for k in ("precision", "recall", "f1")
        }

    print("\n" + "=" * 78)
    print(f" REPEATED RUNS: {len(runs)}x   source={cfg['source']}  model={cfg['model']}")
    print("=" * 78)
    print(f"\n{'metric':<12}{'mean':>8}{'stdev':>8}{'min':>8}{'max':>8}")
    print("-" * 44)
    for key in ("precision", "recall", "f1"):
        s = summary[key]
        print(f"{key:<12}{s['mean']:>8.3f}{s['stdev']:>8.3f}{s['min']:>8.3f}{s['max']:>8.3f}")

    print(f"\n{'class':<20}{'F1 mean':>9}{'F1 stdev':>10}   stability")
    print("-" * 56)
    for cname in SCORED_CLASSES:
        s = per_class[cname]["f1"]
        if s["mean"] is None:
            continue
        bar = "stable" if s["stdev"] < 0.02 else ("noisy" if s["stdev"] < 0.06 else "VERY NOISY")
        tag = " *" if cname in INFORMATIONAL_CLASSES else ""
        print(f"{cname+tag:<20}{s['mean']:>9.3f}{s['stdev']:>10.3f}   {bar}")
    print("=" * 78)
    print("A change is only real if it moves the mean by more than ~2x the stdev.\n")
    return {"summary": summary, "per_class": per_class, "n_runs": len(runs)}


async def _score_all(gold, manifest, args) -> tuple[dict, dict, dict]:
    doc_ids = [d for d in gold if not args.only or d in set(args.only)]
    sem = asyncio.Semaphore(args.concurrency)

    async def _guard(doc_id):
        async with sem:
            return await run_one(doc_id, gold[doc_id], manifest, args.source, args.max_chunks)

    results = await asyncio.gather(*[_guard(d) for d in doc_ids])
    per_doc_scores = {d: sc for d, sc, _m in results}
    per_doc_meta = {d: m for d, _sc, m in results}
    return per_doc_scores, per_doc_meta, aggregate(per_doc_scores)


async def main_async(args) -> dict:
    gold = load_gold()
    manifest = load_manifest()
    doc_ids = [d for d in gold if not args.only or d in set(args.only)]

    import datetime as _dt
    cfg = {
        "source": args.source,
        "model": os.environ.get("AISC_LLM_MODEL", "(default)"),
        "fixtures_dir": FIXTURES_DIR,
        "n_docs": len(doc_ids),
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
    }

    repeat = max(1, int(getattr(args, "repeat", 1) or 1))
    repeat_runs: list[dict] = []
    for i in range(repeat):
        if repeat > 1:
            print(f"\n--- run {i + 1}/{repeat} ---")
        per_doc_scores, per_doc_meta, agg = await _score_all(gold, manifest, args)
        repeat_runs.append(agg)
        if repeat == 1 or i == repeat - 1:
            print_report(per_doc_meta, per_doc_scores, agg, cfg)

    repeat_stats = None
    if repeat > 1:
        cfg["repeat"] = repeat
        repeat_stats = print_repeat_report(repeat_runs, cfg)

    report = {
        "config": cfg,
        "overall": agg["overall"],
        "per_class": agg["per_class"],
        "repeat_stats": repeat_stats,
        "per_doc": {
            d: {
                "metrics": _doc_totals(sc) if sc else None,
                "by_class": {c: {"precision": s.precision(), "recall": s.recall(), "f1": s.f1(),
                                 "tp": s.tp, "fp": s.fp, "fn": s.fn,
                                 "missed": s.missed_required, "false_positives": s.false_positives}
                             for c, s in sc.items()} if sc else None,
                "meta": per_doc_meta[d],
            }
            for d, sc in per_doc_scores.items()
        },
    }
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"report written to {args.out}")
    if args.xlsx:
        from extract_eval.regression.export_excel import build_workbook
        build_workbook(report, args.xlsx)
        print(f"excel written to {args.xlsx}")
    if args.csv:
        from extract_eval.regression.export_csv import export_all
        for p in export_all(report, args.csv):
            print(f"csv written to {p}")
    if args.combined:
        from extract_eval.regression.export_combined import export as export_combined
        for p in export_combined(report, args.combined):
            print(f"combined written to {p}")
    if args.audit_fps:
        from extract_eval.regression.judge import audit_report, write_yaml
        audit = await audit_report(report, concurrency=args.concurrency)
        write_yaml(audit, args.audit_fps)
        print(f"judge verdicts (advisory, score unchanged): {audit['counts']}")
        print(f"proposed gold additions -> {args.audit_fps}")
    if args.sheet:
        from extract_eval.regression.push_sheet import push_report
        try:
            print(f"sheet: {push_report(report)}")
        except Exception as e:  # keep the local report even if the upload fails
            print(f"sheet upload failed: {e}", file=sys.stderr)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Extraction-pipeline regression benchmark (P/R/F1).")
    ap.add_argument("--source", choices=["fixture", "live"], default="fixture",
                    help="fixture = cached markdown (default, reproducible); live = re-crawl URLs")
    ap.add_argument("--only", nargs="*", help="Only evaluate these doc ids")
    ap.add_argument("--model", help="Override base LLM (sets AISC_LLM_MODEL for this run)")
    ap.add_argument(
        "--fixtures-dir",
        help="Alternate fixtures directory (default: extract_eval/regression/fixtures). "
             "Must contain *.md and manifest.json.",
    )
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--max-chunks", type=int, default=12)
    ap.add_argument("--repeat", type=int, default=1,
                    help="Run the whole suite N times and report mean/stdev per metric. "
                         "Use >=3 before believing any headline delta (single-run noise is ~±0.03 F1).")
    ap.add_argument("--audit-fps", metavar="OUT.yaml",
                    help="After scoring, have an LLM judge review every false positive against the "
                         "source text and write PROPOSED gold additions here. Advisory only — the "
                         "score is never changed by the judge.")
    ap.add_argument("--out", help="Write the full JSON report here")
    ap.add_argument("--xlsx", help="Write an Excel workbook (summary + links + ground truth + predictions) here")
    ap.add_argument("--csv", help="Write flat CSVs (results_summary / ground_truth / predictions) into this dir")
    ap.add_argument("--combined", help="Write ONE unified table (<base>.csv + <base>.xlsx): tasks+summary+ground truth+predictions")
    ap.add_argument("--sheet", action="store_true",
                    help="Push per-doc results to the team Google Sheet (see push_sheet.py for auth setup)")
    args = ap.parse_args()

    if args.model:
        os.environ["AISC_LLM_MODEL"] = args.model
    if getattr(args, "fixtures_dir", None):
        _set_fixtures_dir(args.fixtures_dir)

    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
