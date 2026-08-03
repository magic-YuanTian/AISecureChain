"""Side-by-side comparison of two (or more) benchmark reports — an LLM ablation.

Reads reports produced by `evaluate_regression --repeat N` and prints every
metric next to each other: overall P/R/F1 with spread, per-class P/R/F1, and
per-document F1. Where both reports carry `repeat_stats`, differences are
tested against the measured run-to-run noise instead of being read off a single
run — a delta only counts when it exceeds 2x the larger stdev.

Usage:
    python -m extract_eval.regression.compare_models \
        baseline=report_final.json qwen=report_qwen.json
    python -m extract_eval.regression.compare_models a.json b.json --csv out.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

from extract_eval.regression.scorer import SCORED_CLASSES  # noqa: E402

METRICS = ("precision", "recall", "f1")


def _load(spec: str) -> tuple[str, dict]:
    label, _, path = spec.partition("=")
    if not path:
        path, label = label, os.path.basename(label).replace(".json", "")
    with open(path, encoding="utf-8") as f:
        return label, json.load(f)


def _overall(rep: dict, metric: str) -> tuple[float | None, float | None]:
    """(value, stdev). Prefers repeat statistics when present."""
    rs = rep.get("repeat_stats")
    if rs and rs.get("summary", {}).get(metric):
        s = rs["summary"][metric]
        return s.get("mean"), s.get("stdev")
    return rep.get("overall", {}).get(metric), None


def _per_class(rep: dict, cname: str, metric: str) -> tuple[float | None, float | None]:
    rs = rep.get("repeat_stats")
    if rs and rs.get("per_class", {}).get(cname, {}).get(metric):
        s = rs["per_class"][cname][metric]
        return s.get("mean"), s.get("stdev")
    return (rep.get("per_class", {}).get(cname) or {}).get(metric), None


def _fmt(v, sd=None) -> str:
    if v is None:
        return "   -  "
    return f"{v:.3f}" + (f"±{sd:.3f}" if sd is not None else "      ")


def _verdict(a, sa, b, sb) -> str:
    """Is the difference bigger than the noise?"""
    if a is None or b is None:
        return ""
    d = b - a
    if sa is None and sb is None:
        return f"{d:+.3f}"
    thr = 2 * max(sa or 0, sb or 0)
    tag = "REAL" if abs(d) > thr else "noise"
    return f"{d:+.3f} ({tag})"


def compare(reports: list[tuple[str, dict]], csv_path: str | None = None) -> None:
    labels = [lab for lab, _ in reports]
    w = 15

    print("\n" + "=" * (26 + w * len(labels) + 18))
    print(" MODEL ABLATION — extraction regression benchmark")
    for lab, rep in reports:
        cfg = rep.get("config", {})
        rs = rep.get("repeat_stats")
        runs = rs.get("n_runs") if rs else 1
        print(f"   {lab:<12} model={cfg.get('model', '?'):<22} docs={cfg.get('n_docs', '?')}  runs={runs}")
    print("=" * (26 + w * len(labels) + 18))

    rows: list[list] = []

    print(f"\n{'OVERALL':<12}" + "".join(f"{l:>{w}}" for l in labels) +
          ("       delta" if len(labels) == 2 else ""))
    print("-" * (12 + w * len(labels) + 18))
    for m in METRICS:
        vals = [_overall(rep, m) for _, rep in reports]
        line = f"{m:<12}" + "".join(f"{_fmt(v, sd):>{w}}" for v, sd in vals)
        if len(labels) == 2:
            line += "   " + _verdict(*vals[0], *vals[1])
        print(line)
        rows.append(["overall", m] + [f"{v:.4f}" if v is not None else "" for v, _ in vals])

    for m in METRICS:
        print(f"\n{'per-class ' + m:<12}" + "".join(f"{l:>{w}}" for l in labels) +
              ("       delta" if len(labels) == 2 else ""))
        print("-" * (12 + w * len(labels) + 18))
        for cname in SCORED_CLASSES:
            vals = [_per_class(rep, cname, m) for _, rep in reports]
            if all(v is None for v, _ in vals):
                continue
            line = f"{cname:<12}" + "".join(f"{_fmt(v, sd):>{w}}" for v, sd in vals)
            if len(labels) == 2:
                line += "   " + _verdict(*vals[0], *vals[1])
            print(line)
            rows.append([f"class:{cname}", m] + [f"{v:.4f}" if v is not None else "" for v, _ in vals])

    # Per-document F1 (last run of each report)
    all_docs = sorted({d for _, rep in reports for d in rep.get("per_doc", {})})
    print(f"\n{'per-doc F1':<42}" + "".join(f"{l:>{w}}" for l in labels))
    print("-" * (42 + w * len(labels)))
    for doc in all_docs:
        vals = []
        for _, rep in reports:
            m = (rep.get("per_doc", {}).get(doc) or {}).get("metrics") or {}
            vals.append(m.get("f1"))
        print(f"{doc:<42}" + "".join(f"{_fmt(v):>{w}}" for v in vals))
        rows.append([f"doc:{doc}", "f1"] + [f"{v:.4f}" if v is not None else "" for v in vals])

    # Pipeline errors are a first-class ablation result for small models
    print(f"\n{'pipeline errors':<42}" + "".join(f"{l:>{w}}" for l in labels))
    print("-" * (42 + w * len(labels)))
    counts = []
    for _, rep in reports:
        n = sum(len((d.get("meta") or {}).get("pipeline_errors") or [])
                for d in rep.get("per_doc", {}).values())
        counts.append(n)
    print(f"{'docs with extraction errors':<42}" + "".join(f"{c:>{w}}" for c in counts))
    rows.append(["pipeline", "errors"] + [str(c) for c in counts])
    print("=" * (42 + w * len(labels)) + "\n")

    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            wtr = csv.writer(f)
            wtr.writerow(["scope", "metric"] + labels)
            wtr.writerows(rows)
        print(f"csv written to {csv_path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare benchmark reports (model ablation).")
    ap.add_argument("reports", nargs="+", help="label=path.json or path.json")
    ap.add_argument("--csv", help="also write a flat CSV")
    args = ap.parse_args()
    compare([_load(s) for s in args.reports], args.csv)


if __name__ == "__main__":
    main()
