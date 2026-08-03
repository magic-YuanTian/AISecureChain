"""
Export a benchmark report to flat CSV files (for spreadsheets / diffing / pandas).

CSV is one table per file, so this writes a small set into an output directory:
  results_summary.csv  — overall + per-class + per-doc precision/recall/F1
  ground_truth.csv     — every oracle label (required/acceptable) + link + matched?
  predictions.csv      — every predicted entity + verdict (TP/acceptable/FP) + link

Usage:
  cd query_engine
  python -m extract_eval.regression.export_csv report.json csv_out/
  # or produced automatically by:  evaluate_regression ... --csv csv_out/
"""
from __future__ import annotations

import csv
import json
import os
import sys

from extract_eval.regression.scorer import SCORED_CLASSES


def _round(x):
    return "" if x is None else round(x, 4)


def write_results_summary(report: dict, path: str) -> None:
    cfg = report.get("config", {})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["scope", "name", "precision", "recall", "f1", "tp", "fp", "fn",
                    "model", "source", "generated_at"])
        o = report["overall"]
        w.writerow(["overall", "OVERALL (headline)", _round(o["precision"]), _round(o["recall"]),
                    _round(o["f1"]), o["tp"], o["fp"], o["fn"],
                    cfg.get("model"), cfg.get("source"), cfg.get("generated_at")])
        for c, m in report["per_class"].items():
            w.writerow(["class", c, _round(m["precision"]), _round(m["recall"]), _round(m["f1"]),
                        m["tp"], m["fp"], m["fn"], "", "", ""])
        for doc_id, d in report["per_doc"].items():
            m = d.get("metrics") or {}
            w.writerow(["document", doc_id, _round(m.get("precision")), _round(m.get("recall")),
                        _round(m.get("f1")), m.get("tp"), m.get("fp"), m.get("fn"), "", "", ""])


def write_ground_truth(report: dict, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["doc_id", "url", "class", "kind", "gold_label", "aliases", "matched"])
        for doc_id, d in report["per_doc"].items():
            meta = d.get("meta", {})
            url = meta.get("url", "")
            details = meta.get("details") or {}
            for c in SCORED_CLASSES:
                for item in details.get(c, {}).get("gold", []):
                    w.writerow([doc_id, url, c, item["kind"], item["label"],
                                "; ".join(item.get("aliases", [])),
                                "yes" if item["matched"] else "no"])


def write_predictions(report: dict, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["doc_id", "url", "class", "predicted_value", "verdict", "attributes"])
        for doc_id, d in report["per_doc"].items():
            meta = d.get("meta", {})
            url = meta.get("url", "")
            details = meta.get("details") or {}
            for c in SCORED_CLASSES:
                for item in details.get(c, {}).get("predicted", []):
                    w.writerow([doc_id, url, c, item["value"], item["verdict"],
                                json.dumps(item.get("attrs", {}), ensure_ascii=False)])


def export_all(report: dict, out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, fn in (("results_summary.csv", write_results_summary),
                     ("ground_truth.csv", write_ground_truth),
                     ("predictions.csv", write_predictions)):
        p = os.path.join(out_dir, name)
        fn(report, p)
        written.append(p)
    return written


def main() -> None:
    if len(sys.argv) < 3:
        print("usage: python -m extract_eval.regression.export_csv <report.json> <out_dir>")
        raise SystemExit(2)
    with open(sys.argv[1], encoding="utf-8") as f:
        report = json.load(f)
    for p in export_all(report, sys.argv[2]):
        print("wrote", p)


if __name__ == "__main__":
    main()
