"""
Export a benchmark report to an Excel workbook for manual testing/inspection.

The workbook has five sheets:
  - Summary        : run config + overall and per-class precision/recall/F1
  - Per-Document   : one row per page (clickable link, metrics, entity/relation counts, errors)
  - Ground Truth   : every oracle label (required/acceptable) per doc×class, with the
                     page link and whether the pipeline matched it
  - Predicted      : every entity the pipeline produced per doc×class, with verdict
                     (TP / acceptable / FP) and the page link
  - Gold Reference : the full gold.yaml labels per doc×class as text (for editing)

Usage:
  # produced automatically by:  evaluate_regression ... --xlsx results.xlsx
  # or stand-alone from a saved JSON report:
  cd query_engine
  python -m extract_eval.regression.export_excel report.json results.xlsx
"""
from __future__ import annotations

import json
import os
import sys

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from extract_eval.regression.scorer import SCORED_CLASSES, INFORMATIONAL_CLASSES

HEADER_FILL = PatternFill("solid", fgColor="1F4E78")
HEADER_FONT = Font(bold=True, color="FFFFFF")
TITLE_FONT = Font(bold=True, size=13)
WRAP = Alignment(vertical="top", wrap_text=True)
TOP = Alignment(vertical="top")
LINK_FONT = Font(color="0563C1", underline="single")
VERDICT_FILL = {
    "TP": PatternFill("solid", fgColor="C6EFCE"),
    "acceptable": PatternFill("solid", fgColor="FFEB9C"),
    "FP": PatternFill("solid", fgColor="FFC7CE"),
    True: PatternFill("solid", fgColor="C6EFCE"),
    False: PatternFill("solid", fgColor="FFC7CE"),
}


def _pct(x):
    return "" if x is None else round(x, 3)


def _header(ws, row, headers):
    for j, h in enumerate(headers, 1):
        c = ws.cell(row=row, column=j, value=h)
        c.fill = HEADER_FILL
        c.font = HEADER_FONT
        c.alignment = WRAP
    ws.freeze_panes = ws.cell(row=row + 1, column=1)


def _widths(ws, widths):
    for j, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(j)].width = w


def _link(cell, url):
    if url:
        cell.value = url
        cell.hyperlink = url
        cell.font = LINK_FONT


def _sheet_summary(wb, report):
    ws = wb.active
    ws.title = "Summary"
    cfg = report["config"]
    ws["A1"] = "AISecureChain — Extraction Regression Benchmark"
    ws["A1"].font = TITLE_FONT
    meta_rows = [
        ("Generated", cfg.get("generated_at", "")),
        ("Base LLM (model)", cfg.get("model", "")),
        ("Source", cfg.get("source", "")),
        ("Documents", cfg.get("n_docs", "")),
        ("Note", "Headline excludes VulnerabilityType (validator/CWE-mapper driven, informational)."),
    ]
    r = 3
    for k, v in meta_rows:
        ws.cell(row=r, column=1, value=k).font = Font(bold=True)
        ws.cell(row=r, column=2, value=v)
        r += 1

    r += 1
    ws.cell(row=r, column=1, value="Metrics (micro-averaged)").font = TITLE_FONT
    r += 1
    _header(ws, r, ["Class", "Precision", "Recall", "F1", "TP", "FP", "FN", "Note"])
    ws.freeze_panes = None
    r += 1
    for c in SCORED_CLASSES:
        m = report["per_class"][c]
        note = "informational — excluded from OVERALL" if c in INFORMATIONAL_CLASSES else ""
        for j, v in enumerate([c, _pct(m["precision"]), _pct(m["recall"]), _pct(m["f1"]),
                               m["tp"], m["fp"], m["fn"], note], 1):
            ws.cell(row=r, column=j, value=v)
        r += 1
    o = report["overall"]
    for j, v in enumerate(["OVERALL (micro)", _pct(o["precision"]), _pct(o["recall"]), _pct(o["f1"]),
                           o["tp"], o["fp"], o["fn"], "headline classes only"], 1):
        cell = ws.cell(row=r, column=j, value=v)
        cell.font = Font(bold=True)
    _widths(ws, [22, 11, 11, 9, 7, 7, 7, 48])
    ws.column_dimensions["H"].width = 48


def _sheet_per_doc(wb, report):
    ws = wb.create_sheet("Per-Document")
    headers = ["Doc ID", "Category", "Title", "Source", "Link", "Chars",
               "Precision", "Recall", "F1", "TP", "FP", "FN",
               "Entity counts", "Relation counts", "Pipeline errors"]
    _header(ws, 1, headers)
    r = 2
    for doc_id, d in report["per_doc"].items():
        meta = d.get("meta", {})
        m = d.get("metrics") or {}
        ws.cell(row=r, column=1, value=doc_id)
        ws.cell(row=r, column=2, value=meta.get("category", ""))
        ws.cell(row=r, column=3, value=meta.get("title", "")).alignment = WRAP
        ws.cell(row=r, column=4, value=meta.get("source_name", ""))
        _link(ws.cell(row=r, column=5), meta.get("url", ""))
        ws.cell(row=r, column=6, value=meta.get("char_len"))
        ws.cell(row=r, column=7, value=_pct(m.get("precision")))
        ws.cell(row=r, column=8, value=_pct(m.get("recall")))
        ws.cell(row=r, column=9, value=_pct(m.get("f1")))
        ws.cell(row=r, column=10, value=m.get("tp"))
        ws.cell(row=r, column=11, value=m.get("fp"))
        ws.cell(row=r, column=12, value=m.get("fn"))
        ws.cell(row=r, column=13, value=json.dumps(meta.get("entity_counts", {}))).alignment = WRAP
        ws.cell(row=r, column=14, value=json.dumps(meta.get("relation_counts", {}))).alignment = WRAP
        ws.cell(row=r, column=15, value="; ".join(meta.get("pipeline_errors", []) or [])).alignment = WRAP
        r += 1
    _widths(ws, [40, 22, 44, 18, 50, 7, 10, 9, 8, 6, 6, 6, 26, 22, 30])


def _sheet_ground_truth(wb, report):
    ws = wb.create_sheet("Ground Truth")
    _header(ws, 1, ["Doc ID", "Link", "Class", "Type", "Gold label", "Aliases", "Matched?"])
    r = 2
    for doc_id, d in report["per_doc"].items():
        meta = d.get("meta", {})
        details = (meta.get("details") or {})
        url = meta.get("url", "")
        for c in SCORED_CLASSES:
            for item in details.get(c, {}).get("gold", []):
                ws.cell(row=r, column=1, value=doc_id)
                _link(ws.cell(row=r, column=2), url)
                ws.cell(row=r, column=3, value=c)
                ws.cell(row=r, column=4, value=item["kind"])
                ws.cell(row=r, column=5, value=item["label"]).alignment = TOP
                ws.cell(row=r, column=6, value=", ".join(item.get("aliases", []))).alignment = WRAP
                mc = ws.cell(row=r, column=7, value="yes" if item["matched"] else "no")
                # only 'required' misses are red; acceptable misses are neutral
                if item["kind"] == "required":
                    mc.fill = VERDICT_FILL[bool(item["matched"])]
                r += 1
    _widths(ws, [40, 50, 18, 12, 40, 40, 10])


def _sheet_predicted(wb, report):
    ws = wb.create_sheet("Predicted")
    _header(ws, 1, ["Doc ID", "Link", "Class", "Predicted value", "Verdict", "Attributes"])
    r = 2
    for doc_id, d in report["per_doc"].items():
        meta = d.get("meta", {})
        details = (meta.get("details") or {})
        url = meta.get("url", "")
        for c in SCORED_CLASSES:
            for item in details.get(c, {}).get("predicted", []):
                ws.cell(row=r, column=1, value=doc_id)
                _link(ws.cell(row=r, column=2), url)
                ws.cell(row=r, column=3, value=c)
                ws.cell(row=r, column=4, value=item["value"]).alignment = TOP
                vc = ws.cell(row=r, column=5, value=item["verdict"])
                vc.fill = VERDICT_FILL.get(item["verdict"])
                ws.cell(row=r, column=6, value=json.dumps(item.get("attrs", {}), ensure_ascii=False)).alignment = WRAP
                r += 1
    _widths(ws, [40, 50, 18, 38, 12, 60])


def build_workbook(report: dict, path: str) -> str:
    wb = Workbook()
    _sheet_summary(wb, report)
    _sheet_per_doc(wb, report)
    _sheet_ground_truth(wb, report)
    _sheet_predicted(wb, report)
    wb.save(path)
    return path


def main() -> None:
    if len(sys.argv) < 3:
        print("usage: python -m extract_eval.regression.export_excel <report.json> <out.xlsx>")
        raise SystemExit(2)
    report_path, out_path = sys.argv[1], sys.argv[2]
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)
    build_workbook(report, out_path)
    print(f"excel written to {out_path}")


if __name__ == "__main__":
    main()
