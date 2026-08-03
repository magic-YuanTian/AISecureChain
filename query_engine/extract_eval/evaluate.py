"""
Evaluation harness for the AISecureChain extraction pipeline.

Loads ``urls.yaml``, runs ``run_pipeline`` for each entry (with DB writes
disabled), and reports per-URL + aggregate metrics.

Metrics
-------
Per URL:
    * ``status``          : pass | fail | partial
    * ``expected_found``  : count of expected_ids that appeared
    * ``recall``          : found / expected  (only if vulnerability_ids given)
    * ``unexpected``      : IDs found that were not in expected / forbidden
    * ``forbidden_hits``  : forbidden IDs that leaked in (should be 0)
    * ``entity_counts``   : per-class count from the pipeline
    * ``partial_rate``    : 0-1
    * ``coverage``        : fraction of required attrs filled on non-partial entities
    * ``failed_checks``   : list of human-readable failure reasons
    * ``duration_s``      : wall-clock seconds

Aggregate:
    * macro/micro recall over vulnerability_ids
    * mean partial_rate
    * mean coverage
    * pass-rate (fraction of URLs whose checks all passed)

Usage
-----
    python -m extract_eval.evaluate
    python -m extract_eval.evaluate --urls extract_eval/urls.yaml \\
        --out report.json --max-urls 5
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

# Make sibling packages importable when run as a script
_THIS = Path(__file__).resolve()
sys.path.insert(0, str(_THIS.parent.parent))

import yaml  # type: ignore

from extract_pipeline import run_pipeline, PipelineResult
from extract_pipeline.ontology import required_attributes


DEFAULT_URLS = _THIS.parent / "urls.yaml"


# ── Metrics helpers ───────────────────────────────────────────────────────

def _norm_id(s: str) -> str:
    return (s or "").strip().upper().replace(" ", "")


def _vuln_ids(result: PipelineResult) -> set[str]:
    out: set[str] = set()
    for e in result.entities_of_class("Vulnerability"):
        vid = e.attributes.get("vuln_id")
        if vid:
            out.add(_norm_id(vid))
    return out


def _coverage(result: PipelineResult) -> float:
    """Average fraction of required attrs filled on non-partial entities."""
    total = 0
    filled = 0
    for e in result.canonical_entities:
        reqs = required_attributes(e.class_name)
        if not reqs:
            continue
        for a in reqs:
            total += 1
            v = e.attributes.get(a)
            if v not in (None, "", []):
                filled += 1
    return filled / total if total else 1.0


# ── Per-URL evaluation ─────────────────────────────────────────────────────

async def evaluate_one(entry: dict[str, Any]) -> dict[str, Any]:
    url = entry["url"]
    expected = entry.get("expected") or {}
    failed: list[str] = []

    t0 = time.time()
    try:
        result = await run_pipeline(url, skip_db=True)
    except Exception as e:  # noqa: BLE001
        return {
            "url": url,
            "status": "fail",
            "failed_checks": [f"pipeline crashed: {e}"],
            "duration_s": round(time.time() - t0, 2),
        }
    dur = round(time.time() - t0, 2)

    found_ids = _vuln_ids(result)
    expected_ids = {_norm_id(v) for v in expected.get("vulnerability_ids", [])}
    forbidden_ids = {_norm_id(v) for v in expected.get("forbidden_ids", [])}

    # Recall / precision checks
    missing = sorted(expected_ids - found_ids)
    unexpected = sorted(found_ids - expected_ids - forbidden_ids) if expected_ids else []
    forbidden_hits = sorted(found_ids & forbidden_ids)

    if expected_ids:
        if missing:
            failed.append(f"missing vulnerability_ids: {missing}")
    if forbidden_hits:
        failed.append(f"forbidden ids present: {forbidden_hits}")

    counts = result.entity_counts_by_class()
    for cname in expected.get("must_have_classes", []):
        if counts.get(cname, 0) < 1:
            failed.append(f"missing class: {cname}")

    for key, cls in (
        ("min_vulnerabilities", "Vulnerability"),
        ("min_vendors", "Vendor"),
        ("min_software", "Software"),
        ("min_versions", "Version"),
        ("min_vulnerability_types", "VulnerabilityType"),
    ):
        if key in expected:
            need = int(expected[key])
            got = counts.get(cls, 0)
            if got < need:
                failed.append(f"{key}: got {got} < {need}")

    partial_rate = result.partial_rate()
    if "max_partial_rate" in expected:
        if partial_rate > float(expected["max_partial_rate"]):
            failed.append(
                f"partial_rate {partial_rate:.2f} > max {expected['max_partial_rate']}"
            )

    coverage = _coverage(result)

    recall = None
    if expected_ids:
        recall = len(expected_ids & found_ids) / len(expected_ids)

    status = "pass" if not failed and not result.errors else ("partial" if result.canonical_entities else "fail")

    return {
        "url": url,
        "category": entry.get("category"),
        "status": status,
        "expected_ids": sorted(expected_ids),
        "found_ids": sorted(found_ids),
        "unexpected": unexpected,
        "forbidden_hits": forbidden_hits,
        "recall": recall,
        "entity_counts": counts,
        "partial_rate": round(partial_rate, 3),
        "coverage": round(coverage, 3),
        "chunks_total": result.chunks_total,
        "chunks_extracted": result.chunks_extracted,
        "errors": result.errors,
        "warnings": result.warnings,
        "failed_checks": failed,
        "duration_s": dur,
    }


# ── Aggregate ─────────────────────────────────────────────────────────────

def aggregate(reports: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(reports)
    pass_n = sum(1 for r in reports if r["status"] == "pass")
    any_entities_n = sum(1 for r in reports if r.get("entity_counts"))

    # Micro / macro recall on vulnerability_ids
    micro_num = micro_den = 0
    macro_recalls: list[float] = []
    for r in reports:
        exp = set(r.get("expected_ids") or [])
        found = set(r.get("found_ids") or [])
        if exp:
            hit = len(exp & found)
            micro_num += hit
            micro_den += len(exp)
            macro_recalls.append(hit / len(exp))

    partial_rates = [r["partial_rate"] for r in reports if r.get("partial_rate") is not None]
    coverages = [r["coverage"] for r in reports if r.get("coverage") is not None]

    def _mean(xs: list[float]) -> float | None:
        return round(sum(xs) / len(xs), 3) if xs else None

    return {
        "urls_total": n,
        "urls_passed": pass_n,
        "urls_with_extractions": any_entities_n,
        "pass_rate": round(pass_n / n, 3) if n else 0.0,
        "vuln_micro_recall": round(micro_num / micro_den, 3) if micro_den else None,
        "vuln_macro_recall": _mean(macro_recalls),
        "mean_partial_rate": _mean(partial_rates),
        "mean_coverage": _mean(coverages),
    }


# ── Reporting ─────────────────────────────────────────────────────────────

_STATUS_ICON = {"pass": "[OK]  ", "partial": "[PART]", "fail": "[FAIL]"}


def print_report(reports: list[dict[str, Any]], agg: dict[str, Any]) -> None:
    print("=" * 88)
    print(f"{'STATUS':6}  {'URL':62}  {'RECALL':>7}  {'PR':>5}  {'COV':>5}")
    print("-" * 88)
    for r in reports:
        url = r["url"]
        if len(url) > 60:
            url = url[:57] + "..."
        recall = f"{r['recall']:.2f}" if r.get("recall") is not None else "   -"
        pr_ = f"{r['partial_rate']:.2f}" if r.get("partial_rate") is not None else "   -"
        cov = f"{r['coverage']:.2f}" if r.get("coverage") is not None else "   -"
        print(f"{_STATUS_ICON.get(r['status'], '?'):6}  {url:62}  {recall:>7}  {pr_:>5}  {cov:>5}")
        for fc in r.get("failed_checks", []):
            print(f"         ! {fc}")
        if r.get("errors"):
            for err in r["errors"]:
                print(f"         x {err}")
    print("-" * 88)
    print("AGGREGATE:")
    for k, v in agg.items():
        print(f"  {k:22s} = {v}")
    print("=" * 88)


# ── Entry point ───────────────────────────────────────────────────────────

async def _run_all(entries: list[dict[str, Any]], concurrency: int) -> list[dict[str, Any]]:
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(e: dict[str, Any]) -> dict[str, Any]:
        async with sem:
            return await evaluate_one(e)

    return await asyncio.gather(*[_bounded(e) for e in entries])


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate the AISecureChain extraction pipeline.")
    ap.add_argument("--urls", default=str(DEFAULT_URLS), help="Path to urls.yaml")
    ap.add_argument("--out", default=None, help="Optional JSON report output path")
    ap.add_argument("--max-urls", type=int, default=None, help="Limit number of URLs")
    ap.add_argument("--concurrency", type=int, default=2, help="Parallel URL evaluations")
    ap.add_argument("--only", nargs="*", default=None,
                    help="Only evaluate URLs that substring-match any of these")
    args = ap.parse_args()

    with open(args.urls) as f:
        cfg = yaml.safe_load(f) or {}
    entries = cfg.get("urls", [])

    if args.only:
        needles = [n.lower() for n in args.only]
        entries = [e for e in entries if any(n in e["url"].lower() for n in needles)]

    if args.max_urls:
        entries = entries[: args.max_urls]

    if not entries:
        print("No URLs to evaluate.")
        return

    print(f"Evaluating {len(entries)} URL(s) with concurrency={args.concurrency} ...")
    reports = asyncio.run(_run_all(entries, args.concurrency))
    agg = aggregate(reports)

    print_report(reports, agg)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"reports": reports, "aggregate": agg}, f, indent=2, default=str)
        print(f"\nFull report: {args.out}")


if __name__ == "__main__":
    main()
