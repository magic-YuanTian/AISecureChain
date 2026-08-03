"""
Performance benchmark for the extraction pipeline.

Measures per-stage latency on the URLs in ``urls.yaml`` so you can track
end-to-end performance regressions over time.

Stages timed:
    1. crawl       — URL → Markdown (crawl4ai)
    2. chunk       — Markdown → chunks
    3. extract     — all chunks → graphs (parallel LLM calls)
    4. merge       — graphs → canonical entities/relations
    5. persist     — DB upsert + same_as detection

Usage::

    python -m extract_eval.benchmark
    python -m extract_eval.benchmark --max-urls 5 --concurrency 4 --runs 2
    python -m extract_eval.benchmark --out bench.json

Reports: per-URL timings + aggregate (mean, p50, p95, max) + throughput.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import yaml  # type: ignore

_THIS = Path(__file__).resolve()
sys.path.insert(0, str(_THIS.parent.parent))

from extract_pipeline.chunker import chunk_markdown
from extract_pipeline.llm import build_system_prompt, extract_graph
from extract_pipeline.merger import merge_graphs
from extract_pipeline.persist import persist_canonical
from extract_pipeline.pipeline import crawl_url_to_markdown


DEFAULT_URLS = _THIS.parent / "urls.yaml"


async def _time_one(url: str, persist_db: str | None) -> dict[str, Any]:
    timings: dict[str, float] = {}
    counts: dict[str, int] = {}

    t0 = time.perf_counter()
    md, err = await crawl_url_to_markdown(url)
    timings["crawl"] = time.perf_counter() - t0
    if err:
        return {"url": url, "error": err, "timings": timings}
    counts["markdown_chars"] = len(md)

    t0 = time.perf_counter()
    chunks = chunk_markdown(md)
    timings["chunk"] = time.perf_counter() - t0
    counts["chunks"] = len(chunks)

    sys_prompt = build_system_prompt()

    t0 = time.perf_counter()
    graphs_outs = await asyncio.gather(
        *[extract_graph(c, system_prompt=sys_prompt) for c in chunks[:12]],
        return_exceptions=True,
    )
    timings["extract"] = time.perf_counter() - t0
    graphs = []
    for out in graphs_outs:
        if isinstance(out, Exception):
            continue
        g, _ = out
        if g.entities or g.relations:
            graphs.append(g)

    t0 = time.perf_counter()
    ents, rels = merge_graphs(graphs)
    timings["merge"] = time.perf_counter() - t0
    counts["entities"] = len(ents)
    counts["relations"] = len(rels)

    timings["persist"] = 0.0
    if persist_db and ents:
        t0 = time.perf_counter()
        persist_canonical(ents, rels, source_url=url, db_path=persist_db)
        timings["persist"] = time.perf_counter() - t0

    timings["total"] = sum(timings.values())
    return {"url": url, "timings": timings, "counts": counts}


def _pctl(xs: list[float], p: float) -> float | None:
    if not xs:
        return None
    xs_sorted = sorted(xs)
    k = max(0, min(len(xs_sorted) - 1, int(round((p / 100.0) * (len(xs_sorted) - 1)))))
    return xs_sorted[k]


def aggregate(runs: list[dict[str, Any]]) -> dict[str, Any]:
    stages = ["crawl", "chunk", "extract", "merge", "persist", "total"]
    ok_runs = [r for r in runs if "error" not in r]
    agg: dict[str, Any] = {
        "urls_total": len(runs),
        "urls_ok": len(ok_runs),
        "urls_failed": len(runs) - len(ok_runs),
    }
    for s in stages:
        xs = [r["timings"].get(s, 0.0) for r in ok_runs]
        if xs:
            agg[s] = {
                "mean": round(statistics.mean(xs), 3),
                "median": round(statistics.median(xs), 3),
                "p95": round(_pctl(xs, 95) or 0.0, 3),
                "max": round(max(xs), 3),
            }
    if ok_runs:
        total_time = sum(r["timings"]["total"] for r in ok_runs)
        agg["throughput_urls_per_minute"] = round(60.0 * len(ok_runs) / total_time, 2) if total_time else None
    return agg


# ── Reporting ──────────────────────────────────────────────────────────────

def print_table(runs: list[dict[str, Any]], agg: dict[str, Any]) -> None:
    print("=" * 104)
    print(f"{'URL':56}  {'crawl':>7} {'chunk':>6} {'extract':>7} {'merge':>6} {'pers':>6} {'total':>7} {'ents':>5}")
    print("-" * 104)
    for r in runs:
        url = r["url"]
        if len(url) > 54:
            url = url[:51] + "..."
        if "error" in r:
            print(f"{url:56}  ERROR: {r['error']}")
            continue
        t = r["timings"]
        c = r.get("counts", {})
        print(
            f"{url:56}  "
            f"{t['crawl']:>7.2f} "
            f"{t['chunk']:>6.3f} "
            f"{t['extract']:>7.2f} "
            f"{t['merge']:>6.3f} "
            f"{t['persist']:>6.3f} "
            f"{t['total']:>7.2f} "
            f"{c.get('entities', 0):>5}"
        )
    print("-" * 104)
    print("AGGREGATE (per stage, seconds):")
    stages = [k for k in ["crawl", "chunk", "extract", "merge", "persist", "total"] if k in agg]
    hdr = f"{'':12}" + " ".join(f"{s:>9}" for s in stages)
    print(hdr)
    for m in ("mean", "median", "p95", "max"):
        row = f"  {m:10}" + " ".join(f"{agg[s][m]:>9.2f}" for s in stages if m in agg[s])
        print(row)
    print(f"\nurls_ok: {agg.get('urls_ok')}/{agg.get('urls_total')}   "
          f"throughput: {agg.get('throughput_urls_per_minute')} urls/min")
    print("=" * 104)


# ── Main ──────────────────────────────────────────────────────────────────

async def _run_all(entries: list[dict[str, Any]], concurrency: int, persist_db: str | None) -> list[dict[str, Any]]:
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(url: str) -> dict[str, Any]:
        async with sem:
            try:
                return await _time_one(url, persist_db)
            except Exception as e:  # noqa: BLE001
                return {"url": url, "error": f"crashed: {e}", "timings": {}}

    return await asyncio.gather(*[_bounded(e["url"]) for e in entries])


def main() -> None:
    ap = argparse.ArgumentParser(description="Benchmark the extraction pipeline.")
    ap.add_argument("--urls", default=str(DEFAULT_URLS))
    ap.add_argument("--out", default=None)
    ap.add_argument("--max-urls", type=int, default=None)
    ap.add_argument("--concurrency", type=int, default=2)
    ap.add_argument("--runs", type=int, default=1, help="Run the whole suite N times and average")
    ap.add_argument("--persist-db", default=None, help="Path to a temp DB for persist timing (optional)")
    ap.add_argument("--only", nargs="*", default=None)
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
        print("No URLs.")
        return

    all_runs: list[list[dict[str, Any]]] = []
    for i in range(args.runs):
        if args.runs > 1:
            print(f"\n━━ run {i + 1}/{args.runs} ━━")
        runs = asyncio.run(_run_all(entries, args.concurrency, args.persist_db))
        all_runs.append(runs)

    flat = [r for runset in all_runs for r in runset]
    agg = aggregate(flat)
    print_table(flat, agg)

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"runs": flat, "aggregate": agg}, f, indent=2, default=str)
        print(f"\nDetailed output: {args.out}")


if __name__ == "__main__":
    main()
