"""
Freshness checks: detect whether a remote URL's content has changed since
we last ingested it, without running the heavy crawl + LLM pipeline.

Strategy (cheap → expensive):

    1. HEAD request:
         * If ETag matches stored → FRESH
         * If Last-Modified matches stored → FRESH
    2. GET + SHA-1 of response body:
         * Hash matches stored content_hash → FRESH
         * Otherwise → STALE

A URL that has never been ingested starts in state ``never`` and moves
straight to ``stale`` the moment it's added to the registry (so the UI
shows "needs ingestion" rather than "unknown").

Requests are issued with a realistic user-agent, a short timeout, and
``allow_redirects=True`` so single-page CVE detail pages work.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterable

try:
    import requests  # depends on extract_pipeline which already pulls it
except ImportError as e:  # pragma: no cover
    raise RuntimeError(
        "The `requests` package is required for freshness checks."
    ) from e

USER_AGENT = "AISecureChain/1.0 (+https://aisecurechain.org)"
HEAD_TIMEOUT = 10
GET_TIMEOUT = 20


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _sha1(b: bytes | str) -> str:
    if isinstance(b, str):
        b = b.encode("utf-8", errors="replace")
    return hashlib.sha1(b).hexdigest()


def _http_head(url: str) -> dict[str, Any]:
    try:
        r = requests.head(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            allow_redirects=True,
            timeout=HEAD_TIMEOUT,
        )
        return {
            "ok": r.status_code < 400,
            "status": r.status_code,
            "etag": r.headers.get("ETag"),
            "last_modified": r.headers.get("Last-Modified"),
            "content_length": r.headers.get("Content-Length"),
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "status": None, "error": str(e)}


def _http_get_body(url: str) -> tuple[bytes | None, dict[str, Any]]:
    try:
        r = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*"},
            allow_redirects=True,
            timeout=GET_TIMEOUT,
        )
        meta = {
            "ok": r.status_code < 400,
            "status": r.status_code,
            "etag": r.headers.get("ETag"),
            "last_modified": r.headers.get("Last-Modified"),
        }
        return (r.content if r.status_code < 400 else None), meta
    except Exception as e:  # noqa: BLE001
        return None, {"ok": False, "status": None, "error": str(e)}


def check_one(
    conn: sqlite3.Connection,
    url_row: dict[str, Any],
    *,
    deep: bool = True,
) -> dict[str, Any]:
    """Check freshness of a single source_url row; update the DB; return the new row dict.

    ``deep=True`` allows falling back to a full GET+SHA-1 when the server
    doesn't return ETag/Last-Modified (many CDNs strip them).
    """
    url = url_row["url"]
    uid = url_row["id"]
    now = _now_iso()

    head = _http_head(url)
    new_status = url_row.get("status") or "never"
    new_etag = url_row.get("etag")
    new_lm = url_row.get("last_modified")
    new_error: str | None = None

    if not head.get("ok"):
        # HEAD may be blocked; only mark error if GET also fails (see below)
        if not deep:
            new_status = "error"
            new_error = head.get("error") or f"HTTP {head.get('status')}"
        # else: fall through to GET
    else:
        remote_etag = head.get("etag")
        remote_lm = head.get("last_modified")
        if (remote_etag and remote_etag == url_row.get("etag")) or (
            remote_lm and remote_lm == url_row.get("last_modified")
        ):
            new_status = "fresh"
            new_etag = remote_etag or new_etag
            new_lm = remote_lm or new_lm
        else:
            # Only promote to stale if we *had* something stored; if never
            # ingested yet, keep 'never' so the UI still shows it as new.
            if url_row.get("last_ingested"):
                new_status = "stale"
            else:
                new_status = "never"
            new_etag = remote_etag or new_etag
            new_lm = remote_lm or new_lm

    if deep and new_status in ("error", "never") or (
        deep and new_status == "stale" and not url_row.get("content_hash")
    ):
        body, meta = _http_get_body(url)
        if body is None:
            new_status = "error"
            new_error = meta.get("error") or f"HTTP {meta.get('status')}"
        else:
            remote_hash = _sha1(body)
            stored = url_row.get("content_hash")
            if stored and stored == remote_hash:
                new_status = "fresh"
            elif url_row.get("last_ingested"):
                new_status = "stale"
            else:
                new_status = "never"
            new_etag = meta.get("etag") or new_etag
            new_lm = meta.get("last_modified") or new_lm
            new_error = None

    cur = conn.cursor()
    cur.execute(
        """UPDATE source_url
           SET last_checked=?, etag=?, last_modified=?, status=?, error=?
           WHERE id=?""",
        (now, new_etag, new_lm, new_status, new_error, uid),
    )
    conn.commit()
    row = cur.execute("SELECT * FROM source_url WHERE id=?", (uid,)).fetchone()
    return dict(row)


def check_many(
    conn: sqlite3.Connection,
    url_rows: Iterable[dict[str, Any]],
    *,
    max_workers: int = 6,
    deep: bool = True,
) -> list[dict[str, Any]]:
    """Run ``check_one`` against many rows in parallel (I/O bound)."""
    rows = list(url_rows)
    if not rows:
        return []
    # We serialise DB writes (SQLite + Flask-threaded) by taking the
    # connection's cursor inside each update. That's fine because
    # sqlite3 connections in shared-across-thread mode aren't safe, so
    # we copy rows first, fetch network in parallel, then apply updates.
    def _fetch(row: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        return row, _remote_probe(row["url"], deep=deep)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        probed = list(ex.map(_fetch, rows))

    results: list[dict[str, Any]] = []
    cur = conn.cursor()
    now = _now_iso()
    for row, probe in probed:
        status, etag, lm, err = _decide(row, probe)
        cur.execute(
            """UPDATE source_url
               SET last_checked=?, etag=?, last_modified=?, status=?, error=?
               WHERE id=?""",
            (now, etag, lm, status, err, row["id"]),
        )
        updated = cur.execute(
            "SELECT * FROM source_url WHERE id=?", (row["id"],)
        ).fetchone()
        results.append(dict(updated))
    conn.commit()
    return results


# ── helpers for the parallel path ────────────────────────────────────────

def _remote_probe(url: str, *, deep: bool) -> dict[str, Any]:
    head = _http_head(url)
    if not deep and not head.get("ok"):
        return {"kind": "error", **head}
    # If HEAD worked and returned validators, that's enough to decide.
    if head.get("ok") and (head.get("etag") or head.get("last_modified")):
        return {"kind": "head", **head}
    # Else GET.
    body, meta = _http_get_body(url)
    if body is None:
        return {"kind": "error", **meta}
    return {
        "kind": "hash",
        "content_hash": _sha1(body),
        "etag": meta.get("etag") or head.get("etag"),
        "last_modified": meta.get("last_modified") or head.get("last_modified"),
        "ok": True,
    }


def _decide(
    row: dict[str, Any], probe: dict[str, Any]
) -> tuple[str, str | None, str | None, str | None]:
    kind = probe.get("kind")
    etag = probe.get("etag") or row.get("etag")
    lm = probe.get("last_modified") or row.get("last_modified")

    if kind == "error":
        return "error", row.get("etag"), row.get("last_modified"), probe.get("error") or f"HTTP {probe.get('status')}"

    if kind == "head":
        r_etag = probe.get("etag")
        r_lm = probe.get("last_modified")
        if (r_etag and r_etag == row.get("etag")) or (r_lm and r_lm == row.get("last_modified")):
            return "fresh", r_etag, r_lm, None
        if row.get("last_ingested"):
            return "stale", r_etag, r_lm, None
        return "never", r_etag, r_lm, None

    if kind == "hash":
        stored = row.get("content_hash")
        if stored and stored == probe.get("content_hash"):
            return "fresh", etag, lm, None
        if row.get("last_ingested"):
            return "stale", etag, lm, None
        return "never", etag, lm, None

    return row.get("status", "never"), etag, lm, None


__all__ = ["check_one", "check_many"]
