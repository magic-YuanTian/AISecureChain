"""
Ingestion wrapper for the Data Source Manager.

Given a ``source_url`` row, ``ingest_url`` runs the extraction pipeline,
writes a row in ``ingestion_run`` with timing + counts, and updates the
``source_url`` row's ``last_ingested`` / ``content_hash`` / ``status``.

The heavy work (crawl + LLM) runs in a background thread so the Flask
request can return immediately; the UI polls ``/api/sources/runs`` to see
progress and final counts.

Everything respects idempotency: if the pipeline produces an extraction
that's identical to what we already have (same content_hash), the run is
still recorded but no duplicate rows are written — the existing dedup
layer (``extract_pipeline/dedup.py``) handles that.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .freshness import _sha1  # reuse helper
from .schema import ensure_schema

_QE_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DB = str(_QE_ROOT / "ai_vuln_kb.db")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    # Same WAL + busy_timeout combo as app.py::get_db so background
    # ingest threads and the main Flask request thread can coexist
    # without "database is locked".
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _start_run(conn: sqlite3.Connection, url_row: dict[str, Any]) -> int:
    """Insert a 'running' ingestion_run row, return its id."""
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO ingestion_run
           (source_url_id, source_id, url, started_at, status)
           VALUES (?, ?, ?, ?, 'running')""",
        (url_row["id"], url_row["source_id"], url_row["url"], _now_iso()),
    )
    conn.commit()
    return int(cur.lastrowid)


def _start_run_no_commit(conn: sqlite3.Connection, url_row: dict[str, Any]) -> int:
    """Insert a 'running' ingestion_run row without committing yet."""
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO ingestion_run
           (source_url_id, source_id, url, started_at, status)
           VALUES (?, ?, ?, ?, 'running')""",
        (url_row["id"], url_row["source_id"], url_row["url"], _now_iso()),
    )
    return int(cur.lastrowid)


def _finalise_run(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    status: str,
    entities_inserted: int = 0,
    entities_reused: int = 0,
    same_as_edges: int = 0,
    chunks_extracted: int = 0,
    error_message: str | None = None,
) -> None:
    # Preserve a user/server cancellation decision.
    st = conn.execute("SELECT status FROM ingestion_run WHERE id=?", (run_id,)).fetchone()
    if st and st["status"] == "cancelled":
        return
    conn.cursor().execute(
        """UPDATE ingestion_run
           SET finished_at=?, status=?, entities_inserted=?, entities_reused=?,
               same_as_edges=?, chunks_extracted=?, error_message=?
           WHERE id=?""",
        (
            _now_iso(), status, entities_inserted, entities_reused,
            same_as_edges, chunks_extracted, error_message, run_id,
        ),
    )
    conn.commit()


def _update_url_after_ingest(
    conn: sqlite3.Connection,
    url_id: int,
    *,
    status: str,
    content_hash: str | None,
    entities_count: int,
    error: str | None,
) -> None:
    conn.cursor().execute(
        """UPDATE source_url
           SET last_ingested=?, last_checked=?, status=?,
               content_hash=?, entities_count=?, error=?
           WHERE id=?""",
        (
            _now_iso(), _now_iso(), status,
            content_hash, entities_count, error, url_id,
        ),
    )
    conn.commit()


def _is_run_cancelled(conn: sqlite3.Connection, run_id: int) -> bool:
    row = conn.execute("SELECT status FROM ingestion_run WHERE id=?", (run_id,)).fetchone()
    return bool(row and row["status"] == "cancelled")


# ── synchronous core ──────────────────────────────────────────────────────

def ingest_url_sync(url_row: dict[str, Any], *, db_path: str = _DEFAULT_DB) -> dict[str, Any]:
    """Blocking ingestion of a single URL. Returns the final ``ingestion_run`` row."""
    from extract_pipeline import run_pipeline  # local import: heavy deps

    conn = _connect(db_path)
    ensure_schema(conn)
    run_id = _start_run(conn, url_row)

    try:
        result = asyncio.run(run_pipeline(url_row["url"], skip_db=False))
    except Exception as e:  # noqa: BLE001
        if _is_run_cancelled(conn, run_id):
            row = conn.execute("SELECT * FROM ingestion_run WHERE id=?", (run_id,)).fetchone()
            conn.close()
            return dict(row) if row else {"id": run_id, "status": "cancelled"}
        _finalise_run(conn, run_id, status="error", error_message=str(e))
        _update_url_after_ingest(
            conn, url_row["id"], status="error",
            content_hash=url_row.get("content_hash"), entities_count=0,
            error=str(e),
        )
        row = conn.execute("SELECT * FROM ingestion_run WHERE id=?", (run_id,)).fetchone()
        conn.close()
        return dict(row) if row else {"id": run_id, "status": "error", "error_message": str(e)}

    md = result.markdown or ""
    ch = _sha1(md) if md else None

    if _is_run_cancelled(conn, run_id):
        row = conn.execute("SELECT * FROM ingestion_run WHERE id=?", (run_id,)).fetchone()
        conn.close()
        return dict(row) if row else {"id": run_id, "status": "cancelled"}

    if result.errors and not result.canonical_entities:
        _finalise_run(
            conn, run_id, status="error",
            error_message="; ".join(result.errors)[:2000],
        )
        _update_url_after_ingest(
            conn, url_row["id"], status="error",
            content_hash=ch, entities_count=0,
            error="; ".join(result.errors)[:500],
        )
    else:
        stats = result.db_stats or {}
        entities_inserted = sum(
            int(stats.get(k, 0) or 0)
            for k in ("vendors_inserted", "software_inserted", "software_types_inserted",
                      "versions_inserted", "licenses_inserted", "vulns_inserted",
                      "vuln_types_inserted")
        )
        entities_reused = sum(
            int(stats.get(k, 0) or 0)
            for k in ("vendors_reused", "software_reused", "licenses_reused", "vulns_reused")
        )
        same_as = int(stats.get("same_as_edges_written", 0) or 0)
        _finalise_run(
            conn, run_id,
            status="success",
            entities_inserted=entities_inserted,
            entities_reused=entities_reused,
            same_as_edges=same_as,
            chunks_extracted=result.chunks_extracted,
        )
        total_entities = len(result.canonical_entities or [])
        _update_url_after_ingest(
            conn, url_row["id"],
            status="fresh",
            content_hash=ch,
            entities_count=total_entities,
            error=None,
        )

    row = conn.execute("SELECT * FROM ingestion_run WHERE id=?", (run_id,)).fetchone()
    conn.close()
    return dict(row) if row else {"id": run_id}


# ── background runner ────────────────────────────────────────────────────

class _Runner(threading.Thread):
    """Run a callable in a daemon thread; swallow exceptions into the DB."""
    def __init__(self, target: Callable[[], Any]) -> None:
        super().__init__(daemon=True)
        self._target = target

    def run(self) -> None:
        try:
            self._target()
        except Exception:
            # Already logged into the DB by ingest_url_sync; nothing else to do.
            pass


def _run_ingest_worker(url_row: dict[str, Any], run_id: int, *, db_path: str) -> None:
    """Worker body for an already-created ingestion_run row."""
    from extract_pipeline import run_pipeline

    c = _connect(db_path)
    try:
        result = asyncio.run(run_pipeline(url_row["url"], skip_db=False))
    except Exception as e:  # noqa: BLE001
        if _is_run_cancelled(c, run_id):
            c.close()
            return
        _finalise_run(c, run_id, status="error", error_message=str(e))
        _update_url_after_ingest(
            c, url_row["id"], status="error",
            content_hash=url_row.get("content_hash"), entities_count=0,
            error=str(e),
        )
        c.close()
        return

    md = result.markdown or ""
    ch = _sha1(md) if md else None

    if _is_run_cancelled(c, run_id):
        c.close()
        return

    if result.errors and not result.canonical_entities:
        _finalise_run(
            c, run_id, status="error",
            error_message="; ".join(result.errors)[:2000],
        )
        _update_url_after_ingest(
            c, url_row["id"], status="error",
            content_hash=ch, entities_count=0,
            error="; ".join(result.errors)[:500],
        )
    else:
        stats = result.db_stats or {}
        entities_inserted = sum(
            int(stats.get(k, 0) or 0)
            for k in ("vendors_inserted", "software_inserted",
                      "software_types_inserted", "versions_inserted",
                      "licenses_inserted", "vulns_inserted",
                      "vuln_types_inserted")
        )
        entities_reused = sum(
            int(stats.get(k, 0) or 0)
            for k in ("vendors_reused", "software_reused",
                      "licenses_reused", "vulns_reused")
        )
        same_as = int(stats.get("same_as_edges_written", 0) or 0)
        _finalise_run(
            c, run_id,
            status="success",
            entities_inserted=entities_inserted,
            entities_reused=entities_reused,
            same_as_edges=same_as,
            chunks_extracted=result.chunks_extracted,
        )
        _update_url_after_ingest(
            c, url_row["id"],
            status="fresh",
            content_hash=ch,
            entities_count=len(result.canonical_entities or []),
            error=None,
        )
    c.close()


def ingest_url_async(
    url_row: dict[str, Any],
    *,
    db_path: str = _DEFAULT_DB,
    existing_run_id: int | None = None,
) -> int:
    """Kick off ingestion in the background. Returns an ingestion_run id
    immediately (status='running') so the UI has a handle to poll."""
    if existing_run_id is None:
        conn = _connect(db_path)
        ensure_schema(conn)
        run_id = _start_run(conn, url_row)
        conn.close()
    else:
        run_id = existing_run_id

    def _go() -> None:
        _run_ingest_worker(url_row, run_id, db_path=db_path)

    _Runner(_go).start()
    return run_id


def ingest_source_async(
    conn: sqlite3.Connection,
    source_id: str,
    *,
    only_stale: bool = True,
    limit: int = 20,
    db_path: str = _DEFAULT_DB,
) -> dict[str, Any]:
    """Kick off ingestion for every URL in a source that needs it.

    Returns a summary dict with the list of run_ids enqueued.
    """
    ensure_schema(conn)
    where = "source_id=?"
    params: list[Any] = [source_id]
    if only_stale:
        where += " AND status IN ('stale', 'never', 'error')"
    rows = conn.execute(
        f"SELECT * FROM source_url WHERE {where} ORDER BY id LIMIT ?",
        (*params, limit),
    ).fetchall()

    url_rows = [dict(r) for r in rows]
    run_ids: list[int] = []
    for url_row in url_rows:
        rid = _start_run_no_commit(conn, url_row)
        run_ids.append(rid)
    conn.commit()

    for url_row, rid in zip(url_rows, run_ids, strict=False):
        try:
            ingest_url_async(url_row, db_path=db_path, existing_run_id=rid)
        except TypeError:
            # Test monkeypatches may replace ingest_url_async with the old
            # two-argument signature; keep that path working.
            ingest_url_async(url_row, db_path=db_path)

    return {
        "source_id": source_id,
        "queued": len(run_ids),
        "run_ids": run_ids,
    }


__all__ = ["ingest_url_sync", "ingest_url_async", "ingest_source_async"]
