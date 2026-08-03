"""
Registry functions for the Data Source Manager.

* ``seed_from_yaml`` reads ``seeds.yaml`` and UPSERTs into ``data_source``
  + ``source_url``. Safe to call on every boot.
* ``list_sources`` / ``get_source`` / ``list_source_urls`` are read helpers
  the API layer calls.
* ``add_source_url`` / ``delete_source_url`` / ``set_source_enabled`` are
  the write helpers the UI calls.

Every function takes an open ``sqlite3.Connection`` so the caller owns the
DB lifecycle (important because the Flask app already has a connection
factory).
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml  # PyYAML
except ImportError as e:  # pragma: no cover
    raise RuntimeError(
        "PyYAML is required for the sources registry. Install with `pip install pyyaml`."
    ) from e

from .schema import ensure_schema

_SEEDS_PATH = Path(__file__).parent / "seeds.yaml"


# ── Seed loading ──────────────────────────────────────────────────────────

def load_seeds_from_yaml(path: str | os.PathLike[str] | None = None) -> list[dict[str, Any]]:
    """Parse ``seeds.yaml`` into a list of source dicts (not DB-touched)."""
    p = Path(path) if path else _SEEDS_PATH
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return list(data.get("sources", []))


def seed_from_yaml(
    conn: sqlite3.Connection,
    path: str | os.PathLike[str] | None = None,
) -> dict[str, int]:
    """UPSERT every source from seeds.yaml into the DB.

    Returns a stats dict: sources_inserted, sources_updated, urls_inserted.
    """
    ensure_schema(conn)
    seeds = load_seeds_from_yaml(path)

    stats = {"sources_inserted": 0, "sources_updated": 0, "urls_inserted": 0}
    cur = conn.cursor()

    for src in seeds:
        sid = str(src.get("id", "")).strip()
        if not sid:
            continue
        fields = {
            "id": sid,
            "name": src.get("name") or sid,
            "tier": int(src.get("tier", 3)),
            "category": src.get("category"),
            "homepage": src.get("homepage"),
            "description": (src.get("description") or "").strip() or None,
            "discovery_type": src.get("discovery_type") or "manual",
            "discovery_url": src.get("discovery_url"),
            "enabled": 1,
        }
        existed = cur.execute(
            "SELECT 1 FROM data_source WHERE id=?", (sid,)
        ).fetchone()
        if existed:
            cur.execute(
                """UPDATE data_source
                   SET name=?, tier=?, category=?, homepage=?, description=?,
                       discovery_type=?, discovery_url=?, updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (fields["name"], fields["tier"], fields["category"],
                 fields["homepage"], fields["description"],
                 fields["discovery_type"], fields["discovery_url"], sid),
            )
            stats["sources_updated"] += 1
        else:
            cur.execute(
                """INSERT INTO data_source
                   (id, name, tier, category, homepage, description,
                    discovery_type, discovery_url, enabled)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                tuple(fields.values()),
            )
            stats["sources_inserted"] += 1

        for url in src.get("seed_urls") or []:
            url = str(url).strip()
            if not url:
                continue
            deleted = cur.execute(
                "SELECT 1 FROM source_url_deleted WHERE source_id=? AND url=?",
                (sid, url),
            ).fetchone()
            if deleted:
                continue
            exists = cur.execute(
                "SELECT 1 FROM source_url WHERE source_id=? AND url=?", (sid, url)
            ).fetchone()
            if not exists:
                cur.execute(
                    "INSERT INTO source_url (source_id, url, status) VALUES (?,?,?)",
                    (sid, url, "never"),
                )
                stats["urls_inserted"] += 1

    conn.commit()
    return stats


# ── Read helpers ──────────────────────────────────────────────────────────

def list_sources(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return all registered sources with aggregate URL + running-run stats."""
    ensure_schema(conn)
    rows = conn.execute(
        """
        SELECT ds.*,
               COALESCE(u.total, 0) AS urls_total,
               COALESCE(u.fresh, 0) AS urls_fresh,
               COALESCE(u.stale, 0) AS urls_stale,
               COALESCE(u.never, 0) AS urls_never,
               COALESCE(u.error, 0) AS urls_error,
               u.last_checked   AS last_checked_any,
               u.last_ingested  AS last_ingested_any,
               COALESCE(r.running, 0) AS runs_running
        FROM data_source ds
        LEFT JOIN (
            SELECT source_id,
                   COUNT(*)                                                 AS total,
                   SUM(CASE WHEN status='fresh' THEN 1 ELSE 0 END)           AS fresh,
                   SUM(CASE WHEN status='stale' THEN 1 ELSE 0 END)           AS stale,
                   SUM(CASE WHEN status='never' THEN 1 ELSE 0 END)           AS never,
                   SUM(CASE WHEN status='error' THEN 1 ELSE 0 END)           AS error,
                   MAX(last_checked)                                         AS last_checked,
                   MAX(last_ingested)                                        AS last_ingested
            FROM source_url
            GROUP BY source_id
        ) u ON u.source_id = ds.id
        LEFT JOIN (
            SELECT source_id, COUNT(*) AS running
            FROM ingestion_run
            WHERE status='running'
            GROUP BY source_id
        ) r ON r.source_id = ds.id
        ORDER BY ds.name
        """
    ).fetchall()
    return [dict(r) for r in rows]


def get_source(conn: sqlite3.Connection, source_id: str) -> dict[str, Any] | None:
    ensure_schema(conn)
    row = conn.execute("SELECT * FROM data_source WHERE id=?", (source_id,)).fetchone()
    return dict(row) if row else None


def list_source_urls(
    conn: sqlite3.Connection,
    source_id: str,
    *,
    limit: int = 200,
    offset: int = 0,
) -> list[dict[str, Any]]:
    ensure_schema(conn)
    rows = conn.execute(
        """SELECT * FROM source_url
           WHERE source_id=?
           ORDER BY CASE status
                      WHEN 'stale' THEN 0
                      WHEN 'never' THEN 1
                      WHEN 'error' THEN 2
                      WHEN 'fresh' THEN 3
                      ELSE 4 END,
                    last_ingested DESC
           LIMIT ? OFFSET ?""",
        (source_id, limit, offset),
    ).fetchall()
    return [dict(r) for r in rows]


def list_recent_runs(
    conn: sqlite3.Connection,
    *,
    source_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    ensure_schema(conn)
    if source_id:
        rows = conn.execute(
            """SELECT * FROM ingestion_run WHERE source_id=?
               ORDER BY started_at DESC LIMIT ?""",
            (source_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM ingestion_run ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def recover_interrupted_runs(conn: sqlite3.Connection) -> int:
    """Mark stale 'running' runs as interrupted after process restart.

    Background ingestion uses daemon threads. If the Python process exits
    (reload/crash/manual stop), those threads are terminated and cannot
    finish their DB writes. Any run left in status='running' is therefore
    no longer active and should be surfaced as an interrupted error.
    """
    ensure_schema(conn)
    cur = conn.cursor()
    cur.execute(
        """UPDATE ingestion_run
           SET status='cancelled',
               finished_at=CURRENT_TIMESTAMP,
               error_message=COALESCE(error_message, 'cancelled: server restarted')
           WHERE status='running'"""
    )
    conn.commit()
    return int(cur.rowcount or 0)


def cancel_run(conn: sqlite3.Connection, run_id: int) -> bool:
    """Best-effort cancel for a single run currently in running state."""
    ensure_schema(conn)
    cur = conn.cursor()
    cur.execute(
        """UPDATE ingestion_run
           SET status='cancelled',
               finished_at=CURRENT_TIMESTAMP,
               error_message=COALESCE(error_message, 'cancelled by user')
           WHERE id=? AND status='running'""",
        (run_id,),
    )
    conn.commit()
    return bool(cur.rowcount)


def cancel_running_runs(
    conn: sqlite3.Connection,
    *,
    source_id: str | None = None,
) -> int:
    """Cancel all running runs, optionally for one source."""
    ensure_schema(conn)
    cur = conn.cursor()
    if source_id:
        cur.execute(
            """UPDATE ingestion_run
               SET status='cancelled',
                   finished_at=CURRENT_TIMESTAMP,
                   error_message=COALESCE(error_message, 'cancelled by user')
               WHERE status='running' AND source_id=?""",
            (source_id,),
        )
    else:
        cur.execute(
            """UPDATE ingestion_run
               SET status='cancelled',
                   finished_at=CURRENT_TIMESTAMP,
                   error_message=COALESCE(error_message, 'cancelled by user')
               WHERE status='running'"""
        )
    conn.commit()
    return int(cur.rowcount or 0)


def overall_stats(conn: sqlite3.Connection) -> dict[str, int]:
    """Grand-total counts across the whole registry."""
    ensure_schema(conn)
    row = conn.execute(
        """SELECT COUNT(*)                                               AS sources_total,
                  SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END)             AS sources_enabled
           FROM data_source"""
    ).fetchone()
    url_row = conn.execute(
        """SELECT COUNT(*)                                                AS urls_total,
                  SUM(CASE WHEN status='fresh' THEN 1 ELSE 0 END)         AS urls_fresh,
                  SUM(CASE WHEN status='stale' THEN 1 ELSE 0 END)         AS urls_stale,
                  SUM(CASE WHEN status='never' THEN 1 ELSE 0 END)         AS urls_never,
                  SUM(CASE WHEN status='error' THEN 1 ELSE 0 END)         AS urls_error
           FROM source_url"""
    ).fetchone()
    run_row = conn.execute(
        """SELECT COUNT(*)                                                AS runs_total,
                  SUM(CASE WHEN status='running' THEN 1 ELSE 0 END)       AS runs_running,
                  SUM(CASE WHEN status='success' THEN 1 ELSE 0 END)       AS runs_success,
                  SUM(CASE WHEN status='error'   THEN 1 ELSE 0 END)       AS runs_error
           FROM ingestion_run"""
    ).fetchone()
    out: dict[str, int] = {}
    for r in (row, url_row, run_row):
        for k in r.keys():
            out[k] = int(r[k] or 0)
    return out


# ── Write helpers ─────────────────────────────────────────────────────────

def add_source_url(
    conn: sqlite3.Connection,
    source_id: str,
    url: str,
    *,
    title: str | None = None,
) -> dict[str, Any] | None:
    ensure_schema(conn)
    url = url.strip()
    if not url:
        return None
    cur = conn.cursor()
    exists = cur.execute(
        "SELECT id FROM source_url WHERE source_id=? AND url=?", (source_id, url)
    ).fetchone()
    if exists:
        return dict(cur.execute("SELECT * FROM source_url WHERE id=?", (exists[0],)).fetchone())
    cur.execute(
        "DELETE FROM source_url_deleted WHERE source_id=? AND url=?",
        (source_id, url),
    )
    cur.execute(
        "INSERT INTO source_url (source_id, url, title, status) VALUES (?,?,?,?)",
        (source_id, url, title, "never"),
    )
    conn.commit()
    return dict(
        cur.execute("SELECT * FROM source_url WHERE id=?", (cur.lastrowid,)).fetchone()
    )


def delete_source_url(conn: sqlite3.Connection, url_id: int) -> bool:
    ensure_schema(conn)
    cur = conn.cursor()
    row = cur.execute("SELECT source_id, url FROM source_url WHERE id=?", (url_id,)).fetchone()
    if row:
        cur.execute(
            """INSERT OR REPLACE INTO source_url_deleted (source_id, url, deleted_at)
               VALUES (?, ?, CURRENT_TIMESTAMP)""",
            (row["source_id"], row["url"]),
        )
    cur.execute("DELETE FROM source_url WHERE id=?", (url_id,))
    conn.commit()
    return cur.rowcount > 0


def set_source_enabled(
    conn: sqlite3.Connection,
    source_id: str,
    enabled: bool,
) -> bool:
    ensure_schema(conn)
    cur = conn.cursor()
    cur.execute(
        "UPDATE data_source SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (1 if enabled else 0, source_id),
    )
    conn.commit()
    return cur.rowcount > 0


def get_source_url(conn: sqlite3.Connection, url_id: int) -> dict[str, Any] | None:
    ensure_schema(conn)
    row = conn.execute("SELECT * FROM source_url WHERE id=?", (url_id,)).fetchone()
    return dict(row) if row else None


__all__ = [
    "load_seeds_from_yaml",
    "seed_from_yaml",
    "list_sources",
    "get_source",
    "list_source_urls",
    "list_recent_runs",
    "recover_interrupted_runs",
    "cancel_run",
    "cancel_running_runs",
    "overall_stats",
    "add_source_url",
    "delete_source_url",
    "set_source_enabled",
    "get_source_url",
]
