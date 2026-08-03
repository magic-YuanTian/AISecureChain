"""
Idempotent schema for the Data Source Manager.

Three tables, all created with ``IF NOT EXISTS`` so they're safe to
apply on every request / startup:

    data_source      one row per registered source (NVD, GHSA, OSV, ...)
    source_url       one row per individual URL we track inside a source
    ingestion_run    one row per extraction attempt against a source_url
"""

from __future__ import annotations

import sqlite3

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS data_source (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    tier            INTEGER NOT NULL DEFAULT 3,
    category        TEXT,
    homepage        TEXT,
    description     TEXT,
    discovery_type  TEXT DEFAULT 'manual',
    discovery_url   TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS source_url (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id        TEXT NOT NULL REFERENCES data_source(id) ON DELETE CASCADE,
    url              TEXT NOT NULL,
    title            TEXT,
    first_seen       TEXT DEFAULT CURRENT_TIMESTAMP,
    last_checked     TEXT,
    last_ingested    TEXT,
    content_hash     TEXT,
    etag             TEXT,
    last_modified    TEXT,
    status           TEXT NOT NULL DEFAULT 'never',
    error            TEXT,
    entities_count   INTEGER DEFAULT 0,
    preview_json     TEXT,
    previewed_at     TEXT,
    merged_at        TEXT,
    UNIQUE(source_id, url)
);
CREATE INDEX IF NOT EXISTS idx_source_url_source ON source_url(source_id);
CREATE INDEX IF NOT EXISTS idx_source_url_status ON source_url(status);

CREATE TABLE IF NOT EXISTS source_url_deleted (
    source_id        TEXT NOT NULL,
    url              TEXT NOT NULL,
    deleted_at       TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source_id, url)
);

CREATE TABLE IF NOT EXISTS ingestion_run (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    source_url_id      INTEGER REFERENCES source_url(id) ON DELETE SET NULL,
    source_id          TEXT,
    url                TEXT,
    started_at         TEXT DEFAULT CURRENT_TIMESTAMP,
    finished_at        TEXT,
    status             TEXT NOT NULL DEFAULT 'running',
    entities_inserted  INTEGER DEFAULT 0,
    entities_reused    INTEGER DEFAULT 0,
    same_as_edges      INTEGER DEFAULT 0,
    chunks_extracted   INTEGER DEFAULT 0,
    error_message      TEXT
);
CREATE INDEX IF NOT EXISTS idx_ingestion_run_url ON ingestion_run(source_url_id);
CREATE INDEX IF NOT EXISTS idx_ingestion_run_started ON ingestion_run(started_at DESC);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the Data Source Manager tables if they don't exist."""
    conn.executescript(SCHEMA_SQL)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(source_url)").fetchall()}
    if "preview_json" not in cols:
        conn.execute("ALTER TABLE source_url ADD COLUMN preview_json TEXT")
    if "previewed_at" not in cols:
        conn.execute("ALTER TABLE source_url ADD COLUMN previewed_at TEXT")
    if "merged_at" not in cols:
        conn.execute("ALTER TABLE source_url ADD COLUMN merged_at TEXT")
    conn.commit()


__all__ = ["SCHEMA_SQL", "ensure_schema"]
