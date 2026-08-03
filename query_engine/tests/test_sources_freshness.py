"""Tests for sources.freshness — state transitions given mocked HTTP."""

from __future__ import annotations

import sqlite3

import pytest

from sources import freshness as fr
from sources.registry import add_source_url, seed_from_yaml
from sources.schema import ensure_schema


@pytest.fixture()
def conn(tmp_db):
    c = sqlite3.connect(tmp_db)
    c.row_factory = sqlite3.Row
    ensure_schema(c)
    seed_from_yaml(c)
    yield c
    c.close()


def _make_row(conn, url="https://example.com/a", **updates):
    row = add_source_url(conn, "nvd", url)
    if updates:
        keys = ", ".join(f"{k}=?" for k in updates)
        conn.execute(
            f"UPDATE source_url SET {keys} WHERE id=?",
            (*updates.values(), row["id"]),
        )
        conn.commit()
    return dict(conn.execute("SELECT * FROM source_url WHERE id=?", (row["id"],)).fetchone())


class TestDecideLogic:
    """`_decide` is pure — exercise all three probe outcomes."""

    def test_head_same_etag_is_fresh(self):
        row = {"etag": '"abc"', "last_modified": None, "content_hash": None, "last_ingested": "2024-01-01", "status": "fresh"}
        probe = {"kind": "head", "etag": '"abc"', "last_modified": None, "ok": True}
        status, _, _, err = fr._decide(row, probe)
        assert status == "fresh"
        assert err is None

    def test_head_new_etag_with_prior_ingest_is_stale(self):
        row = {"etag": '"abc"', "last_modified": None, "content_hash": None, "last_ingested": "2024-01-01", "status": "fresh"}
        probe = {"kind": "head", "etag": '"xyz"', "last_modified": None, "ok": True}
        status, etag, _, _ = fr._decide(row, probe)
        assert status == "stale"
        assert etag == '"xyz"'

    def test_head_never_ingested_stays_never(self):
        row = {"etag": None, "last_modified": None, "content_hash": None, "last_ingested": None, "status": "never"}
        probe = {"kind": "head", "etag": '"new"', "last_modified": None, "ok": True}
        status, _, _, _ = fr._decide(row, probe)
        assert status == "never"

    def test_hash_match_is_fresh(self):
        row = {"etag": None, "last_modified": None, "content_hash": "ABC", "last_ingested": "2024-01-01", "status": "fresh"}
        probe = {"kind": "hash", "content_hash": "ABC", "etag": None, "last_modified": None, "ok": True}
        status, _, _, _ = fr._decide(row, probe)
        assert status == "fresh"

    def test_hash_diff_with_prior_ingest_is_stale(self):
        row = {"etag": None, "last_modified": None, "content_hash": "ABC", "last_ingested": "2024-01-01", "status": "fresh"}
        probe = {"kind": "hash", "content_hash": "XYZ", "etag": None, "last_modified": None, "ok": True}
        status, _, _, _ = fr._decide(row, probe)
        assert status == "stale"

    def test_error_probe_is_error(self):
        row = {"etag": None, "last_modified": None, "content_hash": None, "last_ingested": None, "status": "never"}
        probe = {"kind": "error", "error": "timeout", "status": None}
        status, _, _, err = fr._decide(row, probe)
        assert status == "error"
        assert "timeout" in (err or "")


class TestCheckMany:
    def test_mocked_probe_updates_rows(self, conn, monkeypatch):
        a = _make_row(conn, url="https://example.com/a", last_ingested="2024-01-01", content_hash="OLD_A", status="fresh")
        b = _make_row(conn, url="https://example.com/b")
        c = _make_row(conn, url="https://example.com/c", last_ingested="2024-01-01", etag='"same"', status="fresh")

        def _fake_probe(url, *, deep):  # noqa: ARG001
            if url.endswith("/a"):
                return {"kind": "hash", "content_hash": "NEW_A", "etag": None, "last_modified": None, "ok": True}
            if url.endswith("/b"):
                return {"kind": "hash", "content_hash": "B_HASH", "etag": None, "last_modified": None, "ok": True}
            if url.endswith("/c"):
                return {"kind": "head", "etag": '"same"', "last_modified": None, "ok": True}
            return {"kind": "error", "error": "no"}

        monkeypatch.setattr(fr, "_remote_probe", _fake_probe)

        out = fr.check_many(conn, [a, b, c])
        by_url = {r["url"]: r for r in out}

        assert by_url["https://example.com/a"]["status"] == "stale"
        assert by_url["https://example.com/b"]["status"] == "never"  # never ingested
        assert by_url["https://example.com/c"]["status"] == "fresh"

        # Persisted in the DB too
        persisted = dict(conn.execute("SELECT * FROM source_url WHERE url=?", ("https://example.com/a",)).fetchone())
        assert persisted["status"] == "stale"
        assert persisted["last_checked"] is not None
