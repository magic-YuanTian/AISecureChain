"""Tests for sources.registry — seed loading, CRUD, stats."""

from __future__ import annotations

import sqlite3

import pytest

from sources.registry import (
    add_source_url,
    delete_source_url,
    get_source,
    get_source_url,
    list_recent_runs,
    list_source_urls,
    list_sources,
    overall_stats,
    seed_from_yaml,
    set_source_enabled,
)
from sources.schema import ensure_schema


@pytest.fixture()
def conn(tmp_db):
    c = sqlite3.connect(tmp_db)
    c.row_factory = sqlite3.Row
    ensure_schema(c)
    yield c
    c.close()


class TestSeedFromYaml:
    def test_first_load_inserts_sources_and_urls(self, conn):
        stats = seed_from_yaml(conn)
        assert stats["sources_inserted"] > 0
        assert stats["sources_updated"] == 0
        assert stats["urls_inserted"] > 0

        all_sources = list_sources(conn)
        assert any(s["id"] == "nvd" for s in all_sources)
        assert any(s["id"] == "ghsa" for s in all_sources)
        assert any(s["id"] == "avid" for s in all_sources)

    def test_reload_is_idempotent(self, conn):
        seed_from_yaml(conn)
        url_count_before = conn.execute("SELECT COUNT(*) FROM source_url").fetchone()[0]

        stats = seed_from_yaml(conn)
        assert stats["sources_inserted"] == 0
        assert stats["sources_updated"] > 0
        assert stats["urls_inserted"] == 0  # all seed URLs already there

        url_count_after = conn.execute("SELECT COUNT(*) FROM source_url").fetchone()[0]
        assert url_count_after == url_count_before

    def test_deleted_seed_url_is_not_reinserted_on_reload(self, conn):
        seed_from_yaml(conn)
        row = conn.execute(
            "SELECT id, source_id, url FROM source_url WHERE source_id != 'user' LIMIT 1"
        ).fetchone()
        assert row is not None

        assert delete_source_url(conn, row["id"]) is True
        seed_from_yaml(conn)

        restored = conn.execute(
            "SELECT 1 FROM source_url WHERE source_id=? AND url=?",
            (row["source_id"], row["url"]),
        ).fetchone()
        assert restored is None

    def test_sources_have_tier_and_category(self, conn):
        seed_from_yaml(conn)
        for s in list_sources(conn):
            assert 1 <= s["tier"] <= 5
            assert s["category"] is not None


class TestCRUD:
    def test_add_url_then_fetch(self, conn):
        seed_from_yaml(conn)
        row = add_source_url(conn, "nvd", "https://example.com/cve/123")
        assert row is not None
        assert row["status"] == "never"
        assert row["url"].endswith("/cve/123")

        fetched = get_source_url(conn, row["id"])
        assert fetched is not None and fetched["id"] == row["id"]

    def test_add_duplicate_url_is_noop(self, conn):
        seed_from_yaml(conn)
        add_source_url(conn, "nvd", "https://example.com/x")
        before = conn.execute("SELECT COUNT(*) FROM source_url WHERE url='https://example.com/x'").fetchone()[0]
        add_source_url(conn, "nvd", "https://example.com/x")
        after = conn.execute("SELECT COUNT(*) FROM source_url WHERE url='https://example.com/x'").fetchone()[0]
        assert before == after == 1

    def test_delete_source_url(self, conn):
        seed_from_yaml(conn)
        row = add_source_url(conn, "nvd", "https://example.com/delete-me")
        assert delete_source_url(conn, row["id"]) is True
        assert get_source_url(conn, row["id"]) is None

    def test_toggle_enabled(self, conn):
        seed_from_yaml(conn)
        assert set_source_enabled(conn, "nvd", False) is True
        assert get_source(conn, "nvd")["enabled"] == 0
        set_source_enabled(conn, "nvd", True)
        assert get_source(conn, "nvd")["enabled"] == 1

    def test_unknown_source_returns_none(self, conn):
        assert get_source(conn, "does-not-exist") is None


class TestListing:
    def test_list_source_urls_sorts_stale_first(self, conn):
        seed_from_yaml(conn)
        conn.execute(
            "UPDATE source_url SET status='stale' WHERE id=(SELECT MIN(id) FROM source_url WHERE source_id='nvd')"
        )
        conn.execute(
            "UPDATE source_url SET status='fresh' WHERE id=(SELECT MAX(id) FROM source_url WHERE source_id='nvd')"
        )
        conn.commit()
        urls = list_source_urls(conn, "nvd")
        # stale should appear before fresh
        statuses = [u["status"] for u in urls]
        assert statuses.index("stale") < statuses.index("fresh")

    def test_overall_stats_totals_match(self, conn):
        seed_from_yaml(conn)
        totals = overall_stats(conn)
        actual_sources = conn.execute("SELECT COUNT(*) FROM data_source").fetchone()[0]
        actual_urls = conn.execute("SELECT COUNT(*) FROM source_url").fetchone()[0]
        assert totals["sources_total"] == actual_sources
        assert totals["urls_total"] == actual_urls
        # No runs yet
        assert totals["runs_total"] == 0

    def test_list_recent_runs_empty_by_default(self, conn):
        seed_from_yaml(conn)
        assert list_recent_runs(conn) == []
