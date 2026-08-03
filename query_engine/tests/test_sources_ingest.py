"""Tests for sources.ingest — wrap run_pipeline + write ingestion_run."""

from __future__ import annotations

import sqlite3

import pytest

from sources import ingest as ingest_mod
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


@pytest.fixture()
def url_row(conn):
    row = add_source_url(conn, "nvd", "https://example.com/cve/FAKE-1")
    return row


def _fake_pipeline_result(*, errors=None, entities=5, db_stats=None):
    """Build a PipelineResult-like stub that ingest_url_sync understands."""
    from extract_pipeline.models import CanonicalEntity, PipelineResult

    result = PipelineResult(url="https://example.com/cve/FAKE-1")
    result.markdown = "# CVE-FAKE-1\n\nSome vulnerability description."
    result.markdown_length = len(result.markdown)
    result.chunks_total = 1
    result.chunks_extracted = 1
    result.errors = list(errors or [])
    result.canonical_entities = [
        CanonicalEntity(
            class_name="Vendor",
            canonical_key=f"Vendor::x-{i}",
            attributes={"name": f"Vendor-{i}"},
        )
        for i in range(entities)
    ]
    result.db_stats = db_stats or {
        "vendors_inserted": entities,
        "software_inserted": 0,
        "versions_inserted": 0,
        "vulns_inserted": 1,
        "vendors_reused": 0,
        "software_reused": 0,
        "vulns_reused": 0,
        "licenses_reused": 0,
        "same_as_edges_written": 0,
    }
    return result


class TestIngestUrlSync:
    def test_success_path(self, tmp_db, url_row, monkeypatch):
        async def _fake_run_pipeline(url, skip_db=False, **kwargs):  # noqa: ARG001
            return _fake_pipeline_result()

        import extract_pipeline as ep
        monkeypatch.setattr(ep, "run_pipeline", _fake_run_pipeline)

        out = ingest_mod.ingest_url_sync(url_row, db_path=tmp_db)

        assert out["status"] == "success"
        assert out["entities_inserted"] >= 1
        assert out["finished_at"] is not None

        # URL row should be marked fresh with content_hash + entities_count
        c = sqlite3.connect(tmp_db)
        c.row_factory = sqlite3.Row
        u = dict(c.execute("SELECT * FROM source_url WHERE id=?", (url_row["id"],)).fetchone())
        c.close()
        assert u["status"] == "fresh"
        assert u["content_hash"] is not None
        assert u["entities_count"] == 5

    def test_pipeline_errors_marked_as_error(self, tmp_db, url_row, monkeypatch):
        async def _fake(url, skip_db=False, **kwargs):  # noqa: ARG001
            r = _fake_pipeline_result(errors=["crawl4ai: 404"], entities=0)
            r.canonical_entities = []  # force error path
            return r

        import extract_pipeline as ep
        monkeypatch.setattr(ep, "run_pipeline", _fake)

        out = ingest_mod.ingest_url_sync(url_row, db_path=tmp_db)
        assert out["status"] == "error"
        assert "404" in (out["error_message"] or "")

        c = sqlite3.connect(tmp_db)
        c.row_factory = sqlite3.Row
        u = dict(c.execute("SELECT * FROM source_url WHERE id=?", (url_row["id"],)).fetchone())
        c.close()
        assert u["status"] == "error"
        assert u["entities_count"] == 0

    def test_pipeline_raises_creates_error_run(self, tmp_db, url_row, monkeypatch):
        async def _boom(url, skip_db=False, **kwargs):  # noqa: ARG001
            raise RuntimeError("unexpected")

        import extract_pipeline as ep
        monkeypatch.setattr(ep, "run_pipeline", _boom)

        out = ingest_mod.ingest_url_sync(url_row, db_path=tmp_db)
        assert out["status"] == "error"
        assert "unexpected" in (out["error_message"] or "")


class TestIngestSourceAsync:
    def test_enqueues_only_stale_urls(self, conn, tmp_db, monkeypatch):
        # Add 3 URLs; mark one as fresh.
        u1 = add_source_url(conn, "nvd", "https://example.com/1")
        u2 = add_source_url(conn, "nvd", "https://example.com/2")
        u3 = add_source_url(conn, "nvd", "https://example.com/3")
        conn.execute("UPDATE source_url SET status='fresh' WHERE id=?", (u1["id"],))
        conn.commit()

        # Prevent actual background thread work (we only test enqueueing).
        called = []
        def _fake_ingest_url_async(row, db_path):  # noqa: ARG001
            called.append(row["id"])
            return len(called)
        monkeypatch.setattr(ingest_mod, "ingest_url_async", _fake_ingest_url_async)

        out = ingest_mod.ingest_source_async(conn, "nvd", only_stale=True, limit=50, db_path=tmp_db)

        assert out["queued"] >= 2
        # Fresh URL must NOT be in the list
        assert u1["id"] not in called
        assert u2["id"] in called
        assert u3["id"] in called
