from __future__ import annotations

import sqlite3

import pytest

from extract_pipeline.models import CanonicalEntity, CanonicalRelation, PipelineResult


@pytest.fixture()
def client(monkeypatch, tmp_db):
    import app as app_module
    from sources.schema import ensure_schema

    app_module.app.config["TESTING"] = True
    app_module.DB_PATH = tmp_db
    app_module._sources_seeded = True

    conn = sqlite3.connect(tmp_db)
    conn.row_factory = sqlite3.Row
    ensure_schema(conn)
    app_module._ensure_user_source(conn)
    conn.close()

    calls = {"run_pipeline": 0, "persist": 0}

    async def _fake_run_pipeline(url: str, skip_db: bool = False):  # noqa: ARG001
        calls["run_pipeline"] += 1
        return PipelineResult(
            url=url,
            markdown="demo",
            markdown_length=4,
            chunks_total=1,
            chunks_extracted=1,
            canonical_entities=[
                CanonicalEntity(
                    class_name="Vendor",
                    canonical_key="Vendor::openai",
                    attributes={"name": "OpenAI"},
                ),
                CanonicalEntity(
                    class_name="Software",
                    canonical_key="Software::openai::chatgpt",
                    attributes={"name": "ChatGPT", "is_ai": True},
                ),
            ],
            canonical_relations=[
                CanonicalRelation(
                    predicate="produce",
                    subject_key="Vendor::openai",
                    object_key="Software::openai::chatgpt",
                )
            ],
            errors=[],
            warnings=[],
            db_stats=None,
        )

    def _fake_persist(entities, relations, **kwargs):  # noqa: ARG001
        calls["persist"] += 1
        return {
            "vendors_inserted": 1,
            "software_inserted": 1,
            "versions_inserted": 0,
            "vulns_inserted": 0,
            "vendors_reused": 0,
            "software_reused": 0,
            "vulns_reused": 0,
            "same_as_edges_written": 0,
        }

    monkeypatch.setattr("extract_pipeline.run_pipeline", _fake_run_pipeline)
    monkeypatch.setattr("extract_pipeline.persist.persist_canonical", _fake_persist)
    return app_module.app.test_client(), calls


def test_extract_endpoint_serializes_canonical_relation_keys(client):
    client, _calls = client
    response = client.post("/api/extract", json={"url": "https://example.com", "skip_db": True})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["extraction"]["relations"] == [
        {
            "predicate": "produce",
            "subject": "Vendor::openai",
            "object": "Software::openai::chatgpt",
        }
    ]


def test_url_preview_is_cached_and_merge_reuses_cached_result(client):
    client, calls = client

    add = client.post("/api/urls", json={"url": "https://example.com/cached"})
    assert add.status_code == 200
    url_id = add.get_json()["url"]["id"]

    preview1 = client.post(f"/api/urls/{url_id}/preview")
    assert preview1.status_code == 200
    assert preview1.get_json()["status"] == "extracted"
    assert calls["run_pipeline"] == 1

    preview2 = client.post(f"/api/urls/{url_id}/preview")
    assert preview2.status_code == 200
    assert preview2.get_json()["cached"] is True
    assert preview2.get_json()["status"] == "extracted"
    assert calls["run_pipeline"] == 1, "second preview should reuse cached extraction"

    merge = client.post(f"/api/urls/{url_id}/merge")
    assert merge.status_code == 200
    assert merge.get_json()["status"] == "merged"
    assert calls["persist"] == 1
    assert calls["run_pipeline"] == 1, "merge should not rerun extraction"

    rows = client.get("/api/urls").get_json()["urls"]
    row = next(r for r in rows if r["id"] == url_id)
    assert row["status"] == "merged"
