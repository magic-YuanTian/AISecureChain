"""Shared pytest fixtures.

All tests are self-contained:
    * Never hit the network
    * Never call the real LLM
    * Never touch the real ai_vuln_kb.db (a temp DB is used instead)
"""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

import pytest

# Make sibling packages importable
_QE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_QE))

from build_db import SCHEMA  # noqa: E402
from extract_pipeline.models import (  # noqa: E402
    CanonicalEntity,
    CanonicalRelation,
    ExtractedEntity,
    ExtractedRelation,
    ExtractionGraph,
)


@pytest.fixture()
def tmp_db(tmp_path) -> str:
    """Spin up a fresh SQLite DB with the real schema applied."""
    path = str(tmp_path / "test.db")
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    return path


@pytest.fixture()
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture()
def sample_vuln_graph() -> ExtractionGraph:
    """A representative chunk: LangChain / CVE-2023-36258."""
    return ExtractionGraph(
        entities=[
            ExtractedEntity(**{"class": "Vendor", "local_id": "v1", "attributes": {"name": "LangChain"}}),
            ExtractedEntity(**{"class": "Software", "local_id": "s1", "attributes": {"name": "langchain", "is_ai": True}}),
            ExtractedEntity(**{"class": "Version", "local_id": "ver1", "attributes": {"version_string": "0.0.331"}}),
            ExtractedEntity(**{"class": "Vulnerability", "local_id": "vu1", "attributes": {
                "vuln_id": "CVE-2023-36258",
                "title": "PALChain command injection",
                "description": "PALChain interpolates untrusted LLM output into a shell command.",
                "cvss_base_score": 9.8,
                "cvss_severity": "CRITICAL",
                "references": ["https://example.com/a", "https://example.com/b"],
            }}),
            ExtractedEntity(**{"class": "VulnerabilityType", "local_id": "cwe1", "attributes": {
                "id": "CWE-78",
                "description": "OS Command Injection",
            }}),
        ],
        relations=[
            ExtractedRelation(predicate="produce", subject="v1", object="s1"),
            ExtractedRelation(predicate="hasVersion", subject="s1", object="ver1"),
            ExtractedRelation(predicate="vulnerableTo", subject="ver1", object="vu1"),
            ExtractedRelation(predicate="isA_vulnType", subject="vu1", object="cwe1"),
        ],
    )


@pytest.fixture()
def llm_fixed_response(monkeypatch):
    """Factory: patch the LLM call to return a fixed JSON string.

    Usage::

        def test_x(llm_fixed_response):
            llm_fixed_response('{"entities":[...], "relations":[]}')
            # ... call pipeline ...
    """
    def _apply(json_text: str):
        from extract_pipeline import llm as _llm

        def _fake_call_llm(messages, temperature=0.0):  # noqa: ARG001
            return json_text

        monkeypatch.setattr(_llm, "_call_llm", _fake_call_llm)
    return _apply


@pytest.fixture()
def crawler_fixed_markdown(monkeypatch):
    """Factory: patch crawl4ai to return a fixed markdown string."""
    def _apply(markdown: str):
        from extract_pipeline import pipeline as _pipe

        async def _fake_crawl(url):  # noqa: ARG001
            return markdown, None

        monkeypatch.setattr(_pipe, "crawl_url_to_markdown", _fake_crawl)
    return _apply
