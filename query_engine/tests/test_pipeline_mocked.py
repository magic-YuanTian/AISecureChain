"""
End-to-end pipeline tests with mocked crawler + mocked LLM.

These tests give you confidence that the whole pipeline works on realistic
markdown WITHOUT touching the network or spending LLM credits.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from extract_pipeline import run_pipeline


# ── Single-CVE page ─────────────────────────────────────────────────────────

SINGLE_CVE_MD = """# CVE-2024-5184 Detail

**Vendor:** OpenAI
**Product:** ChatGPT
**Affected versions:** 1.2.3, 1.2.4

## Description
Prompt injection vulnerability in ChatGPT allowing exfiltration of user data.

## CWE
CWE-79 — Cross-site Scripting (XSS)

## CVSS 3.1
Base score 7.5 (HIGH)
"""

SINGLE_CVE_JSON = json.dumps({
    "entities": [
        {"class": "Vendor", "local_id": "v1", "attributes": {"name": "OpenAI"}},
        {"class": "Software", "local_id": "s1", "attributes": {"name": "ChatGPT", "is_ai": True}},
        {"class": "Version", "local_id": "ver1", "attributes": {"version_string": "1.2.3"}},
        {"class": "Version", "local_id": "ver2", "attributes": {"version_string": "1.2.4"}},
        {"class": "Vulnerability", "local_id": "vu1", "attributes": {
            "vuln_id": "CVE-2024-5184",
            "title": "ChatGPT prompt injection",
            "description": "A crafted prompt can override ChatGPT instructions and leak user data.",
            "cvss_base_score": 7.5,
            "cvss_severity": "HIGH",
        }},
        {"class": "VulnerabilityType", "local_id": "cwe1", "attributes": {
            "id": "CWE-79", "description": "Cross-site Scripting (XSS)",
        }},
    ],
    "relations": [
        {"predicate": "produce", "subject": "v1", "object": "s1"},
        {"predicate": "hasVersion", "subject": "s1", "object": "ver1"},
        {"predicate": "hasVersion", "subject": "s1", "object": "ver2"},
        {"predicate": "vulnerableTo", "subject": "ver1", "object": "vu1"},
        {"predicate": "vulnerableTo", "subject": "ver2", "object": "vu1"},
        {"predicate": "isA_vulnType", "subject": "vu1", "object": "cwe1"},
    ],
})


def test_pipeline_single_cve(monkeypatch, tmp_db, crawler_fixed_markdown, llm_fixed_response):
    crawler_fixed_markdown(SINGLE_CVE_MD)
    llm_fixed_response(SINGLE_CVE_JSON)

    # Redirect DB writes to the temp DB
    monkeypatch.setattr("extract_pipeline.persist.DB_PATH", tmp_db)

    result = asyncio.run(run_pipeline("https://example.com/cve", skip_db=False))

    assert not result.errors
    counts = result.entity_counts_by_class()
    assert counts.get("Vulnerability") == 1
    assert counts.get("Vendor") == 1
    assert counts.get("Software") == 1
    assert counts.get("Version") == 2
    assert counts.get("VulnerabilityType") == 1

    assert result.db_stats
    assert result.db_stats["vulnerabilities_inserted"] == 1
    assert result.db_stats["versions_inserted"] == 2


# ── Multi-record listing page ──────────────────────────────────────────────

MULTI_MD = "\n\n".join(
    [f"## CVE-2024-{i:04d}\nLangChain SQL injection #{i}. Severity HIGH." for i in range(3)]
)

MULTI_JSON = json.dumps({
    "entities": [
        {"class": "Vendor", "local_id": "v", "attributes": {"name": "LangChain"}},
        {"class": "Software", "local_id": "s", "attributes": {"name": "langchain", "is_ai": True}},
    ] + [
        {"class": "Vulnerability", "local_id": f"vu{i}", "attributes": {
            "vuln_id": f"CVE-2024-{i:04d}",
            "title": f"LangChain SQL injection #{i}",
            "description": "Untrusted input is concatenated into a SQL query.",
            "cvss_severity": "HIGH",
        }} for i in range(3)
    ],
    "relations": [{"predicate": "produce", "subject": "v", "object": "s"}],
})


def test_pipeline_multi_record(monkeypatch, tmp_db, crawler_fixed_markdown, llm_fixed_response):
    crawler_fixed_markdown(MULTI_MD)
    llm_fixed_response(MULTI_JSON)
    monkeypatch.setattr("extract_pipeline.persist.DB_PATH", tmp_db)

    result = asyncio.run(run_pipeline("https://example.com/many", skip_db=False))

    assert not result.errors
    assert result.entity_counts_by_class()["Vulnerability"] == 3
    assert result.db_stats["vulnerabilities_inserted"] == 3


# ── Idempotency: re-running the same URL doesn't duplicate ─────────────────

def test_pipeline_rerun_does_not_duplicate(monkeypatch, tmp_db, crawler_fixed_markdown, llm_fixed_response):
    crawler_fixed_markdown(SINGLE_CVE_MD)
    llm_fixed_response(SINGLE_CVE_JSON)
    monkeypatch.setattr("extract_pipeline.persist.DB_PATH", tmp_db)

    asyncio.run(run_pipeline("https://example.com/cve", skip_db=False))
    result2 = asyncio.run(run_pipeline("https://example.com/cve", skip_db=False))

    assert result2.db_stats["vulnerabilities_inserted"] == 0
    assert result2.db_stats["vulnerabilities_reused"] == 1
    assert result2.db_stats["vendors_inserted"] == 0
    assert result2.db_stats["vendors_reused"] == 1


# ── Error resilience: one bad chunk doesn't kill the run ──────────────────

def test_pipeline_handles_bad_llm_json(monkeypatch, tmp_db, crawler_fixed_markdown, llm_fixed_response):
    crawler_fixed_markdown(SINGLE_CVE_MD)
    llm_fixed_response("total garbage, not json at all")
    monkeypatch.setattr("extract_pipeline.persist.DB_PATH", tmp_db)

    result = asyncio.run(run_pipeline("https://example.com/bad", skip_db=True))
    # Should NOT crash. Should accumulate errors + no entities.
    assert result.errors, "Should record errors"
    assert not result.canonical_entities


# ── Graceful crawler failure ──────────────────────────────────────────────

def test_pipeline_handles_crawler_failure(monkeypatch):
    async def _fail_crawl(url):  # noqa: ARG001
        return "", "simulated network failure"

    monkeypatch.setattr("extract_pipeline.pipeline.crawl_url_to_markdown", _fail_crawl)
    result = asyncio.run(run_pipeline("https://example.com/dead", skip_db=True))
    assert any("simulated" in e for e in result.errors)
    assert result.canonical_entities == []
