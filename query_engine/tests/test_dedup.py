"""Tests for the dedup/same_as module (pure logic, no DB)."""

from extract_pipeline.dedup import (
    detect_vendor_same_as,
    detect_vuln_same_as,
    normalize_cwe_id,
    normalize_name,
    normalize_vendor,
    normalize_vuln_id,
)


# ── Normalization ──────────────────────────────────────────────────────────

class TestNormalization:
    def test_vendor_alias_stripping(self):
        assert normalize_vendor("OpenAI Inc.") == "openai"
        assert normalize_vendor("Open AI") == "openai"
        assert normalize_vendor("openai") == "openai"
        assert normalize_vendor("Microsoft Corporation") == "microsoft"
        assert normalize_vendor("Google LLC") == "google"
        assert normalize_vendor("Alphabet") == "google"
        assert normalize_vendor("Meta Platforms") == "meta"

    def test_generic_name_normalization(self):
        assert normalize_name("  Lang Chain  ") == "lang chain"
        assert normalize_name("foo-bar_baz") == "foo bar baz"
        assert normalize_name("Apache-2.0") == "apache 2.0"

    def test_vuln_id_normalization(self):
        assert normalize_vuln_id("cve-2024-0001") == "CVE-2024-0001"
        assert normalize_vuln_id("  CVE-2024-0001  ") == "CVE-2024-0001"
        assert normalize_vuln_id("") == ""

    def test_cwe_id_normalization(self):
        assert normalize_cwe_id("cwe-79") == "CWE-79"
        assert normalize_cwe_id("79") == "CWE-79"
        assert normalize_cwe_id("CWE-89") == "CWE-89"


# ── Cross-reference same_as detection ──────────────────────────────────────

class TestVulnSameAs:
    def test_cross_reference_links(self):
        pairs = detect_vuln_same_as([
            {"vuln_id": "CVE-2024-5184", "references": ["https://github.com/advisories/GHSA-56xg-wfcc-g829"]},
            {"vuln_id": "GHSA-56xg-wfcc-g829", "references": []},
        ])
        assert len(pairs) == 1
        assert pairs[0].entity_type == "Vulnerability"
        assert {pairs[0].left_key, pairs[0].right_key} == {"CVE-2024-5184", "GHSA-56XG-WFCC-G829"}
        assert "cross-reference" in pairs[0].reason

    def test_same_title_and_cvss(self):
        pairs = detect_vuln_same_as([
            {"vuln_id": "CVE-2024-0010", "title": "PALChain command injection", "cvss_base_score": 9.8},
            {"vuln_id": "GHSA-aaaa-bbbb-cccc", "title": "PALChain command injection", "cvss_base_score": 9.8},
        ])
        assert len(pairs) == 1
        assert "identical title" in pairs[0].reason

    def test_no_false_positive_on_different_titles(self):
        pairs = detect_vuln_same_as([
            {"vuln_id": "CVE-2024-0011", "title": "A", "cvss_base_score": 7.5},
            {"vuln_id": "CVE-2024-0012", "title": "B", "cvss_base_score": 7.5},
        ])
        assert pairs == []

    def test_skips_missing_ids(self):
        pairs = detect_vuln_same_as([
            {"vuln_id": "", "title": "ghost"},
            {"vuln_id": "CVE-2024-0013", "title": "ghost"},
        ])
        assert pairs == []

    def test_same_cvss_vector_and_date(self):
        pairs = detect_vuln_same_as([
            {"vuln_id": "CVE-2024-0020", "cvss_vector": "AV:N/AC:L", "date_published": "2024-01-01"},
            {"vuln_id": "GHSA-zzzz-yyyy-xxxx", "cvss_vector": "AV:N/AC:L", "date_published": "2024-01-01"},
        ])
        assert len(pairs) == 1


class TestVendorSameAs:
    def test_alias_forms_linked(self):
        pairs = detect_vendor_same_as([
            {"name": "OpenAI"},
            {"name": "OpenAI Inc."},
            {"name": "Open AI"},
        ])
        # 3 names, all normalize to "openai" → C(3,2) = 3 pairs
        assert len(pairs) == 3
        assert all(p.entity_type == "Vendor" for p in pairs)

    def test_different_vendors_not_linked(self):
        pairs = detect_vendor_same_as([
            {"name": "OpenAI"},
            {"name": "Anthropic"},
        ])
        assert pairs == []
