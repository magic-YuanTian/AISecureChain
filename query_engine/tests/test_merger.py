"""Merger tests — canonical keys, cross-chunk dedup, attribute union, partial flag."""

from extract_pipeline.merger import merge_graphs
from extract_pipeline.models import (
    ExtractedEntity,
    ExtractedRelation,
    ExtractionGraph,
)


def _mk(cls, lid, **attrs):
    return ExtractedEntity(**{"class": cls, "local_id": lid, "attributes": attrs})


def test_same_vuln_across_chunks_merges():
    g1 = ExtractionGraph(entities=[_mk("Vulnerability", "v", vuln_id="CVE-2024-0001", cvss_base_score=7.5)])
    g2 = ExtractionGraph(entities=[_mk("Vulnerability", "v", vuln_id="CVE-2024-0001", cvss_severity="HIGH", title="Foo")])
    ents, _rels = merge_graphs([g1, g2])
    vulns = [e for e in ents if e.class_name == "Vulnerability"]
    assert len(vulns) == 1
    a = vulns[0].attributes
    assert a["vuln_id"] == "CVE-2024-0001"
    assert a["cvss_base_score"] == 7.5
    assert a["cvss_severity"] == "HIGH"
    assert a["title"] == "Foo"


def test_attribute_union_list_fields():
    g1 = ExtractionGraph(entities=[_mk("Vulnerability", "v", vuln_id="CVE-X-1", references=["a", "b"])])
    g2 = ExtractionGraph(entities=[_mk("Vulnerability", "v", vuln_id="CVE-X-1", references=["b", "c"])])
    ents, _ = merge_graphs([g1, g2])
    assert ents[0].attributes["references"] == ["a", "b", "c"]


def test_longest_text_wins():
    g1 = ExtractionGraph(entities=[_mk("Vulnerability", "v", vuln_id="CVE-X-2", title="short")])
    g2 = ExtractionGraph(entities=[_mk("Vulnerability", "v", vuln_id="CVE-X-2", title="a much longer title")])
    ents, _ = merge_graphs([g1, g2])
    assert ents[0].attributes["title"] == "a much longer title"


def test_software_key_uses_vendor_context():
    g = ExtractionGraph(
        entities=[
            _mk("Vendor", "v1", name="OpenAI"),
            _mk("Software", "s1", name="ChatGPT"),
            _mk("Vendor", "v2", name="Anthropic"),
            _mk("Software", "s2", name="ChatGPT"),  # same name, different vendor
        ],
        relations=[
            ExtractedRelation(predicate="produce", subject="v1", object="s1"),
            ExtractedRelation(predicate="produce", subject="v2", object="s2"),
        ],
    )
    ents, rels = merge_graphs([g])
    software = [e for e in ents if e.class_name == "Software"]
    assert len(software) == 2, "Same product name under different vendors must NOT merge"
    assert all(r.predicate != "produce" or r.subject_key.startswith("Vendor::") for r in rels)


def test_missing_required_flags_partial():
    # Vulnerability with no vuln_id AND no title gets dropped
    g = ExtractionGraph(entities=[_mk("Vulnerability", "v")])
    ents, _ = merge_graphs([g])
    assert not ents, "Empty vuln should be dropped"

    # Vulnerability with a title but no official id: the system mints an
    # internal AISC id so the novel finding is captured (not partial).
    g2 = ExtractionGraph(entities=[_mk("Vulnerability", "v", title="Unnamed")])
    ents2, _ = merge_graphs([g2])
    assert len(ents2) == 1
    assert ents2[0].is_partial is False
    assert ents2[0].attributes["vuln_id"].startswith("AISC-")
    assert ents2[0].attributes.get("_minted_id") is True


def test_minted_vuln_id_is_deterministic():
    g1 = ExtractionGraph(entities=[_mk("Vulnerability", "v", title="Indirect prompt injection in Foo")])
    g2 = ExtractionGraph(entities=[_mk("Vulnerability", "v", title="Indirect prompt injection in Foo")])
    e1, _ = merge_graphs([g1])
    e2, _ = merge_graphs([g2])
    assert e1[0].attributes["vuln_id"] == e2[0].attributes["vuln_id"]


def test_relations_rewritten_to_canonical_keys():
    g = ExtractionGraph(
        entities=[
            _mk("Vulnerability", "vu", vuln_id="CVE-2024-0002"),
            _mk("VulnerabilityType", "cwe", id="CWE-79"),
        ],
        relations=[ExtractedRelation(predicate="isA_vulnType", subject="vu", object="cwe")],
    )
    _ents, rels = merge_graphs([g])
    assert len(rels) == 1
    assert rels[0].subject_key.startswith("Vulnerability::")
    assert rels[0].object_key.startswith("VulnerabilityType::")


def test_deduplicates_identical_relations_across_chunks():
    g1 = ExtractionGraph(
        entities=[
            _mk("Vulnerability", "vu", vuln_id="CVE-2024-0003"),
            _mk("VulnerabilityType", "cwe", id="CWE-79"),
        ],
        relations=[ExtractedRelation(predicate="isA_vulnType", subject="vu", object="cwe")],
    )
    g2 = ExtractionGraph(
        entities=[
            _mk("Vulnerability", "vu", vuln_id="CVE-2024-0003"),
            _mk("VulnerabilityType", "cwe", id="CWE-79"),
        ],
        relations=[ExtractedRelation(predicate="isA_vulnType", subject="vu", object="cwe")],
    )
    _ents, rels = merge_graphs([g1, g2])
    assert len(rels) == 1, "Duplicate relation should be deduped"
