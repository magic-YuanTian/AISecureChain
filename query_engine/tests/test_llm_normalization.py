"""Tests for the LLM-output normalization layer (no real LLM call)."""

import pytest

from extract_pipeline.llm import (
    _clean_entity,
    _clean_relation,
    _extract_json_blob,
    _normalize_graph,
)


# ── JSON extraction ─────────────────────────────────────────────────────────

def test_extract_fenced_json():
    raw = 'Some prose\n```json\n{"foo": 1}\n```\nmore'
    assert '{"foo": 1}' in _extract_json_blob(raw)


def test_extract_raw_json():
    raw = '   {"entities": []}   '
    assert _extract_json_blob(raw).strip() == '{"entities": []}'


def test_extract_handles_leading_prose():
    raw = 'Here is the result: {"x": 1}. Hope that helps.'
    assert _extract_json_blob(raw) == '{"x": 1}'


# ── Entity cleaning ─────────────────────────────────────────────────────────

def test_clean_entity_renames_class_name():
    out = _clean_entity({"class_name": "Vendor", "local_id": "v1", "attributes": {"name": "X"}})
    assert out["class"] == "Vendor"


def test_clean_entity_drops_null_attributes():
    out = _clean_entity({
        "class": "Vulnerability",
        "local_id": "v",
        "attributes": {"vuln_id": "CVE-2024-0001", "title": None, "description": "ok"},
    })
    assert "title" not in out["attributes"]
    assert out["attributes"]["description"] == "ok"


def test_clean_entity_missing_class_returns_none():
    assert _clean_entity({"local_id": "v"}) is None
    assert _clean_entity({"class": "Vendor"}) is None


def test_confidence_coerced():
    e = _clean_entity({"class": "Vendor", "local_id": "v", "confidence": 95})
    assert e["confidence"] == 0.95
    e = _clean_entity({"class": "Vendor", "local_id": "v", "confidence": "not-a-number"})
    assert e["confidence"] == 1.0


# ── Relation cleaning ──────────────────────────────────────────────────────

def test_clean_relation_renames_source_target():
    out = _clean_relation({"predicate": "produce", "source": "v1", "target": "s1"})
    assert out["subject"] == "v1"
    assert out["object"] == "s1"


def test_clean_relation_missing_fields():
    assert _clean_relation({"predicate": "produce"}) is None
    assert _clean_relation({"subject": "x", "object": "y"}) is None


# ── Graph-level normalization ──────────────────────────────────────────────

def test_prunes_relations_with_unknown_local_ids():
    shaped = _normalize_graph({
        "entities": [
            {"class": "Vendor", "local_id": "v1", "attributes": {"name": "X"}},
        ],
        "relations": [
            {"predicate": "produce", "subject": "v1", "object": "ghost"},
        ],
    })
    assert shaped["entities"] and len(shaped["entities"]) == 1
    assert shaped["relations"] == [], "Relation pointing to nonexistent local_id must be pruned"


def test_accepts_alternate_top_level_keys():
    shaped = _normalize_graph({
        "nodes": [{"class": "Vendor", "local_id": "v1", "attributes": {"name": "X"}}],
        "edges": [],
    })
    assert len(shaped["entities"]) == 1


def test_non_dict_input_is_safe():
    assert _normalize_graph(None) == {"entities": [], "relations": []}
    assert _normalize_graph([]) == {"entities": [], "relations": []}


def test_deeply_null_attrs_tolerated():
    """Regression: LLM sometimes emits {attributes: null}."""
    shaped = _normalize_graph({
        "entities": [{"class": "Vendor", "local_id": "v1", "attributes": None}],
        "relations": [],
    })
    assert shaped["entities"][0]["attributes"] == {}
