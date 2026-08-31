"""OWASP classifier JSON parse + frozen prompt (no live LLM, no YAML)."""

from pathlib import Path

from owasp_classifier.llm import (
    ALLOWED_IDS,
    SYSTEM_PROMPT_PATH,
    load_system_prompt,
    parse_classification,
)


def test_allowed_ids_are_thirty():
    assert list(ALLOWED_IDS) == (
        [f"LLM{i:02d}" for i in range(1, 11)]
        + [f"ASI{i:02d}" for i in range(1, 11)]
        + [f"ML{i:02d}" for i in range(1, 11)]
    )


def test_frozen_prompt_on_disk():
    text = load_system_prompt()
    assert SYSTEM_PROMPT_PATH.is_file()
    assert "LLM01 — Prompt Injection" in text
    assert "Scenario #9" in text
    assert "Coverage matrix" not in text
    assert "Closed label set" in text
    assert text.strip().endswith("Return JSON only.")
    assert Path(SYSTEM_PROMPT_PATH).stat().st_size > 10_000


def test_parse_fenced_json():
    raw = """here you go
```json
{"labels": [{"id": "llm01", "confidence": 0.9, "why": "email overrides instructions"}], "abstain": false, "propose_new": null}
```
"""
    result = parse_classification(raw)
    assert not result.abstain
    assert result.labels[0].id == "LLM01"
    assert result.propose_new is None


def test_parse_drops_unknown_id_and_caps_labels():
    raw = {
        "labels": [
            {"id": "LLM01", "confidence": 0.4, "why": "a"},
            {"id": "NOTREAL", "confidence": 0.99, "why": "b"},
            {"id": "ASI01", "confidence": 0.8, "why": "c"},
            {"id": "LLM03", "confidence": 0.7, "why": "d"},
            {"id": "LLM10", "confidence": 0.6, "why": "e"},
        ],
        "abstain": True,
    }
    import json

    result = parse_classification(json.dumps(raw))
    assert [x.id for x in result.labels] == ["ASI01", "LLM03", "LLM10"]
    assert result.abstain is False


def test_parse_abstain_when_empty():
    result = parse_classification('{"labels": [], "abstain": false, "propose_new": null}')
    assert result.abstain is True
    assert result.labels == []
