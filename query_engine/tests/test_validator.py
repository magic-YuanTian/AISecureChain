from __future__ import annotations

import asyncio

from extract_pipeline.models import CanonicalEntity, CanonicalRelation
from extract_pipeline.validator import validate_and_map_vulnerability_types


def test_validator_maps_prompt_disclosure_to_predefined_cwe(monkeypatch):
    async def _run():
        entities = [
            CanonicalEntity(
                class_name="Vulnerability",
                canonical_key="Vulnerability::title::bing-chat-prompt-injection",
                attributes={
                    "title": "Prompt injection attack on Bing Chat",
                    "description": "Bing Chat divulged its hidden initial prompt and internal instructions.",
                },
                evidence=["used a prompt injection attack to discover Bing Chat's initial prompt"],
            ),
            CanonicalEntity(
                class_name="VulnerabilityType",
                canonical_key="VulnerabilityType::prompt injection",
                attributes={"description": "Prompt injection"},
            ),
        ]
        relations = [
            CanonicalRelation(
                predicate="isA_vulnType",
                subject_key="Vulnerability::title::bing-chat-prompt-injection",
                object_key="VulnerabilityType::prompt injection",
            )
        ]

        from extract_pipeline import validator

        async def _no_llm(*args, **kwargs):  # noqa: ARG001
            return {}

        monkeypatch.setattr(validator, "_llm_validation_decisions", _no_llm)

        return await validate_and_map_vulnerability_types(
            entities,
            relations,
            source_text=(
                "Kevin Liu used prompt injection to make Bing Chat disclose its "
                "hidden initial prompt and internal instructions."
            ),
        )

    entities, relations, warnings = asyncio.run(_run())

    vuln_types = [e for e in entities if e.class_name == "VulnerabilityType"]
    assert len(vuln_types) == 1
    assert vuln_types[0].attributes["id"] == "CWE-200"
    vulns = [e for e in entities if e.class_name == "Vulnerability"]
    assert len(vulns) == 1
    assert vulns[0].attributes["vuln_id"].startswith("EXTRACT-")
    assert relations == [
        CanonicalRelation(
            predicate="isA_vulnType",
            subject_key=vulns[0].canonical_key,
            object_key="VulnerabilityType::cwe-200",
            confidence=1.0,
        )
    ]
    assert any("CWE-200" in warning for warning in warnings)


def test_validator_drops_vulnerability_rejected_by_self_validation(monkeypatch):
    async def _run():
        entities = [
            CanonicalEntity(
                class_name="Vulnerability",
                canonical_key="Vulnerability::title::unsupported",
                attributes={"title": "Unsupported issue"},
            ),
        ]

        from extract_pipeline import validator

        async def _reject(*args, **kwargs):  # noqa: ARG001
            return {
                "Vulnerability::title::unsupported": {
                    "keep": False,
                    "reason": "Not supported by source text",
                }
            }

        monkeypatch.setattr(validator, "_llm_validation_decisions", _reject)

        return await validate_and_map_vulnerability_types(
            entities,
            [],
            source_text="This page is unrelated marketing copy.",
        )

    entities, relations, warnings = asyncio.run(_run())

    assert entities == []
    assert relations == []
    assert any("dropped unsupported vulnerability" in warning for warning in warnings)


def test_validator_collapses_duplicate_no_id_vulnerabilities(monkeypatch):
    async def _run():
        entities = [
            CanonicalEntity(
                class_name="Vulnerability",
                canonical_key="Vulnerability::title::prompt-injection-attack-on-bing-chat",
                attributes={"title": "Prompt injection attack on Bing Chat"},
                evidence=["Kevin Liu used a prompt injection attack to discover Bing Chat's initial prompt"],
            ),
            CanonicalEntity(
                class_name="Vulnerability",
                canonical_key="Vulnerability::title::prompt-injection-attack-reaccessing-initial-prompt",
                attributes={"title": "Prompt injection attack on Bing Chat reaccessing initial prompt"},
                evidence=["Liu tried a different method and managed to reaccess the initial prompt"],
            ),
        ]

        from extract_pipeline import validator

        async def _no_llm(*args, **kwargs):  # noqa: ARG001
            return {}

        monkeypatch.setattr(validator, "_llm_validation_decisions", _no_llm)

        return await validate_and_map_vulnerability_types(
            entities,
            [],
            source_text=(
                "Kevin Liu used prompt injection against Bing Chat to disclose "
                "its hidden initial prompt."
            ),
            source_url="https://example.com/bing-chat-prompt-injection",
        )

    entities, relations, warnings = asyncio.run(_run())

    vulns = [e for e in entities if e.class_name == "Vulnerability"]
    assert len(vulns) == 1
    assert vulns[0].attributes["vuln_id"].startswith("EXTRACT-")
    assert vulns[0].canonical_key.startswith("Vulnerability::EXTRACT-")
    assert len([e for e in entities if e.class_name == "VulnerabilityType"]) == 1
    assert relations[0].subject_key == vulns[0].canonical_key
    assert any("Collapsed 2 duplicate" in warning for warning in warnings)


def test_validator_maps_prompt_injection_without_rce_to_llm_prompting_cwe(monkeypatch):
    async def _run():
        entities = [
            CanonicalEntity(
                class_name="Vulnerability",
                canonical_key="Vulnerability::title::chevy-chatbot",
                attributes={
                    "title": "Chevy Dealership AI Chatbot $1 Car Sale Incident",
                    "description": (
                        "Chris Bakke manipulated Chevrolet of Watsonville's "
                        "ChatGPT-powered chatbot into agreeing to sell a Chevy Tahoe for $1."
                    ),
                },
                evidence=["The attack was simple: prompt injection made the bot agree with anything."],
            )
        ]

        from extract_pipeline import validator

        async def _bad_llm_choice(*args, **kwargs):  # noqa: ARG001
            return {
                "Vulnerability::title::chevy-chatbot": {
                    "keep": True,
                    "mapped_type_id": "CWE-94",
                }
            }

        monkeypatch.setattr(validator, "_llm_validation_decisions", _bad_llm_choice)

        return await validate_and_map_vulnerability_types(
            entities,
            [],
            source_text="# Case Study of Chevy Dealership's AI Chatbot Tricked into $1 Car Sale",
            source_url="https://example.com/chevy",
        )

    entities, relations, _warnings = asyncio.run(_run())

    vuln_types = [e for e in entities if e.class_name == "VulnerabilityType"]
    assert vuln_types[0].attributes["id"] == "CWE-1427"
    assert relations[0].object_key == "VulnerabilityType::cwe-1427"
