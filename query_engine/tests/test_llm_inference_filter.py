from extract_pipeline.llm import _filter_unsupported_inferences


def test_filter_drops_inferred_cwe_when_id_absent_from_chunk():
    graph = {
        "entities": [
            {
                "class": "Vulnerability",
                "local_id": "vuln1",
                "attributes": {"title": "Training data extraction"},
            },
            {
                "class": "VulnerabilityType",
                "local_id": "cwe1",
                "attributes": {"id": "CWE-200", "description": "Sensitive data exposure"},
            },
        ],
        "relations": [
            {"predicate": "isA_vulnType", "subject": "vuln1", "object": "cwe1"},
        ],
    }

    filtered = _filter_unsupported_inferences(
        graph,
        "The article discusses training data extraction, but no explicit CWE identifier.",
    )

    assert [e["local_id"] for e in filtered["entities"]] == ["vuln1"]
    assert filtered["relations"] == []


def test_filter_keeps_cwe_when_exact_id_appears_in_chunk():
    graph = {
        "entities": [
            {
                "class": "VulnerabilityType",
                "local_id": "cwe1",
                "attributes": {"id": "CWE-400", "description": "Resource consumption"},
            },
        ],
        "relations": [],
    }

    filtered = _filter_unsupported_inferences(
        graph,
        "The writeup explicitly maps the issue to CWE-400 resource consumption.",
    )

    assert filtered["entities"][0]["local_id"] == "cwe1"


def test_filter_drops_incidental_software_mentions():
    graph = {
        "entities": [
            {
                "class": "Software",
                "local_id": "s1",
                "attributes": {"name": "jq"},
                "evidence": "text describing the Linux jq utility for parsing JSON data",
            },
            {
                "class": "Software",
                "local_id": "s2",
                "attributes": {"name": "ChatGPT", "is_ai": True},
                "evidence": "OpenAI's ChatGPT models were vulnerable to repeated token attacks",
            },
        ],
        "relations": [
            {"predicate": "vulnerableTo", "subject": "s1", "object": "v1"},
            {"predicate": "vulnerableTo", "subject": "s2", "object": "v1"},
        ],
    }

    filtered = _filter_unsupported_inferences(graph, "ChatGPT repeated token attack")

    assert [e["local_id"] for e in filtered["entities"]] == ["s2"]
    assert filtered["relations"] == [
        {"predicate": "vulnerableTo", "subject": "s2", "object": "v1"},
    ]
