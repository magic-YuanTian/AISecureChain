from extract_pipeline.merger import merge_graphs
from extract_pipeline.models import ExtractedEntity, ExtractedRelation, ExtractionGraph


def test_no_id_vulnerabilities_are_separated_by_title():
    graph = ExtractionGraph(entities=[
        ExtractedEntity(
            **{
                "class": "Vulnerability",
                "local_id": "v1",
                "attributes": {
                    "title": "Training data extraction vulnerability",
                    "description": "An attacker can recover training examples from model outputs.",
                },
            }
        ),
        ExtractedEntity(
            **{
                "class": "Vulnerability",
                "local_id": "v2",
                "attributes": {
                    "title": "Resource exhaustion attack",
                    "description": "Repeated requests consume model capacity until the service fails.",
                },
            }
        ),
    ])

    entities, _ = merge_graphs([graph])

    vuln_keys = sorted(e.canonical_key for e in entities if e.class_name == "Vulnerability")
    assert vuln_keys == [
        "Vulnerability::title::resource exhaustion attack",
        "Vulnerability::title::training data extraction vulnerability",
    ]


def test_vulnerability_type_without_id_uses_description_identity():
    graph = ExtractionGraph(entities=[
        ExtractedEntity(
            **{
                "class": "VulnerabilityType",
                "local_id": "vt1",
                "attributes": {"description": "Prompt injection"},
            }
        )
    ])

    entities, _ = merge_graphs([graph])

    assert entities[0].canonical_key == "VulnerabilityType::prompt injection"


def test_known_openai_model_names_share_vendor_key_without_relation():
    graph = ExtractionGraph(entities=[
        ExtractedEntity(
            **{
                "class": "Software",
                "local_id": "s1",
                "attributes": {"name": "GPT-4", "is_ai": True},
            }
        ),
        ExtractedEntity(
            **{
                "class": "Software",
                "local_id": "s2",
                "attributes": {"name": "GPT-4", "is_ai": True},
            }
        ),
    ])

    entities, _ = merge_graphs([graph])

    software_keys = [e.canonical_key for e in entities if e.class_name == "Software"]
    assert software_keys == ["Software::openai::gpt-4"]
