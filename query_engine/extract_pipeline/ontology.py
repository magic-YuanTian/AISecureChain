"""
Ontology loader — reads the project TTL and merges it with human-authored
extraction hints to produce an LLM-ready schema.

If the ontology ever changes (new class, new property), the extraction prompt
automatically follows. CLASS_HINTS below is the human-tunable layer that lets
you refine per-class hints (descriptions, examples, required/optional attrs).
"""

from __future__ import annotations

import os
from typing import Any

from rdflib import Graph, RDF, RDFS, OWL, URIRef

ONT = "http://aisecurechain.org/ontology#"
TTL_PATH = os.path.join(os.path.dirname(__file__), "..", "ai_vuln_kb.ttl")


# ── Human-authored hints: the only place humans need to touch to tune extraction.
#    Structure: per class, we define identity, attributes, examples.
#    Attributes listed here are presented to the LLM in the system prompt.

CLASS_HINTS: dict[str, dict[str, Any]] = {
    "Vendor": {
        "identity": "name",
        "description": (
            "An organization that produces software or hardware. NOT threat actors: "
            "ransomware gangs, APT groups, or hacker collectives (e.g. 'Cl0p', 'Qilin', "
            "'Lazarus') are attackers, not vendors — never emit them as Vendor."
        ),
        "attributes": {
            "name": {
                "type": "string",
                "required": True,
                "hint": "Canonical vendor name, e.g. 'OpenAI', 'Meta', 'Google'.",
            },
        },
        "example": {"name": "OpenAI"},
    },
    "SoftwareType": {
        "identity": "name",
        "description": "A category of software, e.g. 'LLM', 'Framework', 'Library'.",
        "attributes": {
            "name": {"type": "string", "required": True, "hint": "Category name."},
        },
        "example": {"name": "LLM Framework"},
    },
    "Software": {
        "identity": "name",  # combined with vendor in canonicalization
        "description": (
            "A concrete, named software product that participates in the security issue "
            "described (the vulnerable/attacked/abused system, or a tool the attacker uses). "
            "NEVER emit generic categories as Software — 'AI', 'Generative AI', 'Agentic AI', "
            "'LLMs', 'chatbots', 'AI systems', 'AI agents', 'machine-learning systems' are "
            "concepts, not products. NEVER emit security/defense products that are only "
            "mentioned as mitigation or vendor marketing (EDR/XDR, CASB, firewalls, the "
            "blog author's own platform), and NEVER emit products cited only as historical "
            "analogies (e.g. SolarWinds/Kaseya in a think-piece about AI attacks)."
        ),
        "attributes": {
            "name": {"type": "string", "required": True, "hint": "Product name, e.g. 'LangChain'."},
            "is_ai": {
                "type": "boolean",
                "required": True,
                "hint": (
                    "True if this product is an AI/ML system, AI component, ML infrastructure, "
                    "AI agent, AI model, or AI-related library/tool. False for non-AI software "
                    "(e.g. Chrome, Linux, Apache). You MUST always set this field."
                ),
            },
            "software_type": {
                "type": "string",
                "required": False,
                "hint": (
                    "Classify the software into exactly one of these categories: "
                    "'Application' (end-user product), 'AI Component' (AI module/plugin within a larger system), "
                    "'ML Infrastructure' (training/serving/pipeline platform), 'Library' (reusable code package), "
                    "'Agent' (autonomous AI agent or agentic system), 'Model' (foundation model or fine-tuned model), "
                    "'Skill' (specific capability/tool of an AI agent), 'Database' (data storage system), "
                    "'Dataset' (training/evaluation dataset). You MUST always set this field."
                ),
            },
            "role": {
                "type": "string",
                "required": False,
                "hint": (
                    "The product's role in THIS article's security story. Exactly one of: "
                    "'affected' (the vulnerable / attacked / abused system), "
                    "'tool' (software the attacker uses to conduct the attack), "
                    "'defense' (security product mentioned as detection/mitigation), "
                    "'mentioned' (background, comparison, analogy, or marketing mention only). "
                    "You MUST always set this field. Only 'affected' and 'tool' software "
                    "will be kept in the knowledge base."
                ),
            },
        },
        "example": {"name": "LangChain", "is_ai": True, "software_type": "Library", "role": "affected"},
    },
    "License": {
        "identity": "name",
        "description": "A software license, e.g. 'MIT', 'Apache-2.0'.",
        "attributes": {
            "name": {"type": "string", "required": True, "hint": "Canonical license ID."},
        },
        "example": {"name": "Apache-2.0"},
    },
    "Version": {
        "identity": "version_string",  # plus software binding
        "description": "A specific version of a software product. Emit one Version entity per mentioned version.",
        "attributes": {
            "version_string": {
                "type": "string",
                "required": True,
                "hint": "Version string as it appears in the text, e.g. '1.2.3', '0.0.331', 'before 2.1'.",
            },
        },
        "example": {"version_string": "0.0.331"},
    },
    "VulnerabilityType": {
        "identity": "id",
        "description": "A weakness class (typically a CWE).",
        "attributes": {
            "id": {
                "type": "string",
                "required": True,
                "hint": "CWE identifier like 'CWE-79', 'CWE-89'.",
            },
            "description": {"type": "string", "required": False, "hint": "Short description of the weakness."},
        },
        "example": {"id": "CWE-79", "description": "Cross-site Scripting"},
    },
    "Vulnerability": {
        "identity": "vuln_id",
        "description": (
            "A security vulnerability. Includes CVEs, GitHub Security Advisories, "
            "AVID records, huntr reports, etc. Emit one per distinct vulnerability mentioned."
        ),
        "attributes": {
            "vuln_id": {
                "type": "string",
                "required": True,
                "hint": (
                    "The official identifier exactly as it appears, e.g. "
                    "'CVE-2024-5184', 'GHSA-56xg-wfcc-g829', 'AVID-2023-V013'. "
                    "If no official id is present, set to null and we'll flag it as partial."
                ),
            },
            "title": {"type": "string", "required": False, "hint": "Short title/headline."},
            "description": {
                "type": "string",
                "required": True,
                "hint": (
                    "2–4 sentences stating the weakness as described in the source. "
                    "Required even for CVE/GHSA records — paraphrase the advisory or article; "
                    "do not leave empty."
                ),
            },
            "date_published": {"type": "string", "required": False, "hint": "ISO 8601 date."},
            "date_updated": {"type": "string", "required": False, "hint": "ISO 8601 date."},
            "cvss_base_score": {"type": "number", "required": False, "hint": "Numeric 0-10."},
            "cvss_severity": {"type": "string", "required": False, "hint": "LOW | MEDIUM | HIGH | CRITICAL."},
            "cvss_vector": {"type": "string", "required": False, "hint": "Full CVSS vector string."},
            "references": {"type": "list[string]", "required": False, "hint": "List of reference URLs."},
            "credit": {"type": "string", "required": False, "hint": "Researcher / reporter name."},
        },
        "example": {
            "vuln_id": "CVE-2024-5184",
            "title": "EmailGPT Prompt Injection",
            "description": (
                "The EmailGPT API accepts a crafted prompt that overrides intended "
                "instructions and can leak the system prompt."
            ),
            "cvss_severity": "HIGH",
            "cvss_base_score": 7.5,
        },
    },
    "Attack": {
        "identity": "name",
        "description": (
            "The METHOD an adversary uses to exploit a vulnerability — the HOW. "
            "The outcome the attacker achieves (remote code execution, privilege "
            "escalation, data exfiltration, …) is an Impact, NOT an Attack. Emit only "
            "techniques the article actually describes being used — not generic "
            "techniques implied by a CWE name. NEVER emit CVSS metric field labels "
            "('Attack Vector', 'Attack Complexity', 'Privileges Required', "
            "'User Interaction') — those are score-table headers, not attacks."
        ),
        "attributes": {
            "name": {
                "type": "string",
                "required": True,
                "hint": (
                    "Normalize to the closest STANDARD technique name whenever one fits: "
                    "'Prompt Injection', 'Indirect Prompt Injection', 'Visual Prompt Injection', "
                    "'Jailbreak', 'Data Poisoning', 'Model Backdoor', 'Supply Chain Attack', "
                    "'Deserialization Attack', 'Code Injection', 'SQL Injection', "
                    "'Template Injection', 'ASCII Smuggling', 'Social Engineering', "
                    "'Phishing', 'Adversarial Example', 'Model Extraction'. "
                    "Prefer the general technique over a page-specific phrasing "
                    "(e.g. 'Backdooring ResNet' → 'Model Backdoor'). Only invent a new "
                    "name when no standard technique fits."
                ),
            },
            "description": {"type": "string", "required": False, "hint": "How the attack works, in one sentence."},
        },
        "example": {"name": "Indirect Prompt Injection"},
    },
    "Impact": {
        "identity": "name",
        "description": (
            "The harm the ATTACKER achieves by exploiting a vulnerability. "
            "It must be a bad outcome for the victim, stated in text that describes "
            "the ATTACK or its consequences. NEVER derive an Impact from a sentence "
            "that recommends a defence — mitigation, hardening, best-practice and "
            "'how to protect yourself' passages describe what defenders should do, "
            "not what an attacker achieved ('design system prompts with clear "
            "instruction hierarchies' is advice, not an Instruction Override "
            "impact). Also NEVER emit: defensive benefits or vendor value "
            "propositions ('Threat Detection', 'Reduced Incident Response Costs', "
            "'Operational Efficiency'), CVSS field labels ('Confidentiality', "
            "'Integrity', 'Availability'), abstract trends ('Increased Breach "
            "Costs'), or attack techniques (those are Attack)."
        ),
        "attributes": {
            "name": {
                "type": "string",
                "required": True,
                "hint": (
                    "Use the MOST SPECIFIC standard impact name the text supports: "
                    "'Remote Code Execution', 'Arbitrary Code Execution', 'Data Exfiltration', "
                    "'Information Disclosure', 'System Prompt Disclosure', 'Memory Poisoning', "
                    "'Credential Theft', 'Privilege Escalation', 'Denial of Service', "
                    "'Financial Loss', 'Model Theft', 'Model Manipulation', 'Malware Delivery', "
                    "'Instruction Override', 'Misinformation', 'Persistence', "
                    "'Harmful Content Generation'. Generic names like 'Unauthorized "
                    "Access' / 'Unauthorized Actions' are a LAST RESORT — use them only "
                    "when the text states no more specific harm, and never alongside a "
                    "more specific Impact that already covers the same harm."
                ),
            },
            "description": {"type": "string", "required": False, "hint": "What the impact entails, in one sentence."},
        },
        "example": {"name": "Remote Code Execution"},
    },
}


# ── Relation hints (supplement what's declared in TTL) ────────────────────

RELATION_HINTS: dict[str, str] = {
    "produce": "A Vendor produces a Software (emit when vendor/product ownership is stated).",
    "isA_softwareType": "A Software is-a SoftwareType (categorisation).",
    "hasVersion": "A Software has a specific Version.",
    "hasLicense": "A Version has a License.",
    "dependsOn": "A Version depends on another Version.",
    "vulnerableTo": "A Version is vulnerable to a Vulnerability.",
    "isA_vulnType": "A Vulnerability is an instance of a VulnerabilityType (CWE).",
    "exploits": "An Attack exploits a Vulnerability (link the attack method to the vuln it abuses).",
    "resultsIn": "A Vulnerability results in an Impact (link the vuln to the consequence of exploiting it).",
}


# ── TTL parsing ────────────────────────────────────────────────────────────

_cached_schema: dict[str, Any] | None = None


def _parse_ttl() -> tuple[list[str], list[dict[str, str]]]:
    """Return (class_names, object_properties) from the TTL T-Box."""
    if not os.path.exists(TTL_PATH):
        # Fall back to hints-only mode.
        return list(CLASS_HINTS.keys()), [
            {"predicate": p, "domain": "", "range": ""} for p in RELATION_HINTS
        ]

    g = Graph()
    g.parse(TTL_PATH, format="turtle")

    classes: list[str] = []
    for s, _, _ in g.triples((None, RDF.type, OWL.Class)):
        if str(s).startswith(ONT):
            classes.append(str(s)[len(ONT):])

    relations: list[dict[str, str]] = []
    for p, _, _ in g.triples((None, RDF.type, OWL.ObjectProperty)):
        pstr = str(p)
        if not pstr.startswith(ONT):
            continue
        pname = pstr[len(ONT):]
        dom = rng = ""
        for _, _, d in g.triples((URIRef(pstr), RDFS.domain, None)):
            if str(d).startswith(ONT):
                dom = str(d)[len(ONT):]
                break
        for _, _, r in g.triples((URIRef(pstr), RDFS.range, None)):
            if str(r).startswith(ONT):
                rng = str(r)[len(ONT):]
                break
        relations.append({"predicate": pname, "domain": dom, "range": rng})

    return classes, relations


def load_ontology_schema(force_reload: bool = False) -> dict[str, Any]:
    """Return the LLM-ready ontology schema (classes + relations with hints)."""
    global _cached_schema
    if _cached_schema is not None and not force_reload:
        return _cached_schema

    ttl_classes, ttl_relations = _parse_ttl()

    # Reference-only classes: present in the ontology/RDF but NOT something the
    # extraction LLM should emit from a web page. (Currently none — Attack and
    # Impact are extracted directly from advisory text.)
    NON_EXTRACTABLE: set[str] = set()

    # Merge TTL classes + CLASS_HINTS. TTL is source of truth for class list,
    # CLASS_HINTS provides attribute/description metadata.
    all_class_names = sorted(
        (set(ttl_classes) | set(CLASS_HINTS.keys())) - NON_EXTRACTABLE
    )
    classes: dict[str, dict[str, Any]] = {}
    for c in all_class_names:
        hint = CLASS_HINTS.get(c, {})
        classes[c] = {
            "name": c,
            "identity": hint.get("identity", "name"),
            "description": hint.get("description", f"Ontology class '{c}'."),
            "attributes": hint.get("attributes", {}),
            "example": hint.get("example", {}),
        }

    # Merge TTL relations + RELATION_HINTS, skipping any relation that touches a
    # reference-only class (those edges are seeded from catalogs, not extracted).
    ttl_relations = [
        r for r in ttl_relations
        if r.get("domain") not in NON_EXTRACTABLE and r.get("range") not in NON_EXTRACTABLE
    ]
    ttl_rel_preds = {r["predicate"] for r in ttl_relations}
    all_relations: list[dict[str, Any]] = []
    for r in ttl_relations:
        all_relations.append({
            **r,
            "description": RELATION_HINTS.get(r["predicate"], ""),
        })
    # Add relation hints present only in the hints file
    for pred, desc in RELATION_HINTS.items():
        if pred not in ttl_rel_preds:
            all_relations.append({"predicate": pred, "domain": "", "range": "", "description": desc})

    _cached_schema = {"classes": classes, "relations": all_relations}
    return _cached_schema


# ── Prompt formatting ─────────────────────────────────────────────────────

def format_ontology_for_prompt(schema: dict[str, Any] | None = None) -> str:
    """Render the ontology in a compact, LLM-friendly way."""
    schema = schema or load_ontology_schema()

    lines: list[str] = ["ONTOLOGY CLASSES (entities to look for):"]
    for cname, cinfo in schema["classes"].items():
        lines.append(f"\n- {cname} — {cinfo['description']}")
        lines.append(f"  identity: {cinfo['identity']}")
        attrs = cinfo.get("attributes", {})
        if attrs:
            lines.append("  attributes:")
            for aname, ameta in attrs.items():
                req = "required" if ameta.get("required") else "optional"
                lines.append(f"    * {aname} ({ameta.get('type', 'string')}, {req}): {ameta.get('hint', '')}")
        if cinfo.get("example"):
            import json as _json
            lines.append(f"  example: {_json.dumps(cinfo['example'])}")

    lines.append("\nONTOLOGY RELATIONS (how entities connect):")
    for r in schema["relations"]:
        if r.get("domain") or r.get("range"):
            lines.append(f"- {r['predicate']}: {r.get('domain', '?')} -> {r.get('range', '?')}  ({r.get('description', '')})")
        else:
            lines.append(f"- {r['predicate']}: {r.get('description', '')}")
    return "\n".join(lines)


def ontology_class_names() -> list[str]:
    return list(load_ontology_schema()["classes"].keys())


def class_identity_attr(class_name: str) -> str:
    return load_ontology_schema()["classes"].get(class_name, {}).get("identity", "name")


def class_attribute_names(class_name: str) -> list[str]:
    cls = load_ontology_schema()["classes"].get(class_name, {})
    return list(cls.get("attributes", {}).keys())


def required_attributes(class_name: str) -> list[str]:
    cls = load_ontology_schema()["classes"].get(class_name, {})
    return [a for a, meta in cls.get("attributes", {}).items() if meta.get("required")]
