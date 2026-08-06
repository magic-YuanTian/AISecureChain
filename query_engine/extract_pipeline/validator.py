"""Post-extraction validation and vulnerability-type mapping.

The extractor is intentionally permissive: it lets the LLM produce partial
records, then normalizes them. This module is the stricter post-pass before
preview/persist:

* ask the model to re-check extracted vulnerabilities against the source text;
* force every kept Vulnerability to point at a predefined VulnerabilityType;
* remove ad-hoc vulnerability-type labels that are not in the ontology data.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from rdflib import RDF, RDFS, Graph, URIRef

from .models import CanonicalEntity, CanonicalRelation
from .ontology import ONT, TTL_PATH


@dataclass(frozen=True)
class PredefinedVulnerabilityType:
    id: str
    description: str


_TOKEN_RE = re.compile(r"[a-z0-9]+")
_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in",
    "into", "is", "it", "of", "on", "or", "that", "the", "their", "this",
    "to", "via", "with", "without", "cwe", "improper", "incorrect",
}


def _type_key(type_id: str) -> str:
    return f"VulnerabilityType::{type_id.strip().lower()}"


def _tokens(text: str) -> set[str]:
    return {t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS and len(t) > 2}


def _has_code_execution_signal(text: str) -> bool:
    return bool(re.search(r"code execution|execute|rce|command|arbitrary code", text.lower()))


def _merge_attrs(base: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in incoming.items():
        if value in (None, "", []):
            continue
        current = out.get(key)
        if current in (None, "", []):
            out[key] = value
        elif isinstance(current, list) and isinstance(value, list):
            out[key] = current + [item for item in value if item not in current]
        elif isinstance(current, str) and isinstance(value, str) and len(value) > len(current):
            out[key] = value
    return out


def _title_tokens(vuln: CanonicalEntity) -> set[str]:
    return _tokens("\n".join([
        str(vuln.attributes.get("title") or ""),
        str(vuln.attributes.get("description") or ""),
        " ".join(vuln.evidence[:3]),
    ]))


def _has_official_id(vuln: CanonicalEntity) -> bool:
    """True only for externally-issued ids (CVE/GHSA/AVID…). Minted AISC-/EXTRACT-
    ids are internal fallbacks and must NOT shield a record from duplicate
    collapsing — the merger mints them *before* validation runs."""
    vid = str(vuln.attributes.get("vuln_id") or "").strip().upper()
    if not vid:
        return False
    if vuln.attributes.get("_minted_id"):
        return False
    return not vid.startswith(("AISC-", "EXTRACT-"))


def _looks_like_same_no_id_vuln(a: CanonicalEntity, b: CanonicalEntity) -> bool:
    a_tokens = _title_tokens(a)
    b_tokens = _title_tokens(b)
    if not a_tokens or not b_tokens:
        return False
    overlap = len(a_tokens & b_tokens)
    smaller = min(len(a_tokens), len(b_tokens))
    # Lower threshold to collapse more aggressively — blog posts about a single
    # topic often yield multiple partially-overlapping vulnerability extracts.
    if overlap >= 2 and overlap / smaller >= 0.35:
        return True
    # Anchor words that indicate the same topic area
    ai_anchors = {
        "prompt", "injection", "jailbreak", "jailbreaking", "llm", "agent",
        "agentic", "rce", "exfiltration", "poisoning", "supply", "chain",
        "bing", "chat", "sydney", "copilot", "gemini", "claude",
    }
    shared_anchor = ai_anchors & a_tokens & b_tokens
    return len(shared_anchor) >= 2


def _generated_vuln_id(source_url: str, vuln: CanonicalEntity) -> str:
    seed = "|".join([
        source_url,
        str(vuln.attributes.get("title") or ""),
        str(vuln.attributes.get("description") or ""),
    ])
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12].upper()
    return f"EXTRACT-{digest}"


def _source_title_tokens(source_text: str) -> set[str]:
    for line in source_text.splitlines()[:30]:
        stripped = line.strip()
        if stripped.startswith("Title:"):
            return _tokens(stripped.removeprefix("Title:"))
        if stripped.startswith("# "):
            return _tokens(stripped[2:])
    return set()


def _representative_score(vuln: CanonicalEntity, source_title_tokens: set[str]) -> int:
    title = str(vuln.attributes.get("title") or "")
    desc = str(vuln.attributes.get("description") or "")
    evidence = " ".join(vuln.evidence[:3])
    title_overlap = len(_tokens(title) & source_title_tokens)
    return title_overlap * 100 + len(title) * 2 + len(desc) + len(evidence)


@lru_cache(maxsize=1)
def predefined_vulnerability_types() -> dict[str, PredefinedVulnerabilityType]:
    """Load vulnerability types that are already defined in the project TTL."""
    graph = Graph()
    graph.parse(TTL_PATH, format="turtle")

    vuln_type_uri = URIRef(ONT + "VulnerabilityType")
    name_uri = URIRef(ONT + "name")
    desc_uri = URIRef(ONT + "description")

    registry: dict[str, PredefinedVulnerabilityType] = {}
    for subject in graph.subjects(RDF.type, vuln_type_uri):
        raw_id = (
            graph.value(subject, name_uri)
            or graph.value(subject, RDFS.label)
            or str(subject).rsplit("/", 1)[-1]
        )
        type_id = str(raw_id).strip().upper()
        if not type_id:
            continue
        desc = graph.value(subject, desc_uri)
        registry[type_id] = PredefinedVulnerabilityType(
            id=type_id,
            description=str(desc).strip() if desc else type_id,
        )
    return registry


def _entity_text(entity: CanonicalEntity) -> str:
    parts: list[str] = [entity.canonical_key]
    for value in entity.attributes.values():
        if isinstance(value, list):
            parts.extend(str(v) for v in value)
        elif value is not None:
            parts.append(str(value))
    parts.extend(entity.evidence)
    return "\n".join(parts)


# CWEs that are never appropriate for AI/LLM-related vulnerability articles.
# These are hardware/low-level/irrelevant types that appear via token overlap noise.
_AI_IRRELEVANT_CWES = frozenset({
    "CWE-120",  # Buffer Overflow
    "CWE-121",  # Stack-based Buffer Overflow
    "CWE-122",  # Heap-based Buffer Overflow
    "CWE-123",  # Write-what-where Condition
    "CWE-124",  # Buffer Underwrite
    "CWE-125",  # Out-of-bounds Read
    "CWE-126",  # Buffer Over-read
    "CWE-127",  # Buffer Under-read
    "CWE-130",  # Improper Handling of Length Parameter Inconsistency
    "CWE-369",  # Divide By Zero
    "CWE-1049", # Excessive Data Query Operations in a Large Data Table
    "CWE-1057", # Data Access Operations Outside of Expected Data Manager Component
    "CWE-1088", # Synchronous Access of Remote Resource without Timeout
    "CWE-1254", # Incorrect Comparison Logic Granularity (hardware)
    "CWE-304",  # Missing Critical Step in Authentication
    "CWE-444",  # HTTP Request Smuggling
    "CWE-119",  # Improper Restriction of Operations within Bounds of a Memory Buffer
    "CWE-134",  # Use of Externally-Controlled Format String
    "CWE-787",  # Out-of-bounds Write
    "CWE-788",  # Access of Memory Location After End of Buffer
    "CWE-416",  # Use After Free
})


def _candidate_types(
    text: str,
    registry: dict[str, PredefinedVulnerabilityType],
    *,
    limit: int = 12,
) -> list[PredefinedVulnerabilityType]:
    """Return a small candidate set so the validation prompt stays compact."""
    text_upper = text.upper()
    candidates: dict[str, float] = {}

    # Explicit CWE IDs mentioned in the text get highest priority
    for cwe in _CWE_RE.findall(text_upper):
        if cwe in registry:
            candidates[cwe] = candidates.get(cwe, 0.0) + 100.0

    lowered = text.lower()

    # ── AI/LLM-specific keyword rules (high-confidence mappings) ──
    if re.search(r"prompt injection|indirect injection", lowered):
        candidates["CWE-1427"] = candidates.get("CWE-1427", 0.0) + 150.0
        if re.search(r"secret|sensitive|divulg|disclos|expos|leak|initial prompt|instruction|system prompt", lowered):
            candidates["CWE-200"] = candidates.get("CWE-200", 0.0) + 180.0
        if _has_code_execution_signal(lowered):
            candidates["CWE-94"] = candidates.get("CWE-94", 0.0) + 120.0
        candidates["CWE-20"] = candidates.get("CWE-20", 0.0) + 10.0

    if re.search(r"jailbreak|guardrail bypass|safety bypass|alignment bypass", lowered):
        candidates["CWE-1427"] = candidates.get("CWE-1427", 0.0) + 140.0
        candidates["CWE-693"] = candidates.get("CWE-693", 0.0) + 60.0  # Protection Mechanism Failure

    if re.search(r"excessive agency|autonomous|agentic.*threat|agent.*hijack|agent.*abuse", lowered):
        candidates["CWE-250"] = candidates.get("CWE-250", 0.0) + 80.0  # Execution with Unnecessary Privileges
        candidates["CWE-1427"] = candidates.get("CWE-1427", 0.0) + 40.0

    if re.search(r"data poison|model poison|training data.*tamper|backdoor.*model", lowered):
        candidates["CWE-506"] = candidates.get("CWE-506", 0.0) + 80.0  # Embedded Malicious Code
        candidates["CWE-20"] = candidates.get("CWE-20", 0.0) + 40.0

    if re.search(r"supply.?chain|compromised.*model|malicious.*package|dependency.*attack", lowered):
        candidates["CWE-506"] = candidates.get("CWE-506", 0.0) + 80.0
        candidates["CWE-1395"] = candidates.get("CWE-1395", 0.0) + 60.0  # Dependency on Vulnerable Third-Party Component

    if re.search(r"model (theft|extraction|steal|distill)|model.*(exfiltrat|clone)", lowered):
        candidates["CWE-200"] = candidates.get("CWE-200", 0.0) + 80.0
        candidates["CWE-359"] = candidates.get("CWE-359", 0.0) + 60.0

    if re.search(r"api.?key.*expos|credential.*leak|token.*exfiltrat|key.*expos", lowered):
        candidates["CWE-200"] = candidates.get("CWE-200", 0.0) + 100.0
        candidates["CWE-798"] = candidates.get("CWE-798", 0.0) + 60.0  # Use of Hard-coded Credentials

    if re.search(r"insecure output|output handling|unsanitized output", lowered):
        candidates["CWE-116"] = candidates.get("CWE-116", 0.0) + 80.0  # Improper Encoding or Escaping

    if re.search(r"system prompt leak|prompt leak|system prompt expos", lowered):
        candidates["CWE-200"] = candidates.get("CWE-200", 0.0) + 100.0
        candidates["CWE-497"] = candidates.get("CWE-497", 0.0) + 60.0

    if re.search(r"rce|remote code execution|arbitrary code|code execution", lowered):
        candidates["CWE-94"] = candidates.get("CWE-94", 0.0) + 100.0

    if re.search(r"privilege escalat|escalat.*privilege", lowered):
        candidates["CWE-269"] = candidates.get("CWE-269", 0.0) + 80.0

    if re.search(r"ssrf|server.?side request forgery", lowered):
        candidates["CWE-918"] = candidates.get("CWE-918", 0.0) + 80.0

    if re.search(r"path traversal|directory traversal|\.\.\/", lowered):
        candidates["CWE-22"] = candidates.get("CWE-22", 0.0) + 80.0

    if re.search(r"deserializ|insecure deserial", lowered):
        candidates["CWE-502"] = candidates.get("CWE-502", 0.0) + 80.0

    if re.search(r"resource|billing|cost|quota|denial of service|dos|unbounded consumption", lowered):
        candidates["CWE-400"] = candidates.get("CWE-400", 0.0) + 60.0

    if re.search(r"xss|cross.?site scripting", lowered):
        candidates["CWE-79"] = candidates.get("CWE-79", 0.0) + 60.0
    if re.search(r"sql injection", lowered):
        candidates["CWE-89"] = candidates.get("CWE-89", 0.0) + 60.0
    if re.search(r"command injection|shell injection|os command", lowered):
        candidates["CWE-78"] = candidates.get("CWE-78", 0.0) + 60.0

    if re.search(r"access control|unauthori[sz]ed access|permission bypass|auth.*bypass", lowered):
        candidates["CWE-284"] = candidates.get("CWE-284", 0.0) + 60.0
        candidates["CWE-288"] = candidates.get("CWE-288", 0.0) + 40.0

    # Trusting *who sent* a message instead of *where it runs* — the classic
    # extension/postMessage/CORS confused-deputy shape.
    if re.search(
        r"origin (validation|verification|check)|trusts? the origin|"
        r"verify(ing)? (the )?(sender|source|origin)|execution context|"
        r"same.?origin|postmessage|message handler|cross.?origin|"
        r"without verifying its (owner|origin|sender)",
        lowered,
    ):
        candidates["CWE-346"] = candidates.get("CWE-346", 0.0) + 150.0
        candidates["CWE-940"] = candidates.get("CWE-940", 0.0) + 90.0
        candidates["CWE-284"] = candidates.get("CWE-284", 0.0) + 40.0

    if re.search(r"lax permission|excessive permission|over.?privileg|"
                 r"zero.?permission|inherit(s|ed)? the (capabilit|privileg)|"
                 r"privileged command|permission model", lowered):
        candidates["CWE-284"] = candidates.get("CWE-284", 0.0) + 80.0
        candidates["CWE-250"] = candidates.get("CWE-250", 0.0) + 60.0
        candidates["CWE-276"] = candidates.get("CWE-276", 0.0) + 40.0

    if re.search(r"confirmation (bypass|forg)|forge.*(approval|consent)|"
                 r"user (approval|consent).*(bypass|forg|spoof)|"
                 r"bypass.*(user )?(confirmation|approval|consent)", lowered):
        candidates["CWE-863"] = candidates.get("CWE-863", 0.0) + 70.0
        candidates["CWE-693"] = candidates.get("CWE-693", 0.0) + 50.0

    # ── Token-overlap matching (lower weight, filtered) ──
    # Require >=2 shared tokens: a single shared generic word ("execution",
    # "data") is noise, and because ties are broken by string-sorted id it
    # would let an arbitrary low-numbered CWE win (CWE-1112 beating CWE-346
    # on the word "execution"). Keyword rules above carry the real signal.
    query_tokens = _tokens(text)
    if query_tokens:
        for type_id, vt in registry.items():
            if type_id in _AI_IRRELEVANT_CWES:
                continue
            vt_tokens = _tokens(f"{vt.id} {vt.description}")
            overlap = len(query_tokens & vt_tokens)
            if overlap >= 2:
                candidates[type_id] = candidates.get(type_id, 0.0) + float(overlap)

    # Remove irrelevant CWEs that crept in via token overlap
    for cwe in _AI_IRRELEVANT_CWES:
        # Only remove if they weren't explicitly mentioned in the text
        if cwe not in text_upper:
            candidates.pop(cwe, None)

    ranked = [
        registry[type_id]
        for type_id, _ in sorted(candidates.items(), key=lambda item: (-item[1], item[0]))
        if type_id in registry
    ]
    if ranked:
        return ranked[:limit]

    fallback = [registry[cwe] for cwe in ("CWE-1427", "CWE-200", "CWE-20", "CWE-94") if cwe in registry]
    return fallback[:limit]


def _existing_type_for_vuln(
    vuln: CanonicalEntity,
    entities_by_key: dict[str, CanonicalEntity],
    relations: list[CanonicalRelation],
    registry: dict[str, PredefinedVulnerabilityType],
) -> str | None:
    for rel in relations:
        if rel.predicate != "isA_vulnType" or rel.subject_key != vuln.canonical_key:
            continue
        ent = entities_by_key.get(rel.object_key)
        if not ent:
            continue
        type_id = str(ent.attributes.get("id") or "").strip().upper()
        if type_id in registry:
            return type_id
    return None


def _parse_validation_json(raw: str) -> dict[str, Any] | None:
    text = raw.strip()
    if "```" in text:
        match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
        if match:
            text = match.group(1).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        text = text[start : end + 1]
    try:
        parsed = json.loads(text)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


async def _llm_validation_decisions(
    source_text: str,
    vulnerabilities: list[CanonicalEntity],
    candidates_by_vuln: dict[str, list[PredefinedVulnerabilityType]],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Ask the LLM to validate vulnerability records and choose allowed types.

    Returns ``(decisions_by_key, usage)``.
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from utils.openai_api import empty_usage  # type: ignore

    if not vulnerabilities:
        return {}, empty_usage()

    from .llm import _call_llm  # local import avoids making llm import validator

    source_excerpt = source_text[:24000]
    payload = []
    for vuln in vulnerabilities:
        payload.append({
            "key": vuln.canonical_key,
            "attributes": vuln.attributes,
            "evidence": vuln.evidence[:5],
            "candidate_vulnerability_types": [
                {"id": vt.id, "description": vt.description}
                for vt in candidates_by_vuln[vuln.canonical_key]
            ],
        })

    messages = [
        {
            "role": "system",
            "content": (
                "You are validating a security knowledge-base extraction. "
                "Use only the supplied source text. For each extracted Vulnerability, "
                "decide whether it is supported by the source and choose exactly one "
                "mapped_type_id from that vulnerability's candidate_vulnerability_types. "
                "Prefer the most specific CWE. Key mapping rules:\n"
                "- Prompt injection / jailbreaking / indirect injection → CWE-1427\n"
                "- Prompt injection leading to data disclosure / system prompt leak → CWE-200\n"
                "- Prompt injection leading to code execution → CWE-94\n"
                "- API key / credential exposure → CWE-200\n"
                "- Excessive agency / autonomous agent abuse → CWE-250\n"
                "- Supply chain / model poisoning → CWE-506\n"
                "- Resource exhaustion / billing abuse → CWE-400\n"
                "- RCE / arbitrary code execution → CWE-94\n"
                "- Privilege escalation → CWE-269\n"
                "If a blog/case study describes one central vulnerability or attack "
                "technique with examples, variations, or mitigations, keep ONLY the "
                "central finding (set keep=false for the derivative entries). "
                "Only keep multiple vulnerabilities when they are genuinely distinct "
                "security issues. In particular: when one record carries an official "
                "id (CVE-/GHSA-/AVID-) and other records with internal ids (AISC-, "
                "EXTRACT-) or no id describe the same finding, its attack stages, "
                "sub-techniques, or consequences, keep ONLY the official-id record "
                "and set keep=false for the internal-id duplicates. Conversely, an "
                "article documenting a real-world abuse, misuse, jailbreak, or novel "
                "attack technique against an AI system IS a supported finding — keep "
                "its internal-id vulnerability record even though it has no CVE. "
                "Return JSON only."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "response_schema": {
                        "vulnerabilities": [
                            {
                                "key": "canonical key from input",
                                "keep": True,
                                "mapped_type_id": "one candidate id",
                                "corrected_title": "optional better title",
                                "reason": "short reason",
                            }
                        ]
                    },
                    "source_text": source_excerpt,
                    "extracted_vulnerabilities": payload,
                },
                ensure_ascii=True,
            ),
        },
    ]

    try:
        raw, usage = await asyncio.to_thread(_call_llm, messages, 0.0)
    except Exception:
        return {}, empty_usage()

    parsed = _parse_validation_json(raw)
    if not parsed:
        return {}, usage
    rows = parsed.get("vulnerabilities")
    if not isinstance(rows, list):
        return {}, usage

    decisions: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = row.get("key")
        if isinstance(key, str):
            decisions[key] = row
    return decisions, usage


async def validate_and_map_vulnerability_types(
    entities: list[CanonicalEntity],
    relations: list[CanonicalRelation],
    *,
    source_text: str,
    source_url: str = "",
) -> tuple[list[CanonicalEntity], list[CanonicalRelation], list[str], dict[str, Any]]:
    """Validate final extraction and force every Vulnerability to a predefined type.

    Returns ``(entities, relations, warnings, validation_usage)``.
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from utils.openai_api import empty_usage  # type: ignore

    registry = predefined_vulnerability_types()
    if not registry:
        return (
            entities,
            relations,
            ["No predefined VulnerabilityType registry found; skipped type mapping."],
            empty_usage(),
        )

    warnings: list[str] = []
    vulnerabilities = [e for e in entities if e.class_name == "Vulnerability"]
    entities_by_key = {e.canonical_key: e for e in entities}

    candidates_by_vuln: dict[str, list[PredefinedVulnerabilityType]] = {}
    for vuln in vulnerabilities:
        text = _entity_text(vuln)
        candidates_by_vuln[vuln.canonical_key] = _candidate_types(text, registry)

    decisions, validation_usage = await _llm_validation_decisions(
        source_text, vulnerabilities, candidates_by_vuln
    )

    keep_vuln_keys: set[str] = set()
    mapped_type_by_vuln: dict[str, str] = {}

    for vuln in vulnerabilities:
        decision = decisions.get(vuln.canonical_key, {})
        keep = decision.get("keep", True)
        if keep is False:
            warnings.append(f"Self-validation dropped unsupported vulnerability: {vuln.canonical_key}")
            continue

        corrected_title = decision.get("corrected_title")
        if isinstance(corrected_title, str) and corrected_title.strip():
            vuln.attributes["title"] = corrected_title.strip()

        allowed = {vt.id for vt in candidates_by_vuln.get(vuln.canonical_key, [])}
        chosen = str(decision.get("mapped_type_id") or "").strip().upper()
        if chosen not in allowed or chosen not in registry:
            chosen = _existing_type_for_vuln(vuln, entities_by_key, relations, registry) or ""
        if not chosen:
            candidates = candidates_by_vuln.get(vuln.canonical_key) or []
            chosen = candidates[0].id if candidates else ""
        vuln_text = _entity_text(vuln)
        if "prompt injection" in vuln_text.lower() and chosen == "CWE-94" and not _has_code_execution_signal(vuln_text):
            if re.search(r"secret|sensitive|divulg|disclos|expos|leak|initial prompt|instruction", vuln_text.lower()):
                chosen = "CWE-200" if "CWE-200" in registry else chosen
            else:
                chosen = "CWE-1427" if "CWE-1427" in registry else chosen
        if not chosen or chosen not in registry:
            warnings.append(f"Could not map vulnerability to predefined type: {vuln.canonical_key}")
            continue

        keep_vuln_keys.add(vuln.canonical_key)
        mapped_type_by_vuln[vuln.canonical_key] = chosen

    if not vulnerabilities:
        return entities, relations, warnings, validation_usage

    surviving_vuln_ids: set[int] = set()
    key_rewrites: dict[str, str] = {}
    collapsed_old_keys: set[str] = set()
    rebuilt_mapping: dict[str, str] = {}

    by_type: dict[str, list[CanonicalEntity]] = {}
    for vuln in vulnerabilities:
        if vuln.canonical_key in keep_vuln_keys:
            by_type.setdefault(mapped_type_by_vuln[vuln.canonical_key], []).append(vuln)

    source_title_tokens = _source_title_tokens(source_text)
    for type_id, group in by_type.items():
        clusters: list[list[CanonicalEntity]] = []
        no_id_group = [vuln for vuln in group if not _has_official_id(vuln)]
        if len(no_id_group) > 1:
            clusters.append(no_id_group)
            seeded_no_id = {id(vuln) for vuln in no_id_group}
        else:
            seeded_no_id = set()
        for vuln in group:
            if id(vuln) in seeded_no_id:
                continue
            if _has_official_id(vuln):
                clusters.append([vuln])
                continue
            for cluster in clusters:
                if not _has_official_id(cluster[0]) and _looks_like_same_no_id_vuln(cluster[0], vuln):
                    cluster.append(vuln)
                    break
            else:
                clusters.append([vuln])

        for cluster in clusters:
            survivor = max(
                cluster,
                key=lambda v: _representative_score(v, source_title_tokens),
            )
            old_survivor_key = survivor.canonical_key
            for duplicate in cluster:
                if duplicate is survivor:
                    continue
                survivor.attributes = _merge_attrs(survivor.attributes, duplicate.attributes)
                survivor.confidence = max(survivor.confidence, duplicate.confidence)
                survivor.evidence.extend(e for e in duplicate.evidence if e not in survivor.evidence)
                survivor.source_chunks.extend(c for c in duplicate.source_chunks if c not in survivor.source_chunks)
                survivor.partial_reasons.extend(
                    r for r in duplicate.partial_reasons if r not in survivor.partial_reasons
                )
                collapsed_old_keys.add(duplicate.canonical_key)

            if not survivor.attributes.get("vuln_id"):
                survivor.attributes["vuln_id"] = _generated_vuln_id(source_url, survivor)
                survivor.is_partial = False
                survivor.partial_reasons = [
                    r for r in survivor.partial_reasons if r != "missing:vuln_id"
                ]
            survivor.canonical_key = f"Vulnerability::{str(survivor.attributes['vuln_id']).strip().upper()}"

            surviving_vuln_ids.add(id(survivor))
            rebuilt_mapping[survivor.canonical_key] = type_id
            for vuln in cluster:
                key_rewrites[vuln.canonical_key] = survivor.canonical_key
            key_rewrites[old_survivor_key] = survivor.canonical_key

            if len(cluster) > 1:
                warnings.append(
                    f"Collapsed {len(cluster)} duplicate no-ID vulnerabilities into {survivor.canonical_key}."
                )

    mapped_type_by_vuln = rebuilt_mapping
    removed_vulns = {
        v.canonical_key for v in vulnerabilities
        if id(v) not in surviving_vuln_ids
    } | collapsed_old_keys
    type_keys_needed = {_type_key(type_id) for type_id in mapped_type_by_vuln.values()}

    new_entities: list[CanonicalEntity] = []
    existing_keys = set()
    for ent in entities:
        if ent.class_name == "Vulnerability":
            if id(ent) not in surviving_vuln_ids:
                continue
        elif ent.canonical_key in removed_vulns:
            continue
        if ent.class_name == "VulnerabilityType":
            type_id = str(ent.attributes.get("id") or "").strip().upper()
            if type_id not in registry or _type_key(type_id) not in type_keys_needed:
                continue
            ent.canonical_key = _type_key(type_id)
            ent.attributes["id"] = type_id
            ent.attributes.setdefault("description", registry[type_id].description)
        new_entities.append(ent)
        existing_keys.add(ent.canonical_key)

    for type_id in sorted(set(mapped_type_by_vuln.values())):
        key = _type_key(type_id)
        if key in existing_keys:
            continue
        vt = registry[type_id]
        new_entities.append(CanonicalEntity(
            class_name="VulnerabilityType",
            canonical_key=key,
            attributes={"id": vt.id, "description": vt.description},
            confidence=1.0,
        ))
        existing_keys.add(key)

    new_relations: list[CanonicalRelation] = []
    for rel in relations:
        if rel.predicate == "isA_vulnType":
            continue
        subject_key = key_rewrites.get(rel.subject_key, rel.subject_key)
        object_key = key_rewrites.get(rel.object_key, rel.object_key)
        if subject_key in removed_vulns or object_key in removed_vulns:
            continue
        new_relations.append(CanonicalRelation(
            predicate=rel.predicate,
            subject_key=subject_key,
            object_key=object_key,
            confidence=rel.confidence,
        ))
    seen = {(rel.predicate, rel.subject_key, rel.object_key) for rel in new_relations}
    for vuln_key, type_id in mapped_type_by_vuln.items():
        key = ("isA_vulnType", vuln_key, _type_key(type_id))
        if key in seen:
            continue
        new_relations.append(CanonicalRelation(
            predicate="isA_vulnType",
            subject_key=vuln_key,
            object_key=_type_key(type_id),
            confidence=1.0,
        ))
        seen.add(key)

    for vuln_key, type_id in mapped_type_by_vuln.items():
        warnings.append(f"Mapped {vuln_key} to predefined VulnerabilityType {type_id}.")

    valid_keys = {ent.canonical_key for ent in new_entities}
    new_relations = [
        rel for rel in new_relations
        if rel.subject_key in valid_keys and rel.object_key in valid_keys
    ]
    return new_entities, new_relations, warnings, validation_usage
