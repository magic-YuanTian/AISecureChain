"""
LLM-based extractor.

Produces an ExtractionGraph (entities + relations) from a single markdown chunk.
The prompt is built dynamically from the ontology schema so extraction auto-
adapts if the ontology is updated.

Robustness features:
    * Strict JSON instruction with fenced-block fallback parsing.
    * Key-name normalization for common LLM drift (``class_name`` -> ``class``,
      ``source``/``target`` -> ``subject``/``object`` on relations, etc.).
    * Null-value sanitization so Pydantic validation never trips on ``None``.
    * One retry with a "STRICT JSON ONLY" prompt if parsing fails.
    * Each chunk is independent — one bad chunk doesn't poison the run.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from pydantic import ValidationError

from .models import ExtractionGraph, ExtractedEntity, ExtractedRelation
from .ontology import (
    format_ontology_for_prompt,
    load_ontology_schema,
    ontology_class_names,
)


# ── System prompt ──────────────────────────────────────────────────────────

def build_system_prompt() -> str:
    ontology_block = format_ontology_for_prompt(load_ontology_schema())
    class_list = ", ".join(ontology_class_names())

    return f"""You are a precise information-extraction engine for a security knowledge base.

Given a chunk of web-page Markdown, identify every entity that matches a class
in the ontology below, and every relation that connects them.

Output a single JSON object of the form:
{{
  "entities": [
    {{
      "class": "<one of: {class_list}>",
      "local_id": "<short unique id within this chunk, e.g. v1, s1, ver1>",
      "attributes": {{ ... ontology attributes as key/value ... }},
      "evidence": "<short quote from the text that supports this entity>",
      "confidence": <number 0-1>
    }}
  ],
  "relations": [
    {{
      "predicate": "<one of the ontology relations>",
      "subject": "<local_id>",
      "object":  "<local_id>",
      "confidence": <number 0-1>
    }}
  ]
}}

EXTRACTION RULES (follow strictly):
1. The chunk may contain zero, one, or many records. Emit every entity you find.
2. Partial records are OK. If a required attribute is missing from the text,
   OMIT the key entirely (do not emit null, do not invent a value).
3. Do NOT hallucinate. Prefer omission over inference. Every entity and
   attribute must be supported by a direct quote in the chunk.
4. Emit one entity per real-world thing. If a product has multiple versions,
   emit one Software entity + one Version per version, linked by ``hasVersion``.
5. Link entities via local_id. Every subject/object in ``relations`` must match
   some entity's ``local_id`` in the same chunk.
6. When a Vendor can be inferred from the product name (e.g. "Microsoft Copilot"
   implies vendor "Microsoft"), emit it as a separate Vendor entity and link
   with the ``produce`` relation.
7. For every Software entity, you MUST set both ``is_ai`` and ``software_type``:
   - ``is_ai``: true for AI/ML systems, models, agents, AI libraries; false for
     non-AI software (browsers, OS, web servers, etc.).
   - ``software_type``: exactly one of: Application, AI Component,
     ML Infrastructure, Library, Agent, Model, Skill, Database, Dataset.
     Examples: ChatGPT→Application, LangChain→Library, GPT-4→Model,
     Claude Code→Agent, TensorFlow→ML Infrastructure, Chrome→Application.
8. Only extract Software that is the affected/vulnerable/abused system, a tool
   the attacker uses, or the main subject of the article, and set its ``role``
   attribute accordingly. Do NOT extract: products from navigation, ads,
   related posts, footers, examples, documentation pages, future work, or
   "compatible with" mentions; generic categories ("AI", "Generative AI",
   "LLMs", "chatbots", "AI agents" are NOT Software); defense/security products
   mentioned only as mitigation (EDR, CASB, SIEM, firewalls, the author's own
   platform — mark them role="defense" if you emit them at all); products
   cited only as historical analogies (mark role="mentioned"); or hypothetical
   / illustrative example systems that are not real named products (e.g. "a
   customer service bot", "an AI-powered fraud detection system" in a made-up
   scenario).
9. Classify vulnerabilities with ``isA_vulnType`` only when the vulnerability
   type is explicitly named in the text (for example "prompt injection").
10. Emit a CWE-style VulnerabilityType id (for example CWE-200) ONLY when that
   exact CWE identifier appears in the chunk. Do not map concepts to CWE IDs
   yourself.
11. For security news/blogs, emit a Vulnerability even when there is no CVE if
    the text clearly states a security weakness, exposure, bypass, abuse path,
    data leak, credential leak, or resource/billing abuse. Use the article title
    or the explicit finding as the vulnerability title. Leave ``vuln_id`` absent
    unless a CVE or GHSA appears in the chunk — then put that exact id in
    ``vuln_id``. ALWAYS set ``description`` to 2–4 sentences restating the
    weakness from this chunk (including CVE/GHSA records). Do not omit it.
    Paraphrase the source; do not invent facts that are not in the chunk.
    IMPORTANT: If the article describes ONE central vulnerability, finding, or
    attack technique (with examples, sub-categories, or mitigations), emit only
    ONE Vulnerability entity for the central finding. Do NOT emit separate
    Vulnerability entities for each section heading, example, or mitigation.
    Only emit multiple Vulnerabilities when the article documents genuinely
    distinct, unrelated security issues (e.g. a CVE roundup). If the central
    finding already carries an official id (CVE/GHSA), do NOT also emit
    separate no-id Vulnerabilities for its sub-techniques, attack stages,
    examples, or consequences — they belong to the same Vulnerability.
12. For API-key/credential stories, the affected software should be the service
    whose data/API can be accessed (for example Gemini / Generative Language
    API), not historical comparison services that merely used similar keys
    (for example Maps, YouTube embeds, Firebase).
13. Attack vs Impact discipline: an Attack is the METHOD (how the adversary
    gets in); an Impact is the OUTCOME (the harm achieved). 'Remote Code
    Execution', 'Privilege Escalation', 'Data Exfiltration' are Impacts, never
    Attacks. Link every Attack to a Vulnerability via ``exploits`` and every
    Impact via ``resultsIn``. If the chunk describes attacks or harms but you
    emitted no Vulnerability, emit ONE Vulnerability for the central
    weakness/finding (per rule 11) and link them to it — never leave
    Attack/Impact entities unlinked.
13b. ALWAYS connect the affected product to the vulnerability. Emit
    ``vulnerableTo`` from the affected Version to the Vulnerability when a
    version is stated; when the text names NO version (common for SaaS,
    browser extensions, and hosted AI products), emit ``vulnerableTo``
    directly from the affected Software entity. A Vulnerability with no
    ``vulnerableTo`` edge is incomplete — never leave the affected product
    disconnected.
14. Emit each impact the text explicitly attributes to the central
    vulnerability (an advisory stating privilege escalation, code execution
    AND data exfiltration yields three Impact entities). On CVE/GHSA/NVD
    advisory pages, always emit the attack technique and impact(s) stated in
    the description sentence (e.g. "allows arbitrary code execution via
    template injection" → Attack 'Template Injection', Impact 'Arbitrary Code
    Execution'), and the technique named by the Weakness/CWE section title
    (e.g. CWE-94 → Attack 'Code Injection'), linked to that CVE — while still
    ignoring the CVSS metric table labels. On conceptual, listicle, or
    thought-leadership pages, do NOT enumerate an Impact or Attack for every
    section, category, or scenario — emit only the 1-3 impacts and 1-2 attack
    techniques most central to the page's main finding. Never add speculative
    impacts that are not stated in the text.
15. Respond with JSON ONLY, no prose, no fences.

{ontology_block}
"""


# ── JSON parsing helpers ───────────────────────────────────────────────────

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
# Reasoning models (Qwen3.x, DeepSeek-R1, …) emit chain of thought before the
# answer. The thinking text routinely contains braces, which would poison the
# "first { .. last }" fallback below, so strip it first. Servers configured with
# a reasoning parser already remove it; this covers the ones that do not.
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_UNCLOSED_THINK_RE = re.compile(r"^.*?</think>", re.DOTALL | re.IGNORECASE)


def _extract_json_blob(text: str) -> str:
    """Pick the JSON object out of whatever the LLM returned."""
    t = text.strip()
    if "</think>" in t.lower():
        t = (_THINK_RE.sub("", t) if "<think>" in t.lower()
             else _UNCLOSED_THINK_RE.sub("", t)).strip()
    # Fenced block first
    m = _FENCE_RE.search(t)
    if m:
        return m.group(1).strip()
    # Fall back to first { ... last }
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        return t[start : end + 1]
    return t


# ── Normalisation of LLM drift before Pydantic ─────────────────────────────

_ENTITY_KEY_ALIASES = {
    "class_name": "class",
    "type": "class",
    "entity_class": "class",
    "id": "local_id",
    "entity_id": "local_id",
    "attrs": "attributes",
    "properties": "attributes",
    "props": "attributes",
}

_RELATION_KEY_ALIASES = {
    "rel": "predicate",
    "relation": "predicate",
    "type": "predicate",
    "source": "subject",
    "from": "subject",
    "subj": "subject",
    "target": "object",
    "to": "object",
    "obj": "object",
}


def _rename(d: dict[str, Any], aliases: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        nk = aliases.get(k, k)
        # Prefer an explicit canonical key if already present
        if nk in out and k != nk:
            continue
        out[nk] = v
    return out


def _coerce_confidence(x: Any) -> float:
    try:
        v = float(x)
        if v > 1.0 and v <= 100.0:
            v = v / 100.0
        return max(0.0, min(1.0, v))
    except Exception:
        return 1.0


def _clean_entity(raw: dict[str, Any]) -> dict[str, Any] | None:
    raw = _rename(raw, _ENTITY_KEY_ALIASES)
    cls = raw.get("class")
    lid = raw.get("local_id")
    if not cls or not isinstance(cls, str):
        return None
    if not lid or not isinstance(lid, str):
        return None
    attrs = raw.get("attributes") or {}
    if not isinstance(attrs, dict):
        attrs = {}
    # Drop explicit None attributes (schema requires we omit missing fields)
    attrs = {k: v for k, v in attrs.items() if v is not None}
    raw["class"] = cls.strip()
    raw["local_id"] = lid.strip()
    raw["attributes"] = attrs
    raw["confidence"] = _coerce_confidence(raw.get("confidence", 1.0))
    return raw


def _clean_relation(raw: dict[str, Any]) -> dict[str, Any] | None:
    raw = _rename(raw, _RELATION_KEY_ALIASES)
    pred = raw.get("predicate")
    subj = raw.get("subject")
    obj = raw.get("object")
    if not (pred and subj and obj):
        return None
    raw["predicate"] = str(pred).strip()
    raw["subject"] = str(subj).strip()
    raw["object"] = str(obj).strip()
    raw["confidence"] = _coerce_confidence(raw.get("confidence", 1.0))
    return raw


def _relation_domain_range() -> dict[str, tuple[str, str]]:
    """predicate -> (domain_class, range_class) from the TTL T-Box."""
    schema = load_ontology_schema()
    out: dict[str, tuple[str, str]] = {}
    for rel in schema.get("relations", []):
        pred = rel.get("predicate")
        if pred:
            out[pred] = (rel.get("domain") or "", rel.get("range") or "")
    return out


# ``vulnerableTo`` is declared Version→Vulnerability, but pages that state no
# version legitimately link the Software itself (persist.py attaches those via
# a placeholder version). Allow that widening explicitly.
_DOMAIN_WIDENING: dict[str, set[str]] = {
    "vulnerableTo": {"Software"},
}

# Predicates whose mis-wired endpoints may be repaired. Deliberately EXCLUDES
# the causal-chain edges (``exploits`` / ``resultsIn``): those are what
# ``filters.py`` uses to decide whether an Attack/Impact is real, so repairing
# one rescues an entity the filter would rightly have dropped. Measured: with
# causal edges repaired, Impact FPs rose 28→32 and headline F1 fell 0.78→0.74.
# Structural attribution edges have no such feedback loop.
_REPAIRABLE_PREDICATES = frozenset({
    "produce", "hasVersion", "hasLicense", "dependsOn", "isA_softwareType",
})


def _endpoint_ok(expected: str, actual: str, predicate: str, side: str) -> bool:
    if not expected:  # ontology declares no constraint
        return True
    if actual == expected:
        return True
    return side == "domain" and actual in _DOMAIN_WIDENING.get(predicate, set())


def _normalize_graph(raw: Any) -> dict[str, Any]:
    """Shape arbitrary LLM JSON into something ExtractionGraph can parse."""
    if not isinstance(raw, dict):
        return {"entities": [], "relations": []}

    ents_raw = raw.get("entities") or raw.get("nodes") or []
    rels_raw = raw.get("relations") or raw.get("edges") or raw.get("links") or []

    entities: list[dict[str, Any]] = []
    for item in ents_raw:
        if isinstance(item, dict):
            cleaned = _clean_entity(item)
            if cleaned:
                entities.append(cleaned)

    relations: list[dict[str, Any]] = []
    # keep a set of known local_ids for pruning bad refs
    class_of = {e["local_id"]: e["class"] for e in entities}
    dr = _relation_domain_range()
    for item in rels_raw:
        if not isinstance(item, dict):
            continue
        cleaned = _clean_relation(item)
        if not cleaned:
            continue
        subj, obj = cleaned["subject"], cleaned["object"]
        if subj not in class_of or obj not in class_of:
            continue
        # Type-check endpoints against the ontology. LLMs occasionally wire a
        # predicate to the wrong local_id (e.g. ``produce`` from a
        # Vulnerability instead of the Vendor), which silently corrupts
        # canonical keys downstream. For structural attribution edges, repair
        # the endpoint when the chunk holds exactly one entity of the expected
        # class (unambiguous — the model picked the wrong id, not a different
        # fact); otherwise drop the relation.
        pred = cleaned["predicate"]
        expected = dr.get(pred)
        if expected:
            ok = True
            for side, key, want in (("domain", "subject", expected[0]),
                                    ("range", "object", expected[1])):
                if _endpoint_ok(want, class_of[cleaned[key]], pred, side):
                    continue
                candidates = [i for i, c in class_of.items() if c == want]
                if pred in _REPAIRABLE_PREDICATES and len(candidates) == 1:
                    cleaned[key] = candidates[0]
                else:
                    ok = False
                    break
            if not ok:
                continue
            if cleaned["subject"] == cleaned["object"]:
                continue
        relations.append(cleaned)

    return {"entities": entities, "relations": relations}


_CWE_ID_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)

# Evidence phrased as advice/hardening rather than as something an attacker did.
# Impacts lifted from these sentences are the single largest remaining source of
# Impact false positives (mitigation sections of "how to defend" blog posts).
_MITIGATION_EVIDENCE_RE = re.compile(
    r"\b("
    r"should (be |use |implement |avoid |never |always )|"
    r"organizations? (should|must|need to)|teams? should|"
    r"best practice|recommend(ed|ation)?|guidance|"
    r"to (prevent|mitigate|protect|defend|reduce|avoid|harden)|"
    r"mitigation|remediation|countermeasure|"
    r"(design|implement|deploy|enforce|validate|configure|separate|apply|monitor|"
    r"establish|maintain|require) [a-z ]{0,20}(system prompt|system instruction|"
    r"filter|control|polic|boundar|delimiter|hierarch|guardrail|validation|"
    r"logging|review)"
    r")",
    re.IGNORECASE,
)
_INCIDENTAL_SOFTWARE_EVIDENCE_RE = re.compile(
    r"("
    r"text describing|documentation|docs hosted|compatible detection|compatible with|"
    r"future blog post|related posts|share on|copy link|jobs|career|"
    r"example prompts?|as an example|consider the string|"
    r"historically|services like|treated as non.?secret billing identifiers"
    r")",
    re.IGNORECASE,
)


def _filter_unsupported_inferences(graph: dict[str, Any], chunk: str) -> dict[str, Any]:
    """Remove high-risk inferred IDs/types that are not explicitly supported.

    LLMs are good at semantic mapping, but for KB ingestion a generated CWE ID is
    worse than omission. If the exact CWE identifier is absent from the source
    chunk, drop that VulnerabilityType and any relation pointing to it.
    """
    chunk_upper = chunk.upper()
    kept_entities: list[dict[str, Any]] = []
    dropped_ids: set[str] = set()

    for ent in graph.get("entities", []):
        attrs = ent.get("attributes") or {}
        evidence = str(ent.get("evidence") or "")
        if ent.get("class") == "VulnerabilityType":
            cwe_id = attrs.get("id")
            if isinstance(cwe_id, str) and _CWE_ID_RE.match(cwe_id.strip()):
                if cwe_id.strip().upper() not in chunk_upper:
                    dropped_ids.add(ent["local_id"])
                    continue
        if ent.get("class") == "Software":
            # Drop incidental products/tools mentioned as examples, docs, future
            # work, compatibility notes, or page chrome. These are not affected
            # systems and should not pollute the KB.
            if _INCIDENTAL_SOFTWARE_EVIDENCE_RE.search(evidence):
                dropped_ids.add(ent["local_id"])
                continue
        if ent.get("class") == "Impact":
            # An Impact whose only support is a mitigation/best-practice sentence
            # describes what a defender should do, not what an attacker achieved.
            if evidence and _MITIGATION_EVIDENCE_RE.search(evidence):
                dropped_ids.add(ent["local_id"])
                continue
        kept_entities.append(ent)

    if not dropped_ids:
        return graph

    kept_relations = [
        rel for rel in graph.get("relations", [])
        if rel.get("subject") not in dropped_ids and rel.get("object") not in dropped_ids
    ]
    return {"entities": kept_entities, "relations": kept_relations}


# ── LLM call wrapper ───────────────────────────────────────────────────────

def _call_llm(
    messages: list[dict[str, str]], temperature: float = 0.0
) -> tuple[str, dict]:
    """
    Delegates to get_response_with_usage.
    Kept synchronous — extract_graph will wrap it with asyncio.to_thread.
    Returns (reply_text, usage).
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from utils.openai_api import get_response_with_usage  # type: ignore

    return get_response_with_usage(messages, temperature=temperature)


async def extract_graph(
    chunk: str,
    *,
    system_prompt: str | None = None,
    temperature: float = 0.0,
    retries: int = 1,
) -> tuple[ExtractionGraph, str | None, dict]:
    """Run the LLM on a single chunk. Returns (graph, error_message, usage)."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from utils.openai_api import empty_usage, merge_usage  # type: ignore

    sys_prompt = system_prompt or build_system_prompt()
    user_msg = (
        "Extract all ontology entities and relations from the following "
        "markdown chunk. Return JSON only.\n\n---\n" + chunk + "\n---"
    )

    last_err: str | None = None
    usage_acc = empty_usage()
    for attempt in range(retries + 1):
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_msg},
        ]
        if attempt > 0:
            messages.append({
                "role": "system",
                "content": (
                    "Your previous reply could not be parsed. Respond with a "
                    "single JSON object only, matching the schema exactly. "
                    "No prose, no markdown fences."
                ),
            })

        try:
            raw, call_usage = await asyncio.to_thread(_call_llm, messages, temperature)
            usage_acc = merge_usage(usage_acc, call_usage)
        except Exception as e:  # noqa: BLE001
            last_err = f"LLM call failed: {e}"
            continue

        try:
            blob = _extract_json_blob(raw)
            parsed = json.loads(blob)
        except Exception as e:  # noqa: BLE001
            last_err = f"JSON parse failed: {e}. raw={raw[:300]}"
            continue

        shaped = _filter_unsupported_inferences(_normalize_graph(parsed), chunk)
        try:
            graph = ExtractionGraph.model_validate(shaped)
            return graph, None, usage_acc
        except ValidationError as e:
            last_err = f"Schema validation failed: {e}"
            continue

    return ExtractionGraph(), last_err, usage_acc
