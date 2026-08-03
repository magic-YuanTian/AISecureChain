"""Deterministic precision filters, applied after merge + validation.

The extraction prompt is recall-oriented ("emit every entity"), so a thin,
rule-based post-pass removes the systematic over-extraction patterns the
regression benchmark surfaced:

* Software that is a generic category ("Generative AI", "chatbots"), not a
  named product;
* Software whose LLM-assigned ``role`` is defense/mentioned (mitigation
  products, marketing, historical analogies) — only affected systems and
  attacker tools belong in the KB;
* CVSS metric field labels extracted as Attack/Impact entities ("Attack
  Vector", "Confidentiality", …) — score-table headers, not entities;
* defensive benefits / vendor value propositions extracted as Impact
  ("AI-Powered Threat Detection", "Reduced Incident Response Costs");
* Attack/Impact entities that neither use a standard technique/impact name
  nor are linked to any Vulnerability (``exploits`` / ``resultsIn``) — the
  prompt requires the link, so an unlinked non-standard name is noise.

All filters fail open: a missing attribute never causes a drop.
"""

from __future__ import annotations

import re

from .models import CanonicalEntity, CanonicalRelation

_WORD_RE = re.compile(r"[a-z0-9]+")


def _singular(tok: str) -> str:
    if len(tok) > 4 and tok.endswith("ies"):
        return tok[:-3] + "y"
    if len(tok) > 3 and tok.endswith("ses"):
        return tok[:-2]
    if len(tok) > 3 and tok.endswith("s") and not tok.endswith("ss"):
        return tok[:-1]
    return tok


def _norm(s: str | None) -> str:
    return " ".join(_singular(t) for t in _WORD_RE.findall((s or "").lower()))


# ── Software: generic categories that are concepts, not products ───────────

GENERIC_SOFTWARE = {_norm(s) for s in [
    "AI", "Artificial Intelligence", "Generative AI", "GenAI", "Agentic AI",
    "AI System", "AI Systems", "AI Model", "AI Models", "AI Agent", "AI Agents",
    "Agent", "Agents", "AI Application", "AI Applications", "AI Tool", "AI Tools",
    "AI Platform", "AI Assistant", "AI Chatbot", "Chatbot", "Chatbots",
    "LLM", "LLMs", "Large Language Model", "Large Language Models",
    "Machine Learning", "Machine Learning System", "Machine-Learning System",
    "Machine Learning Model", "ML Model", "ML System", "Foundation Model",
    "Enterprise AI Stack", "Enterprise AI Stacks", "AI Browser Agent",
    "AI Browser Agents", "Neural Network", "Deep Learning",
]}

_SOFTWARE_DROP_ROLES = {"defense", "mentioned"}

# Frameworks, runtimes and model/interchange formats. These are Software; the
# LLM intermittently emits them as Vendor (observed: ONNX, PyTorch, TensorFlow
# and "OpenVINO Toolkit" all classed as Vendor on one page). Names that are
# genuinely both a product and a company (LangChain, Hugging Face, Databricks)
# are deliberately NOT listed — only unambiguous framework/format names.
NEVER_VENDORS = {_norm(s) for s in [
    "PyTorch", "TensorFlow", "ONNX", "Open Neural Network Exchange", "Keras",
    "JAX", "OpenVINO", "OpenVINO Toolkit", "CoreML", "Core ML", "scikit-learn",
    "NumPy", "Pandas", "SafeTensors", "Pickle", "Jinja2", "Netron",
    "Model Explorer", "TensorRT", "MLflow", "Triton", "vLLM", "Transformers",
]}

# Tokens that describe software generically. A Software name made ONLY of
# these tokens (plus numbers) is a description, not a product name —
# "Enterprise RAG System", "AI coding assistant", "customer service bot
# prod 01". Any brand token ("Chrome", "Claude", "LangChain") keeps it.
_GENERIC_NAME_TOKENS = {
    "ai", "genai", "generative", "artificial", "intelligence", "agentic",
    "llm", "chatbot", "model", "language", "large", "foundation",
    "machine", "learning", "ml", "neural", "network", "deep",
    "system", "platform", "service", "tool", "bot", "assistant", "agent",
    "application", "app", "software", "product", "solution", "suite",
    "enterprise", "rag", "retrieval", "augmented", "generation",
    "coding", "browsing", "bio", "customer", "fraud", "detection",
    "clinical", "decision", "support", "powered", "driven", "based",
    "core", "logistic", "monitoring", "intelligent", "smart",
    "security", "firewall", "gateway", "api", "prod", "environment",
    "variable", "hook", "workflow", "pipeline",
}


def _is_descriptive_name(norm_name: str) -> bool:
    toks = norm_name.split()
    return bool(toks) and all(t.isdigit() or t in _GENERIC_NAME_TOKENS for t in toks)


# Anonymised references to an organisation ("a leading logistics SaaS provider",
# "a multinational medical device manufacturer") are descriptions, not vendor
# names. Detected by the trailing noun so real names ending in an ordinary word
# ("Palo Alto Networks", "Trail of Bits") are untouched.
_ORG_DESCRIPTOR_TAIL = {
    "provider", "manufacturer", "company", "firm", "corporation", "corp",
    "vendor", "supplier", "retailer", "organization", "organisation",
    "agency", "institution", "startup", "giant", "operator", "integrator",
    "contractor", "conglomerate", "enterprise",
}


def _is_descriptive_org(norm_name: str) -> bool:
    toks = norm_name.split()
    return len(toks) > 1 and toks[-1] in _ORG_DESCRIPTOR_TAIL


# ── Attack / Impact: CVSS score-table field labels ─────────────────────────

CVSS_LABELS = {_norm(s) for s in [
    "Attack Vector", "Attack Complexity", "Attack Requirements",
    "Privileges Required", "User Interaction", "Scope",
    "Confidentiality", "Integrity", "Availability",
    "Confidentiality Impact", "Integrity Impact", "Availability Impact",
    "Loss of Confidentiality", "Loss of Integrity", "Loss of Availability",
    "Base Score", "Exploitability", "Severity",
]}

# Impact names that are defensive/business benefits, not attacker outcomes.
_DEFENSIVE_IMPACT_RE = re.compile(
    r"(threat detection|threat intelligence|risk (assessment|intelligence)|"
    r"incident response|response (automation|cost)|zero.?trust|"
    r"regulatory|compliance|resilien|efficiency|productivity|"
    r"integration|alignment|monitoring|drift prevention|preparation time|"
    r"improvement|acceleration|gains?$|cost reduction|reduced .*cost|"
    r"increased breach cost)",
    re.IGNORECASE,
)

# Standard names that survive even without a relation link (whitelist mirrors
# the normalization vocabulary in ontology.CLASS_HINTS).
STANDARD_ATTACKS = {_norm(s) for s in [
    "Prompt Injection", "Direct Prompt Injection", "Indirect Prompt Injection",
    "Visual Prompt Injection", "Jailbreak", "Jailbreaking",
    "Data Poisoning", "Training Data Poisoning", "Model Poisoning",
    "Model Backdoor", "Backdoor", "Supply Chain Attack",
    "Deserialization Attack", "Code Injection", "SQL Injection",
    "Command Injection", "Template Injection", "ASCII Smuggling",
    "Social Engineering", "Phishing", "Adversarial Example",
    "Model Extraction", "Membership Inference", "Cross-Site Scripting",
    "Server-Side Request Forgery", "Man-in-the-Middle",
]}

STANDARD_IMPACTS = {_norm(s) for s in [
    "Remote Code Execution", "Arbitrary Code Execution", "Code Execution",
    "Data Exfiltration", "Information Disclosure", "Sensitive Information Disclosure",
    "System Prompt Disclosure", "Data Leakage", "Data Leak", "Data Breach",
    "Data Theft", "Credential Theft", "Privilege Escalation",
    "Denial of Service", "Financial Loss", "Model Theft", "Model Manipulation",
    "Malware Delivery", "Malware Infection", "Unauthorized Access",
    "Unauthorized Actions", "Misinformation", "Persistence",
    "Harmful Content Generation", "Memory Poisoning", "Instruction Override",
    "Device Compromise", "Account Takeover", "Data Destruction",
    "API Key Exfiltration", "Reputational Damage",
]}


def _is_minted(ent: CanonicalEntity) -> bool:
    vid = str(ent.attributes.get("vuln_id") or "").upper()
    return bool(ent.attributes.get("_minted_id")) or vid.startswith(("AISC-", "EXTRACT-"))


def apply_precision_filters(
    entities: list[CanonicalEntity],
    relations: list[CanonicalRelation],
) -> tuple[list[CanonicalEntity], list[CanonicalRelation], list[str]]:
    """Drop systematic over-extractions. Returns (entities, relations, notes)."""
    notes: list[str] = []

    # Pass 0: when the page yields at least one officially-identified
    # vulnerability (CVE/GHSA/…), internally-minted ids are near-always
    # fragments of that same finding (sub-techniques, attack stages) — drop
    # them. Pages with no official id keep their minted finding.
    vulns = [e for e in entities if e.class_name == "Vulnerability"]
    if any(not _is_minted(v) for v in vulns) and any(_is_minted(v) for v in vulns):
        dropped_keys = {v.canonical_key for v in vulns if _is_minted(v)}
        for v in vulns:
            if v.canonical_key in dropped_keys:
                notes.append(
                    f"filter: dropped minted vulnerability '{v.attributes.get('vuln_id')}' "
                    "(official-id vulnerability present)"
                )
        entities = [e for e in entities if e.canonical_key not in dropped_keys]
        relations = [
            r for r in relations
            if r.subject_key not in dropped_keys and r.object_key not in dropped_keys
        ]

    linked_attacks = {r.subject_key for r in relations if r.predicate == "exploits"}
    linked_impacts = {r.object_key for r in relations if r.predicate == "resultsIn"}
    has_vuln = any(e.class_name == "Vulnerability" for e in entities)

    # Vendor/Software class confusion: a name emitted as Vendor that also names
    # (or is a whole-token part of) a Software entity in the same document is
    # almost always the product, not its maker — unless the Vendor actually
    # produces something, which a `produce` edge proves.
    software_tokens = [
        set(_norm(e.attributes.get("name") or "").split())
        for e in entities if e.class_name == "Software"
    ]
    producing_vendors = {r.subject_key for r in relations if r.predicate == "produce"}

    kept: list[CanonicalEntity] = []
    for ent in entities:
        name = str(ent.attributes.get("name") or "")
        n = _norm(name)

        if ent.class_name == "Vendor":
            if n in NEVER_VENDORS:
                notes.append(f"filter: dropped framework-as-Vendor '{name}'")
                continue
            if _is_descriptive_org(n):
                notes.append(f"filter: dropped descriptive Vendor '{name}'")
                continue
            toks = set(n.split())
            if (
                toks
                and ent.canonical_key not in producing_vendors
                and any(toks <= sw for sw in software_tokens if sw)
            ):
                notes.append(
                    f"filter: dropped Vendor '{name}' (same name appears as Software, no produce edge)"
                )
                continue

        if ent.class_name == "Software":
            if n in GENERIC_SOFTWARE or _is_descriptive_name(n):
                notes.append(f"filter: dropped generic-category Software '{name}'")
                continue
            role = str(ent.attributes.get("role") or "").strip().lower()
            if role in _SOFTWARE_DROP_ROLES:
                notes.append(f"filter: dropped Software '{name}' (role={role})")
                continue

        elif ent.class_name == "Attack":
            if n in CVSS_LABELS:
                notes.append(f"filter: dropped CVSS-label Attack '{name}'")
                continue
            # Keep if it is a recognised technique OR the model linked it to a
            # vulnerability. Requiring the link alone was measured (benchmark
            # round 6) at P 0.74 / R 0.77 — it drops real techniques the model
            # simply forgot to wire up, costing more recall than the precision
            # it buys.
            if has_vuln and n not in STANDARD_ATTACKS and ent.canonical_key not in linked_attacks:
                notes.append(f"filter: dropped unlinked non-standard Attack '{name}'")
                continue

        elif ent.class_name == "Impact":
            if n in CVSS_LABELS:
                notes.append(f"filter: dropped CVSS-label Impact '{name}'")
                continue
            if _DEFENSIVE_IMPACT_RE.search(name):
                notes.append(f"filter: dropped defensive-benefit Impact '{name}'")
                continue
            if has_vuln and n not in STANDARD_IMPACTS and ent.canonical_key not in linked_impacts:
                notes.append(f"filter: dropped unlinked non-standard Impact '{name}'")
                continue

        kept.append(ent)

    valid = {e.canonical_key for e in kept}
    kept_rels = [r for r in relations if r.subject_key in valid and r.object_key in valid]
    return kept, kept_rels, notes
