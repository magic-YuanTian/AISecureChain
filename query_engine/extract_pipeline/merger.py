"""
Merge per-chunk ExtractionGraphs into canonical, deduplicated entities.

The identity strategy is class-specific but driven by the ontology metadata
(``CLASS_HINTS.identity``). Special cases are noted inline.

Attribute resolution when multiple chunks describe the same entity:
    * text fields  — longest non-empty wins (tie: first seen)
    * numeric      — first non-null wins, warn on disagreement
    * list fields  — union (order-preserving)
    * boolean      — OR (presence of True dominates)
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from .models import (
    CanonicalEntity,
    CanonicalRelation,
    ExtractionGraph,
)
from .ontology import (
    class_identity_attr,
    load_ontology_schema,
    required_attributes,
)


# ── Normalisation helpers ──────────────────────────────────────────────────

def _norm_text(s: str | None) -> str:
    if not s:
        return ""
    return re.sub(r"\s+", " ", s).strip().lower()


def _norm_vuln_id(s: str | None) -> str:
    if not s:
        return ""
    t = s.strip().upper()
    t = re.sub(r"\s+", "", t)
    return t


# AISecureChain-minted identifier for vulnerabilities the system discovers from
# sources that carry no official CVE/GHSA/AVID id (research blogs, security
# write-ups, novel attack disclosures). The id is *deterministic* in the
# finding's title + year, so re-ingesting the same disclosure dedupes to the
# same id instead of creating a duplicate.
_MINTED_VULN_PREFIX = "AISC"


def mint_vuln_id(title: str | None, date_published: str | None = None) -> str:
    """Coin a stable internal vuln id, e.g. ``AISC-2026-1A2B3C``.

    ``title`` anchors the hash so identical findings collapse on re-ingest.
    The year is taken from ``date_published`` when present, else the current
    UTC year.
    """
    year = ""
    if date_published:
        m = re.search(r"(19|20)\d{2}", str(date_published))
        if m:
            year = m.group(0)
    if not year:
        year = str(datetime.now(timezone.utc).year)
    digest = hashlib.sha1(_norm_text(title).encode("utf-8")).hexdigest()[:6].upper()
    return f"{_MINTED_VULN_PREFIX}-{year}-{digest}"


def is_minted_vuln_id(vid: str | None) -> bool:
    return bool(vid) and str(vid).upper().startswith(_MINTED_VULN_PREFIX + "-")


def _known_model_vendor(name: str | None) -> str | None:
    """Infer vendor for well-known model family names when chunk relations omit it."""
    n = _norm_text(name)
    if n.startswith("gpt-") or n.startswith("gpt "):
        return "OpenAI"
    return None


# ── Canonical key computation ──────────────────────────────────────────────

def _canonical_key(
    class_name: str,
    attrs: dict[str, Any],
    *,
    vendor_hint: str | None = None,
    software_hint: str | None = None,
) -> str:
    """Compute a stable identity string for an entity within one URL."""
    ident = class_identity_attr(class_name)

    if class_name == "Vulnerability":
        vid = _norm_vuln_id(attrs.get("vuln_id"))
        if vid:
            return f"Vulnerability::{vid}"
        # Research blogs often describe named findings without CVE/GHSA/AVID IDs.
        # Keep those partial records separate by title instead of collapsing every
        # no-ID vulnerability into "Vulnerability::".
        return f"Vulnerability::title::{_norm_text(attrs.get('title'))}"

    if class_name == "Vendor":
        return f"Vendor::{_norm_text(attrs.get('name'))}"

    if class_name == "SoftwareType":
        return f"SoftwareType::{_norm_text(attrs.get('name'))}"

    if class_name == "Software":
        v = _norm_text(_known_model_vendor(attrs.get("name")) or vendor_hint or "")
        s = _norm_text(attrs.get("name"))
        return f"Software::{v}::{s}"

    if class_name == "Version":
        sw = software_hint or ""
        vs = _norm_text(attrs.get("version_string"))
        return f"Version::{sw}::{vs}"

    if class_name == "License":
        return f"License::{_norm_text(attrs.get('name'))}"

    if class_name == "VulnerabilityType":
        cid = _norm_text(attrs.get("id"))
        if not cid:
            cid = _norm_text(attrs.get("name") or attrs.get("description"))
        return f"VulnerabilityType::{cid}"

    # Generic fallback for future ontology classes
    return f"{class_name}::{_norm_text(str(attrs.get(ident, '')))}"


# ── Attribute merging ──────────────────────────────────────────────────────

def _merge_attrs(
    a: dict[str, Any], b: dict[str, Any]
) -> dict[str, Any]:
    """Union-merge attributes, preferring longer text / union of lists."""
    out = dict(a)
    for k, v in b.items():
        if v is None or v == "" or v == []:
            continue
        if k not in out or out[k] in (None, "", []):
            out[k] = v
            continue
        cur = out[k]
        if isinstance(cur, list) and isinstance(v, list):
            seen = list(cur)
            for item in v:
                if item not in seen:
                    seen.append(item)
            out[k] = seen
        elif isinstance(cur, bool) or isinstance(v, bool):
            out[k] = bool(cur) or bool(v)
        elif isinstance(cur, str) and isinstance(v, str):
            # longer wins
            if len(v) > len(cur):
                out[k] = v
        # else: keep first
    return out


# ── Main merger ────────────────────────────────────────────────────────────

def merge_graphs(
    graphs: list[ExtractionGraph],
) -> tuple[list[CanonicalEntity], list[CanonicalRelation]]:
    """
    Combine all per-chunk graphs into canonical entities + relations.

    Steps:
        1. For every chunk, first resolve the vendor/software context for each
           Software/Version local_id using that chunk's relations.
        2. Assign a canonical_key to every entity.
        3. Map (chunk_idx, local_id) -> canonical_key.
        4. Merge entities that share a canonical_key (union attrs, max conf).
        5. Rewrite relations to use canonical_keys. Deduplicate.
        6. Flag entities that are missing required attributes as is_partial.
    """
    schema = load_ontology_schema()

    # (chunk_idx, local_id) -> canonical_key
    local_to_canonical: dict[tuple[int, str], str] = {}
    # canonical_key -> merged CanonicalEntity (under construction)
    merged: dict[str, CanonicalEntity] = {}

    # Pass 1: assign canonical keys (needs per-chunk relation context)
    for ci, graph in enumerate(graphs):
        # Build local relation index for this chunk
        produced_by: dict[str, str] = {}  # software_local -> vendor_local
        version_of: dict[str, str] = {}   # version_local -> software_local
        for r in graph.relations:
            if r.predicate == "produce":
                produced_by[r.object] = r.subject
            elif r.predicate == "hasVersion":
                version_of[r.object] = r.subject

        # lookup helper
        ents_by_lid = {e.local_id: e for e in graph.entities}

        for e in graph.entities:
            vendor_hint = None
            software_hint = None
            if e.class_name == "Software":
                vl = produced_by.get(e.local_id)
                if vl and vl in ents_by_lid:
                    vendor_hint = ents_by_lid[vl].attributes.get("name")
            elif e.class_name == "Version":
                sl = version_of.get(e.local_id)
                if sl and sl in ents_by_lid:
                    sw_ent = ents_by_lid[sl]
                    # software's canonical key uses vendor, compute it too
                    sw_vendor_lid = produced_by.get(sl)
                    sw_vendor_name = None
                    if sw_vendor_lid and sw_vendor_lid in ents_by_lid:
                        sw_vendor_name = ents_by_lid[sw_vendor_lid].attributes.get("name")
                    software_hint = _canonical_key(
                        "Software",
                        sw_ent.attributes,
                        vendor_hint=sw_vendor_name,
                    )

            key = _canonical_key(
                e.class_name,
                e.attributes,
                vendor_hint=vendor_hint,
                software_hint=software_hint,
            )
            local_to_canonical[(ci, e.local_id)] = key

            if key in merged:
                m = merged[key]
                m.attributes = _merge_attrs(m.attributes, e.attributes)
                m.confidence = max(m.confidence, e.confidence)
                if ci not in m.source_chunks:
                    m.source_chunks.append(ci)
                if e.evidence:
                    m.evidence.append(e.evidence)
            else:
                merged[key] = CanonicalEntity(
                    class_name=e.class_name,
                    canonical_key=key,
                    attributes=dict(e.attributes),
                    confidence=e.confidence,
                    source_chunks=[ci],
                    evidence=[e.evidence] if e.evidence else [],
                )

    # Pass 2: canonical relations with dedup
    seen_rel: set[tuple[str, str, str]] = set()
    canonical_rels: list[CanonicalRelation] = []
    for ci, graph in enumerate(graphs):
        for r in graph.relations:
            subj = local_to_canonical.get((ci, r.subject))
            obj = local_to_canonical.get((ci, r.object))
            if not subj or not obj:
                continue
            key = (r.predicate, subj, obj)
            if key in seen_rel:
                continue
            seen_rel.add(key)
            canonical_rels.append(CanonicalRelation(
                predicate=r.predicate,
                subject_key=subj,
                object_key=obj,
                confidence=r.confidence,
            ))

    # Pass 2.5: mint internal ids for genuinely new vulnerabilities that have a
    # clear finding (title) but no official CVE/GHSA/AVID id. This is how the
    # system captures novel disclosures from research blogs / write-ups instead
    # of dropping them as "partial". Deterministic in title → idempotent.
    for ent in merged.values():
        if ent.class_name != "Vulnerability":
            continue
        if ent.attributes.get("vuln_id"):
            continue
        title = ent.attributes.get("title")
        if not title:
            continue
        minted = mint_vuln_id(title, ent.attributes.get("date_published"))
        ent.attributes["vuln_id"] = minted
        ent.attributes["_minted_id"] = True

    # Pass 2.6: collapse over-extracted minted findings. Chunk-level extraction
    # can split ONE novel finding into several near-duplicate Vulnerability
    # entities (one per chunk/heading). For minted (no official id) vulns, the
    # affected *software* is a strong identity signal: a single research write-up
    # with no official ids that keeps describing the same software is almost
    # always one disclosure, so we fold those together (richest description
    # wins). Vulns carrying official CVE/GHSA ids are never touched here, so
    # genuine multi-CVE roundups stay separate.
    minted_keys = [k for k, e in merged.items()
                   if e.class_name == "Vulnerability" and e.attributes.get("_minted_id")]
    if len(minted_keys) > 1:
        def _sw_name(sw_key: str) -> str:
            # "Software::<vendor>::<name>" → normalized name (vendor-agnostic, so
            # vendored and vendorless spellings of the same product group).
            parts = sw_key.split("::")
            return parts[-1] if parts else sw_key

        def _signature(vkey: str) -> frozenset[str]:
            return frozenset(
                _sw_name(r.subject_key) for r in canonical_rels
                if r.predicate == "vulnerableTo" and r.object_key == vkey
            )

        groups: dict[frozenset[str], list[str]] = {}
        for vkey in minted_keys:
            sw = _signature(vkey)
            if not sw:  # no affected software → too little signal to merge safely
                continue
            groups.setdefault(sw, []).append(vkey)

        remap: dict[str, str] = {}
        for members in groups.values():
            if len(members) < 2:
                continue
            # Representative: richest description, then longest title.
            rep = max(members, key=lambda k: (
                len(merged[k].attributes.get("description") or ""),
                len(merged[k].attributes.get("title") or ""),
            ))
            for k in members:
                if k == rep:
                    continue
                merged[rep].attributes = _merge_attrs(merged[rep].attributes, merged[k].attributes)
                merged[rep].source_chunks = sorted(set(merged[rep].source_chunks)
                                                   | set(merged[k].source_chunks))
                remap[k] = rep
                del merged[k]

        if remap:
            # Re-point relations at the surviving representative and de-dup.
            seen: set[tuple[str, str, str]] = set()
            rewritten: list[CanonicalRelation] = []
            for r in canonical_rels:
                subj = remap.get(r.subject_key, r.subject_key)
                obj = remap.get(r.object_key, r.object_key)
                if subj == obj:
                    continue
                sig = (r.predicate, subj, obj)
                if sig in seen:
                    continue
                seen.add(sig)
                rewritten.append(CanonicalRelation(
                    predicate=r.predicate, subject_key=subj,
                    object_key=obj, confidence=r.confidence,
                ))
            canonical_rels = rewritten

    # Pass 3: flag partial entities (missing required attributes).
    # Treat only None / blank string as missing — False and 0 are real values
    # (e.g. Software.is_ai=False must not be flagged partial).
    def _attr_missing(attrs: dict, key: str) -> bool:
        val = attrs.get(key)
        if val is None:
            return True
        if isinstance(val, str) and not val.strip():
            return True
        return False

    for ent in merged.values():
        reqs = required_attributes(ent.class_name)
        missing = [a for a in reqs if _attr_missing(ent.attributes, a)]
        if missing:
            ent.is_partial = True
            ent.partial_reasons = [f"missing:{a}" for a in missing]

    # Drop obviously-empty entities (e.g. Vulnerability with no vuln_id AND no title)
    canonical_entities: list[CanonicalEntity] = []
    for e in merged.values():
        if e.class_name == "Vulnerability":
            if not e.attributes.get("vuln_id") and not e.attributes.get("title"):
                continue
            desc = e.attributes.get("description")
            if not (isinstance(desc, str) and desc.strip()):
                continue
        if e.class_name == "Vendor" and not e.attributes.get("name"):
            continue
        if e.class_name == "Software" and not e.attributes.get("name"):
            continue
        if e.class_name == "Version" and not e.attributes.get("version_string"):
            continue
        canonical_entities.append(e)

    valid_keys = {e.canonical_key for e in canonical_entities}
    canonical_rels = [r for r in canonical_rels if r.subject_key in valid_keys and r.object_key in valid_keys]

    return canonical_entities, canonical_rels
