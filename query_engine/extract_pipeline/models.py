"""Pydantic models for the extraction pipeline.

Two layers of models:
    * Per-chunk (LLM output): ExtractedEntity / ExtractedRelation / ExtractionGraph
    * Merged (final): CanonicalEntity / CanonicalRelation
    * Top-level result: PipelineResult
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


# ── Per-chunk LLM output ────────────────────────────────────────────────────

class ExtractedEntity(BaseModel):
    """One entity discovered in a single chunk."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    class_name: str = Field(
        alias="class",
        description="Ontology class name (Vendor, Software, Vulnerability, etc.)",
    )
    local_id: str = Field(
        description="Chunk-local ID used to link relations; e.g. 'v1', 's2'"
    )
    attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Attribute values. Missing attrs are simply omitted.",
    )
    evidence: Optional[str] = Field(
        default=None, description="Short quote from the text supporting this entity"
    )
    confidence: float = Field(
        default=1.0, description="0-1; LLM's stated confidence"
    )


class ExtractedRelation(BaseModel):
    """One relation within a single chunk, linking two local_ids."""
    model_config = ConfigDict(populate_by_name=True)

    predicate: str
    subject: str = Field(description="local_id of the subject entity")
    object: str = Field(description="local_id of the object entity")
    confidence: float = 1.0
    evidence: Optional[str] = None


class ExtractionGraph(BaseModel):
    """All entities + relations found in a single chunk."""
    entities: list[ExtractedEntity] = Field(default_factory=list)
    relations: list[ExtractedRelation] = Field(default_factory=list)


# ── Merged / canonical records ──────────────────────────────────────────────

class CanonicalEntity(BaseModel):
    """An entity after dedup/merge across all chunks."""
    class_name: str
    canonical_key: str = Field(
        description="Stable identity within this page (e.g. vuln_id, vendor:name)"
    )
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0
    is_partial: bool = False
    partial_reasons: list[str] = Field(default_factory=list)
    source_chunks: list[int] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class CanonicalRelation(BaseModel):
    """A relation after dedup/merge, using canonical keys."""
    predicate: str
    subject_key: str
    object_key: str
    confidence: float = 1.0


# ── Top-level pipeline result ───────────────────────────────────────────────

class PipelineResult(BaseModel):
    """The complete output of the pipeline for one URL."""
    url: str
    markdown: str = ""
    markdown_length: int = 0
    chunks_total: int = 0
    chunks_extracted: int = 0
    raw_graphs: list[ExtractionGraph] = Field(default_factory=list)
    canonical_entities: list[CanonicalEntity] = Field(default_factory=list)
    canonical_relations: list[CanonicalRelation] = Field(default_factory=list)
    db_stats: Optional[dict[str, int]] = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    # ── Derived helpers ──

    def entity_counts_by_class(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self.canonical_entities:
            counts[e.class_name] = counts.get(e.class_name, 0) + 1
        return counts

    def entities_of_class(self, class_name: str) -> list[CanonicalEntity]:
        return [e for e in self.canonical_entities if e.class_name == class_name]

    def find_entity(self, canonical_key: str) -> Optional[CanonicalEntity]:
        for e in self.canonical_entities:
            if e.canonical_key == canonical_key:
                return e
        return None

    def partial_rate(self) -> float:
        if not self.canonical_entities:
            return 0.0
        partial = sum(1 for e in self.canonical_entities if e.is_partial)
        return partial / len(self.canonical_entities)

    def to_ui_response(self) -> dict[str, Any]:
        """
        Produce a *backward-compatible* response shape for the existing
        Extract UI, which expects ``extraction.vulnerabilities[]`` with
        affected_products & vulnerability_types nested inside each vuln.
        """
        vulns = self.entities_of_class("Vulnerability")
        # Build outgoing shape
        ui_vulns: list[dict[str, Any]] = []
        for vuln in vulns:
            attrs = dict(vuln.attributes)
            # Nested: vulnerability_types via isA_vulnType
            v_types: list[dict[str, Any]] = []
            for rel in self.canonical_relations:
                if rel.predicate == "isA_vulnType" and rel.subject_key == vuln.canonical_key:
                    vt = self.find_entity(rel.object_key)
                    if vt:
                        v_types.append({
                            "id": vt.attributes.get("id") or vt.canonical_key,
                            "description": vt.attributes.get("description"),
                        })

            # Nested: affected_products via Version -vulnerableTo-> Vulnerability
            # Plus lift up Version -> Software -> Vendor chain
            products_by_software: dict[str, dict[str, Any]] = {}
            for rel in self.canonical_relations:
                if rel.predicate == "vulnerableTo" and rel.object_key == vuln.canonical_key:
                    version = self.find_entity(rel.subject_key)
                    if not version:
                        continue
                    # Find software for this version
                    software = None
                    for r2 in self.canonical_relations:
                        if r2.predicate == "hasVersion" and r2.object_key == version.canonical_key:
                            software = self.find_entity(r2.subject_key)
                            break
                    sw_key = software.canonical_key if software else f"_ver_{version.canonical_key}"
                    if sw_key not in products_by_software:
                        vendor_name = None
                        is_ai = None
                        if software:
                            for r3 in self.canonical_relations:
                                if r3.predicate == "produce" and r3.object_key == software.canonical_key:
                                    vendor = self.find_entity(r3.subject_key)
                                    if vendor:
                                        vendor_name = vendor.attributes.get("name") or vendor.canonical_key
                                    break
                            is_ai = software.attributes.get("is_ai")
                        products_by_software[sw_key] = {
                            "vendor": vendor_name,
                            "product": (software.attributes.get("name") if software else None) or "Unknown",
                            "versions": [],
                            "is_ai": is_ai,
                        }
                    vstr = version.attributes.get("version_string") or version.canonical_key
                    if vstr and vstr not in products_by_software[sw_key]["versions"]:
                        products_by_software[sw_key]["versions"].append(vstr)

            ui_vulns.append({
                "vuln_id": attrs.get("vuln_id") or vuln.canonical_key,
                "title": attrs.get("title"),
                "description": attrs.get("description"),
                "date_published": attrs.get("date_published"),
                "date_updated": attrs.get("date_updated"),
                "cvss_base_score": attrs.get("cvss_base_score"),
                "cvss_severity": attrs.get("cvss_severity"),
                "cvss_vector": attrs.get("cvss_vector"),
                "references": attrs.get("references") or [],
                "credit": attrs.get("credit"),
                "vulnerability_types": v_types,
                "affected_products": list(products_by_software.values()),
                # extra meta
                "_is_partial": vuln.is_partial,
                "_partial_reasons": vuln.partial_reasons,
                "_confidence": vuln.confidence,
            })

        return {
            "vulnerabilities": ui_vulns,
            "entity_counts": self.entity_counts_by_class(),
            "partial_rate": self.partial_rate(),
            "warnings": self.warnings,
            "errors": self.errors,
        }
