# MITRE ATLAS Integration — Progress Summary

How we incorporated [MITRE ATLAS](https://atlas.mitre.org/) into AISecureChain.

## Guiding principle: incorporate, don't copy

ATLAS (and MISP/AVID) are treated as **data providers, not part of our schema**.
Our ontology stays **self-contained and source-neutral**: we reuse their
*identifiers* as references, but never name a field or class after a source.
This let us use ATLAS to **fill gaps**, not clone a competitor.

## What ATLAS adds that we lacked

Our taxonomy already had `VulnerabilityType` (CWE) = *the weakness*. ATLAS
supplies the two axes we were missing, which we modeled as **our own classes**:

| Our class (source-neutral) | Role | Seeded from ATLAS |
|---|---|---|
| `AttackTechnique` | **how** an AI system is attacked | 170 techniques |
| `Tactic` | the adversary's objective / phase | 16 tactics |
| `Mitigation` | the **countermeasure** (we had *no* defense concept before) | 35 mitigations |

New relations (ours): `Vulnerability —exploitedVia→ AttackTechnique —achievesTactic→ Tactic`,
`subtechniqueOf`, and `AttackTechnique —mitigatedBy→ Mitigation`.
Edges seeded: **111** achieves-tactic, **69** sub-technique, **246** mitigates.

The graph now answers a question the CVE feed can't: *what is the weakness (CWE) →
how is it attacked (technique → tactic) → how do we defend (mitigation)?*

## Reusing IDs without branding the schema

- ATLAS `AML.*` ids are reused as the natural keys of our nodes, **and** recorded
  in a generic `entity_external_id(entity_type, entity_id, source, external_id)`
  table — so provenance is explicit without a column named after ATLAS.
- The same principle de-branded the vulnerability record: source-specific fields
  (`misp_*`, `avid_class`, `sep_view`, `lifecycle_view`) were renamed to neutral
  terms (`tags`, `record_type`, `effect_category`, `lifecycle_stage`) or dropped;
  source ids live only in the external-reference tables.
- ATLAS **case studies** were folded into a `record_type` value, not a
  near-duplicate class.

## What was built (end to end)

1. **Data** — vendored `query_engine/data/atlas.yaml` (official `dist/ATLAS.yaml`).
2. **Schema** — `attack_technique` / `tactic` / `mitigation` tables + junctions
   (`technique_achieves_tactic`, `technique_subtechnique_of`, `mitigation_mitigates`,
   `vuln_exploited_via`) + `entity_external_id`, in `build_db.py`.
3. **Import** — `scripts/import_atlas.py` seeds the tables (idempotent), deriving
   sub-technique links from the `AML.Txxxx.NNN` id pattern.
4. **RDF** — `build_rdf.py` serializes the new classes/relations into the OWL graph.
5. **SPARQL** — the NL→SPARQL prompt knows the new classes/edges, so questions
   about attack techniques generate correct queries.
6. **API + Ontology view** — class-data + edge-data endpoints expose them; the
   Ontology graph renders all **10** classes wired by
   `exploitedVia → achievesTactic → mitigatedBy`.

## Extraction safety

The three ATLAS classes are **reference-only**: a `NON_EXTRACTABLE` guard in the
extraction pipeline keeps them (and their relations) out of the LLM prompt, so the
extractor never hallucinates them from a web page. They remain fully present in
RDF, the knowledge graph, and SPARQL.

## Verified

- DB/RDF counts: **170** techniques, **16** tactics, **35** mitigations.
- Ontology view shows the 10 classes + the four new relations.
- SPARQL traverses `AttackTechnique → achievesTactic → Tactic` correctly.
- Vulnerability records expose **zero** source-branded fields.

## Honest gaps / next step

- `vuln_exploited_via` (CVE ↔ ATLAS technique) is wired but **empty** — ATLAS
  doesn't map to our CVEs, so vulnerabilities don't yet connect into the
  technique→tactic→mitigation graph. The natural next step is **extraction-time
  auto-tagging**: map an advisory's described attack to a technique.
- The ATLAS node types were removed from the **Knowledge Graph (instance) view**
  filters (no instance data to show there yet); they live in the **Ontology
  view**, the data tables, and SPARQL.
