# Relational and graph data stores and links

SQLite: `query_engine/ai_vuln_kb.db`  
RDF: `query_engine/ai_vuln_kb.ttl` — **72 triples = T-box only** (classes + properties + domains/ranges; **no** instance/`data:` nodes yet)

---

## 1. Schema overview

Both stores follow the same ontology:

```
Attack ──exploits──▶ Vulnerability ──resultsIn──▶ Impact
                           ▲
              vulnerableTo / isA_vulnType
                           │
        Vendor ──produce──▶ Software ──hasVersion──▶ Version
                              │
                       isA_softwareType
```


| Layer           | What it is                                                                                                                                             |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **RDF / graph** | Classes = node types; object properties = edges you expand (e.g. click Impact → neighbors via `resultsIn`); datatype properties = attributes on a node |
| **SQLite**      | Entity tables = nodes; junction tables = edges; columns on entity tables ≈ datatype properties                                                         |


`build_rdf.py` reads SQLite and emits Turtle. Until you rebuild after merges, SPARQL only sees the schema; the Explorer **SQLite** graph (`/api/kg/`*) already shows instances and expands neighbors on click.

---



## 2. Ontology vocabulary (from the TTL T-box)



### Classes (9)


| Class             | Example (from current DB)                                         |
| ----------------- | ----------------------------------------------------------------- |
| Vendor            | `abetlen`                                                         |
| Software          | `llama-cpp-python`                                                |
| SoftwareType      | `Library`                                                         |
| Version           | `0.*` (of llama-cpp-python)                                       |
| License           | `CC BY-SA 4.0`                                                    |
| Vulnerability     | `CVE-2024-34359` — SSTI in llama-cpp-python chat_template         |
| VulnerabilityType | `CWE-76` — Improper Neutralization of Equivalent Special Elements |
| Attack            | `AI-Generated Disinformation Campaign`                            |
| Impact            | `Arbitrary Code Execution`                                        |




### Object properties (9) — graph edges


| Property         | Typical direction                 |
| ---------------- | --------------------------------- |
| produce          | Vendor → Software                 |
| hasVersion       | Software → Version                |
| hasLicense       | Version → License                 |
| isA_softwareType | Software → SoftwareType           |
| vulnerableTo     | Version → Vulnerability           |
| isA_vulnType     | Vulnerability → VulnerabilityType |
| dependsOn        | Version → Version                 |
| exploits         | Attack → Vulnerability            |
| resultsIn        | Vulnerability → Impact            |




### Datatype properties (18) — node attributes


| Property         | Example (from current DB where present)                                               |
| ---------------- | ------------------------------------------------------------------------------------- |
| name             | `abetlen` (Vendor); also `llama-cpp-python`, `Template Injection`                     |
| description      | `Server-Side Template Injection in llama-cpp-python via malicious chat_template…`     |
| versionString    | `0.2.30`                                                                              |
| vulnId           | `CVE-2024-34359`                                                                      |
| title            | `SSTI in llama-cpp-python chat_template`                                              |
| datePublished    | `2024-05-14T15:38:45Z`                                                                |
| dateUpdated      | `2024-05-13T14:10:18Z`                                                                |
| cvssBaseScore    | `9.6`                                                                                 |
| cvssBaseSeverity | `CRITICAL`                                                                            |
| cvssVector       | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`                                        |
| references       | `https://github.com/abetlen/llama-cpp-python/security/advisories/GHSA-56xg-wfcc-g829` |
| credit           | `retr0reg`                                                                            |
| isAI             | `true` (`software.is_ai = 1` on llama-cpp-python)                                     |
| tags             | *(none in DB yet — e.g. MISP-style tag strings)*                                      |
| riskDomain       | *(none in DB yet — AVID-style domain label)*                                          |
| recordType       | *(none in DB yet — catalog record kind)*                                              |
| effectCategory   | *(none in DB yet — effect taxonomy label)*                                            |
| lifecycleStage   | *(none in DB yet — ML lifecycle stage)*                                               |


*(72 triples = these definitions plus OWL/RDFS boilerplate — not “every possible instance triple.”)*

---



## 3. SQLite entity tables (nodes)

**(n)** = current row count. Header = column row.

**vendor** (2)


| id  | name |
| --- | ---- |


**software** (3)


| id  | name | vendor_id | is_ai | software_type_id |
| --- | ---- | --------- | ----- | ---------------- |


**software_type** (2)


| id  | name | is_ai |
| --- | ---- | ----- |


**sw_version** (46)


| id  | version_string | software_id | license_id |
| --- | -------------- | ----------- | ---------- |


**license** (0)


| id  | name |
| --- | ---- |


**hardware** (0)


| id  | name | vendor_id |
| --- | ---- | --------- |


**hw_version** (0)


| id  | version_string | hardware_id |
| --- | -------------- | ----------- |


**vulnerability** (5)


| vuln_id | description | title | date_published | date_updated | cvss_base_score | cvss_severity | cvss_vector | references_json | credit | misp_threat_level | misp_event_date | misp_tags | source | risk_domain | sep_view | lifecycle_view | avid_class | exploited_in_wild | exploitation_verified_date | ransomware_use |
| ------- | ----------- | ----- | -------------- | ------------ | --------------- | ------------- | ----------- | --------------- | ------ | ----------------- | --------------- | --------- | ------ | ----------- | -------- | -------------- | ---------- | ----------------- | -------------------------- | -------------- |


**vulnerability_type** (1)


| id  | description |
| --- | ----------- |


**attack** (1)


| id  | name | description |
| --- | ---- | ----------- |


**impact** (3)


| id  | name | description |
| --- | ---- | ----------- |


---



## 4. SQLite junction tables (edges)

**sw_version_vulnerable_to** (46)


| sw_version_id | vuln_id |
| ------------- | ------- |


**vulnerability_is_a** (1)


| vuln_id | type_id |
| ------- | ------- |


**attack_exploits_vuln** (3)


| attack_id | vuln_id |
| --------- | ------- |


**vuln_results_in_impact** (3)


| vuln_id | impact_id |
| ------- | --------- |


**hw_version_vulnerable_to** (0)


| hw_version_id | vuln_id |
| ------------- | ------- |


**sw_version_depends_on** (0)


| from_version_id | to_version_id |
| --------------- | ------------- |


**sw_version_operate_on** (0)


| sw_version_id | hw_version_id |
| ------------- | ------------- |


**vulnerability_external_id** (0)


| vuln_id | source | external_id |
| ------- | ------ | ----------- |


**entity_external_id** (0)


| entity_type | entity_id | source | external_id |
| ----------- | --------- | ------ | ----------- |


**entity_same_as** (1)


| entity_type | left_key | right_key | confidence | reason | source_url | created_at |
| ----------- | -------- | --------- | ---------- | ------ | ---------- | ---------- |


**entity_alias** (2)


| entity_type | alias_norm | entity_key |
| ----------- | ---------- | ---------- |


---



## 5. Ops / pipeline tables (not ontology)

**data_source** (22)


| id  | name | tier | category | homepage | description | discovery_type | discovery_url | enabled | created_at | updated_at |
| --- | ---- | ---- | -------- | -------- | ----------- | -------------- | ------------- | ------- | ---------- | ---------- |


**source_url** (25)


| id  | source_id | url | title | first_seen | last_checked | last_ingested | content_hash | etag | last_modified | status | error | entities_count | preview_json | previewed_at | merged_at |
| --- | --------- | --- | ----- | ---------- | ------------ | ------------- | ------------ | ---- | ------------- | ------ | ----- | -------------- | ------------ | ------------ | --------- |


**source_url_deleted** (0)


| source_id | url | deleted_at |
| --------- | --- | ---------- |


**ingestion_run** (0)


| id  | source_url_id | source_id | url | started_at | finished_at | status | entities_inserted | entities_reused | same_as_edges | chunks_extracted | error_message |
| --- | ------------- | --------- | --- | ---------- | ----------- | ------ | ----------------- | --------------- | ------------- | ---------------- | ------------- |


---



## 6. What’s populated (instances)

```
CWE-76 ◄──is_a── CVE-2024-34359 ──sameAs──▶ GHSA-56XG-WFCC-G829
                    ▲
         Template Injection (exploits ×3)
                    │
                    ▼ resultsIn → RCE / Arbitrary Code Execution
         llama-cpp-python @ 0.2.x (46 versions, vendor abetlen)
```

Also: 2 NVD stubs (`CVE-2023-36258`, `CVE-2024-5184`) with no CWE/software links.  
`source_url`: 3 fresh · 10 error · 12 never.

Clicking an **Impact** (or any) node in Explorer expands **neighbors** via junction edges — that’s the live SQLite graph, independent of the 72-triple TTL until you rebuild RDF.