"""
AISecureChain — Build RDF Knowledge Graph from SQLite
=====================================================
Reads the enriched relational DB and serialises an OWL/RDF graph.

Classes (per ontology diagram):
  :Vendor  :Software  :SoftwareType  :Version  :License
  :Vulnerability  :VulnerabilityType  :Attack  :Impact
  (Attack ──exploits──▶ Vulnerability ──resultsIn──▶ Impact)

Datatype Properties (node attributes):
  :name  :description  :versionString  :vulnId
  :title  :datePublished  :dateUpdated
  :cvssBaseScore  :cvssBaseSeverity  :cvssVector
  :references  :credit
  :mispThreatLevel  :mispEventDate  :mispTags
  :isAI

Output: ai_vuln_kb.ttl (Turtle format)
"""

import json
import os
import sqlite3
import re
from rdflib import Graph, Namespace, Literal, RDF, RDFS, OWL, XSD, URIRef

DB_PATH = os.path.join(os.path.dirname(__file__), "ai_vuln_kb.db")
TTL_PATH = os.path.join(os.path.dirname(__file__), "ai_vuln_kb.ttl")

NS = Namespace("http://aisecurechain.org/ontology#")
DATA = Namespace("http://aisecurechain.org/data/")


def safe_uri(prefix, raw_id):
    """Turn an arbitrary string into a safe URI fragment."""
    s = str(raw_id).strip()
    s = re.sub(r'[^A-Za-z0-9_\-.]', '_', s)
    return prefix[s]


def build():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")

    g = Graph()
    g.bind("asc", NS)
    g.bind("data", DATA)
    g.bind("owl", OWL)

    # ── OWL Classes ──
    # Source-neutral, self-contained ontology. Attack and Impact are our own
    # classes (extracted from advisory text) forming the causal chain
    #     Attack ──exploits──▶ Vulnerability ──resultsIn──▶ Impact
    # i.e. the "how is it attacked / what does it cause" axes the CWE layer lacks.
    classes = ["Vendor", "Software", "SoftwareType", "Version",
               "License", "Vulnerability", "VulnerabilityType",
               "Attack", "Impact"]
    for c in classes:
        g.add((NS[c], RDF.type, OWL.Class))
        g.add((NS[c], RDFS.label, Literal(c)))

    # ── OWL Object Properties ──
    props = {
        "produce":          ("Vendor", "Software"),
        "isA_softwareType": ("Software", "SoftwareType"),
        "hasVersion":       ("Software", "Version"),
        "hasLicense":       ("Version", "License"),
        "dependsOn":        ("Version", "Version"),
        "vulnerableTo":     ("Version", "Vulnerability"),
        "isA_vulnType":     ("Vulnerability", "VulnerabilityType"),
        "exploits":         ("Attack", "Vulnerability"),
        "resultsIn":        ("Vulnerability", "Impact"),
    }
    for p, (dom, rng) in props.items():
        g.add((NS[p], RDF.type, OWL.ObjectProperty))
        g.add((NS[p], RDFS.domain, NS[dom]))
        g.add((NS[p], RDFS.range, NS[rng]))
        g.add((NS[p], RDFS.label, Literal(p)))

    # ── Data Properties ──
    data_props = [
        "name", "description", "versionString", "vulnId",
        "title", "datePublished", "dateUpdated",
        "cvssBaseScore", "cvssBaseSeverity", "cvssVector",
        "references", "credit",
        "tags", "isAI",
        "riskDomain", "effectCategory", "lifecycleStage", "recordType",
    ]
    for dp in data_props:
        g.add((NS[dp], RDF.type, OWL.DatatypeProperty))

    # ── Populate Instances ──

    # Vendors
    vendor_uri = {}
    for r in conn.execute("SELECT id, name FROM vendor"):
        uri = safe_uri(DATA, f"vendor_{r['id']}")
        vendor_uri[r["id"]] = uri
        g.add((uri, RDF.type, NS.Vendor))
        g.add((uri, NS.name, Literal(r["name"])))
        g.add((uri, RDFS.label, Literal(r["name"])))

    # Software Types
    stype_uri = {}
    for r in conn.execute("SELECT id, name FROM software_type"):
        uri = safe_uri(DATA, f"stype_{r['id']}")
        stype_uri[r["id"]] = uri
        g.add((uri, RDF.type, NS.SoftwareType))
        g.add((uri, NS.name, Literal(r["name"])))
        g.add((uri, RDFS.label, Literal(r["name"])))

    # Software
    sw_uri = {}
    for r in conn.execute("SELECT id, name, vendor_id, is_ai, software_type_id FROM software"):
        uri = safe_uri(DATA, f"sw_{r['id']}")
        sw_uri[r["id"]] = uri
        g.add((uri, RDF.type, NS.Software))
        g.add((uri, NS.name, Literal(r["name"])))
        g.add((uri, RDFS.label, Literal(r["name"])))
        if r["is_ai"] is not None:
            g.add((uri, NS.isAI, Literal(bool(r["is_ai"]), datatype=XSD.boolean)))
        if r["vendor_id"] and r["vendor_id"] in vendor_uri:
            g.add((vendor_uri[r["vendor_id"]], NS.produce, uri))
        if r["software_type_id"] and r["software_type_id"] in stype_uri:
            g.add((uri, NS.isA_softwareType, stype_uri[r["software_type_id"]]))

    # Licenses
    lic_uri = {}
    for r in conn.execute("SELECT id, name FROM license"):
        uri = safe_uri(DATA, f"lic_{r['id']}")
        lic_uri[r["id"]] = uri
        g.add((uri, RDF.type, NS.License))
        g.add((uri, NS.name, Literal(r["name"])))

    # SW Versions
    ver_uri = {}
    for r in conn.execute("SELECT id, version_string, software_id, license_id FROM sw_version"):
        uri = safe_uri(DATA, f"ver_{r['id']}")
        ver_uri[r["id"]] = uri
        g.add((uri, RDF.type, NS.Version))
        g.add((uri, NS.versionString, Literal(r["version_string"])))
        label = f"{r['version_string']}"
        g.add((uri, RDFS.label, Literal(label)))
        if r["software_id"] and r["software_id"] in sw_uri:
            g.add((sw_uri[r["software_id"]], NS.hasVersion, uri))
        if r["license_id"] and r["license_id"] in lic_uri:
            g.add((uri, NS.hasLicense, lic_uri[r["license_id"]]))

    # Vulnerabilities
    vuln_uri = {}
    vuln_sql = """SELECT vuln_id, description, title, date_published, date_updated,
                         cvss_base_score, cvss_severity, cvss_vector,
                         references_json, credit,
                         misp_tags, risk_domain, sep_view,
                         lifecycle_view, avid_class,
                         exploited_in_wild, exploitation_verified_date, ransomware_use
                  FROM vulnerability"""
    for r in conn.execute(vuln_sql):
        uri = safe_uri(DATA, r["vuln_id"])
        vuln_uri[r["vuln_id"]] = uri
        g.add((uri, RDF.type, NS.Vulnerability))
        g.add((uri, NS.vulnId, Literal(r["vuln_id"])))
        g.add((uri, RDFS.label, Literal(r["vuln_id"])))
        if r["description"]:
            g.add((uri, NS.description, Literal(r["description"])))
        if r["title"]:
            g.add((uri, NS.title, Literal(r["title"])))
        if r["date_published"]:
            g.add((uri, NS.datePublished, Literal(r["date_published"])))
        if r["date_updated"]:
            g.add((uri, NS.dateUpdated, Literal(r["date_updated"])))
        if r["cvss_base_score"] is not None:
            g.add((uri, NS.cvssBaseScore, Literal(r["cvss_base_score"], datatype=XSD.float)))
        if r["cvss_severity"]:
            g.add((uri, NS.cvssBaseSeverity, Literal(r["cvss_severity"])))
        if r["cvss_vector"]:
            g.add((uri, NS.cvssVector, Literal(r["cvss_vector"])))
        if r["references_json"]:
            try:
                ref_list = json.loads(r["references_json"])
                for ref_url in ref_list:
                    g.add((uri, NS.references, Literal(ref_url)))
            except (json.JSONDecodeError, TypeError):
                pass
        if r["credit"]:
            g.add((uri, NS.credit, Literal(r["credit"])))
        # Self-contained, source-neutral attributes (source ids live in the
        # external-reference table, not as branded fields).
        if r["misp_tags"]:
            g.add((uri, NS.tags, Literal(r["misp_tags"])))
        if r["risk_domain"]:
            g.add((uri, NS.riskDomain, Literal(r["risk_domain"])))
        if r["sep_view"]:
            g.add((uri, NS.effectCategory, Literal(r["sep_view"])))
        if r["lifecycle_view"]:
            g.add((uri, NS.lifecycleStage, Literal(r["lifecycle_view"])))
        if r["avid_class"]:
            g.add((uri, NS.recordType, Literal(r["avid_class"])))
        # Verified in-the-wild exploitation (enriched from exploitation catalogs
        # such as CISA KEV — provenance lives in vulnerability_external_id).
        if r["exploited_in_wild"]:
            g.add((uri, NS.exploitedInWild, Literal(True, datatype=XSD.boolean)))
            if r["exploitation_verified_date"]:
                g.add((uri, NS.exploitationVerifiedDate,
                       Literal(r["exploitation_verified_date"], datatype=XSD.date)))
            if r["ransomware_use"]:
                g.add((uri, NS.ransomwareUse, Literal(r["ransomware_use"])))

    # Vulnerability Types (CWE)
    vtype_uri = {}
    for r in conn.execute("SELECT id, description FROM vulnerability_type"):
        uri = safe_uri(DATA, r["id"])
        vtype_uri[r["id"]] = uri
        g.add((uri, RDF.type, NS.VulnerabilityType))
        g.add((uri, NS.name, Literal(r["id"])))
        g.add((uri, RDFS.label, Literal(r["id"])))
        if r["description"]:
            g.add((uri, NS.description, Literal(r["description"])))

    # ── Junction: Version --vulnerableTo--> Vulnerability ──
    for r in conn.execute("SELECT sw_version_id, vuln_id FROM sw_version_vulnerable_to"):
        v = ver_uri.get(r["sw_version_id"])
        vuln = vuln_uri.get(r["vuln_id"])
        if v and vuln:
            g.add((v, NS.vulnerableTo, vuln))

    # ── Junction: Vulnerability --isA_vulnType--> VulnerabilityType ──
    for r in conn.execute("SELECT vuln_id, type_id FROM vulnerability_is_a"):
        vuln = vuln_uri.get(r["vuln_id"])
        vt = vtype_uri.get(r["type_id"])
        if vuln and vt:
            g.add((vuln, NS.isA_vulnType, vt))

    # ── Junction: Version --dependsOn--> Version ──
    for r in conn.execute("SELECT from_version_id, to_version_id FROM sw_version_depends_on"):
        v1 = ver_uri.get(r["from_version_id"])
        v2 = ver_uri.get(r["to_version_id"])
        if v1 and v2:
            g.add((v1, NS.dependsOn, v2))

    # ── Attack / Impact nodes (extracted per advisory) ──
    # Populated from the corresponding tables when present (see persist.py).
    #     Attack ──exploits──▶ Vulnerability ──resultsIn──▶ Impact

    def _table_exists(name: str) -> bool:
        return conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone() is not None

    def _emit_named(table, cls, prefix):
        uris = {}
        if not _table_exists(table):
            return uris
        for r in conn.execute(f"SELECT id, name, description FROM {table}"):
            uri = safe_uri(DATA, f"{prefix}_{r['id']}")
            uris[r["id"]] = uri
            g.add((uri, RDF.type, NS[cls]))
            g.add((uri, NS.name, Literal(r["name"] or str(r["id"]))))
            g.add((uri, RDFS.label, Literal(r["name"] or str(r["id"]))))
            if r["description"]:
                g.add((uri, NS.description, Literal(r["description"])))
        return uris

    attack_uri = _emit_named("attack", "Attack", "attack")
    impact_uri = _emit_named("impact", "Impact", "impact")

    # Attack --exploits--> Vulnerability
    if _table_exists("attack_exploits_vuln"):
        for r in conn.execute("SELECT attack_id, vuln_id FROM attack_exploits_vuln"):
            a = attack_uri.get(r["attack_id"]); b = vuln_uri.get(r["vuln_id"])
            if a and b:
                g.add((a, NS.exploits, b))

    # Vulnerability --resultsIn--> Impact
    if _table_exists("vuln_results_in_impact"):
        for r in conn.execute("SELECT vuln_id, impact_id FROM vuln_results_in_impact"):
            a = vuln_uri.get(r["vuln_id"]); b = impact_uri.get(r["impact_id"])
            if a and b:
                g.add((a, NS.resultsIn, b))

    conn.close()

    # ── Serialize ──
    g.serialize(destination=TTL_PATH, format="turtle")
    print(f"RDF graph built: {len(g)} triples → {TTL_PATH}")
    print(f"  Classes:    {len(classes)}")
    print(f"  Properties: {len(props)} object + {len(data_props)} data")
    print(f"  Vendors:    {len(vendor_uri)}")
    print(f"  Software:   {len(sw_uri)}")
    print(f"  Versions:   {len(ver_uri)}")
    print(f"  Vulns:      {len(vuln_uri)}")
    print(f"  VulnTypes:  {len(vtype_uri)}")
    print(f"  SwTypes:    {len(stype_uri)}")


if __name__ == "__main__":
    build()
