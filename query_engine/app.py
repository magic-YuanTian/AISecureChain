"""
AISecureChain — Flask API for Ontology Knowledge Base
Simplified schema: 9 entity + 5 junction tables.
RDF/SPARQL graph from ai_vuln_kb.ttl.
"""

import datetime
import json
import os
import re
import sqlite3
import time
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from rdflib import Graph as RDFGraph, URIRef

DB_PATH = os.path.join(os.path.dirname(__file__), "ai_vuln_kb.db")
TTL_PATH = os.path.join(os.path.dirname(__file__), "ai_vuln_kb.ttl")
ONT = "http://aisecurechain.org/ontology#"

# Single-port mode: Flask serves the React production build alongside the API.
FRONTEND_BUILD = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "frontend", "build")

app = Flask(__name__, static_folder=FRONTEND_BUILD, static_url_path="/")
CORS(app)


@app.route("/")
def serve_index():
    return send_from_directory(app.static_folder, "index.html")


@app.errorhandler(404)
def spa_fallback(e):
    # Client-side routes fall back to index.html; unknown API paths stay 404.
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(app.static_folder, "index.html")

# ── RDF graph (loaded once at startup) ──
rdf_graph = None

def get_rdf():
    global rdf_graph
    if rdf_graph is None:
        rdf_graph = RDFGraph()
        rdf_graph.parse(TTL_PATH, format="turtle")
        print(f"RDF graph loaded: {len(rdf_graph)} triples")
    return rdf_graph


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    # Concurrency: WAL lets readers and a writer coexist; busy_timeout
    # makes short write-collisions retry instead of failing immediately.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def rows_to_dicts(rows):
    return [dict(r) for r in rows]


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _result_to_api_payload(result):
    ui = result.to_ui_response()

    entities_by_class: dict[str, list[dict]] = {}
    for e in result.canonical_entities:
        entities_by_class.setdefault(e.class_name, []).append({
            "canonical_key": e.canonical_key,
            "attributes": e.attributes,
            "is_partial": e.is_partial,
        })

    relations_out = [
        {
            "predicate": r.predicate,
            "subject": r.subject_key,
            "object": r.object_key,
        }
        for r in result.canonical_relations
    ]

    return {
        "url": result.url,
        "markdown_length": result.markdown_length,
        "extraction": {
            "entities_by_class": entities_by_class,
            "relations": relations_out,
            "vulnerabilities": ui["vulnerabilities"],
            "entity_counts": ui["entity_counts"],
            "partial_rate": ui["partial_rate"],
            "warnings": ui["warnings"],
            "errors": ui["errors"],
            "chunks_total": result.chunks_total,
            "chunks_extracted": result.chunks_extracted,
        },
        "db_stats": result.db_stats,
        "vuln_count": len(ui["vulnerabilities"]),
    }


def _serialize_preview_result(result) -> str:
    return json.dumps(result.model_dump(mode="json"), ensure_ascii=True)


def _deserialize_preview_result(blob: str):
    from extract_pipeline import PipelineResult

    return PipelineResult.model_validate(json.loads(blob))


def _display_status(row: dict) -> str:
    raw = row.get("status") or "never"
    previewed_at = row.get("previewed_at")
    merged_at = row.get("merged_at")

    if raw == "error":
        return "error"
    if previewed_at and (not merged_at or previewed_at > merged_at):
        return "extracted"
    if merged_at or raw == "fresh":
        return "merged"
    if raw == "stale":
        return "stale"
    return "never"


def _url_row_to_payload(row) -> dict:
    out = dict(row)
    out["raw_status"] = out.get("status") or "never"
    out["status"] = _display_status(out)
    out["preview_cached"] = bool(out.get("preview_json"))
    out["last_activity"] = out.get("merged_at") or out.get("previewed_at") or out.get("last_ingested")
    out.pop("preview_json", None)
    return out


SCHEMA_PROMPT = """
You are a SQL expert working with a SQLite ontology-based vulnerability knowledge base.

ENTITY TABLES (11):
  vendor(id INTEGER PK, name TEXT UNIQUE)
  software(id INTEGER PK, name TEXT, vendor_id FK→vendor, is_ai INTEGER 0/1, software_type_id FK→software_type)
  software_type(id INTEGER PK, name TEXT UNIQUE)
  sw_version(id INTEGER PK, version_string TEXT, software_id FK→software, license_id FK→license)
  license(id INTEGER PK, name TEXT UNIQUE)
  hardware(id INTEGER PK, name TEXT, vendor_id FK→vendor)
  hw_version(id INTEGER PK, version_string TEXT, hardware_id FK→hardware)
  vulnerability(vuln_id TEXT PK, description TEXT, title TEXT,
                date_published TEXT, date_updated TEXT,
                cvss_base_score REAL, cvss_severity TEXT, cvss_vector TEXT,
                references_json TEXT, credit TEXT,
                misp_threat_level INTEGER, misp_event_date TEXT, misp_tags TEXT,
                source TEXT, risk_domain TEXT, sep_view TEXT,
                lifecycle_view TEXT, avid_class TEXT,
                exploited_in_wild INTEGER 0/1, exploitation_verified_date TEXT,
                ransomware_use TEXT)
  vulnerability_type(id TEXT PK like 'CWE-79', description TEXT)
  vulnerability_external_id(vuln_id FK→vulnerability, source TEXT like 'CVE'/'AVID'/'GHSA'/'KEV', external_id TEXT)
  attack(id INTEGER PK, name TEXT UNIQUE, description TEXT)   -- how a vuln is exploited
  impact(id INTEGER PK, name TEXT UNIQUE, description TEXT)   -- consequence of exploiting a vuln

JUNCTION TABLES (7, M:N edges):
  sw_version_vulnerable_to(sw_version_id FK→sw_version, vuln_id FK→vulnerability)
  hw_version_vulnerable_to(hw_version_id FK→hw_version, vuln_id FK→vulnerability)
  vulnerability_is_a(vuln_id FK→vulnerability, type_id FK→vulnerability_type)
  sw_version_depends_on(from_version_id FK→sw_version, to_version_id FK→sw_version)
  sw_version_operate_on(sw_version_id FK→sw_version, hw_version_id FK→hw_version)
  attack_exploits_vuln(attack_id FK→attack, vuln_id FK→vulnerability)   -- Attack → Vulnerability
  vuln_results_in_impact(vuln_id FK→vulnerability, impact_id FK→impact)  -- Vulnerability → Impact

1:N edges embedded as FK:
  software.vendor_id → vendor          (Vendor produces Software)
  software.software_type_id → software_type  (Software is-a Type)
  sw_version.software_id → software    (Software has-a Version)
  sw_version.license_id → license      (Version has-a License)
  hardware.vendor_id → vendor          (Vendor produces Hardware)
  hw_version.hardware_id → hardware    (Hardware has-a Version)

IMPORTANT COLUMNS:
- software.is_ai: 1 if that specific software product is AI-related, 0 otherwise.
- vulnerability columns: vuln_id (universal — can be CVE-xxx, AVID-xxx, GHSA-xxx, etc.), description (rich text), title (short), date_published, cvss_base_score (float), cvss_severity (LOW/MEDIUM/HIGH/CRITICAL), misp_threat_level (1=High,2=Medium,3=Low,4=Undefined), references_json (JSON array of URLs), credit (researcher), source (provenance: AVID-report, AVID-vuln, or NULL for legacy NVD/MISP), risk_domain, sep_view, lifecycle_view, avid_class, exploited_in_wild (1 = verified in-the-wild exploitation, e.g. listed in CISA KEV), exploitation_verified_date, ransomware_use ('Known'/'Unknown' — used in ransomware campaigns).
- vulnerability_external_id: cross-reference table mapping one vuln to multiple external IDs (e.g. CVE + AVID + GHSA for the same vulnerability).

COMMON JOIN PATTERNS:
  -- Find vulnerabilities for a software product:
  SELECT vuln.vuln_id, vuln.title, vuln.cvss_base_score, vuln.cvss_severity
  FROM software s
  JOIN sw_version sv ON sv.software_id = s.id
  JOIN sw_version_vulnerable_to svt ON svt.sw_version_id = sv.id
  JOIN vulnerability vuln ON svt.vuln_id = vuln.vuln_id
  WHERE s.name LIKE '%keyword%'

  -- Find AI-specific software vulnerabilities:
  SELECT s.name, vuln.vuln_id, vuln.cvss_base_score
  FROM software s
  JOIN sw_version sv ON sv.software_id = s.id
  JOIN sw_version_vulnerable_to svt ON svt.sw_version_id = sv.id
  JOIN vulnerability vuln ON svt.vuln_id = vuln.vuln_id
  WHERE s.is_ai = 1

  -- Find all external IDs for a vulnerability:
  SELECT vei.source, vei.external_id
  FROM vulnerability_external_id vei
  WHERE vei.vuln_id = ?

IMPORTANT:
- vulnerability.vuln_id is a universal identifier (not limited to CVE). Use it as the primary key.
- vulnerability.description contains rich text. Use LIKE '%keyword%' for topic searches.
- Do not assume software_type implies AI/non-AI status.
- Return ONLY a single SELECT statement, no explanation, no markdown.
- LIMIT 50 unless the user specifies otherwise.
"""


CLASS_QUERIES = {
    "Vendor": {
        "sql": "SELECT id, name FROM vendor ORDER BY name",
        "count": "SELECT COUNT(*) FROM vendor",
        "columns": ["id", "name"],
    },
    "Software": {
        "sql": """SELECT s.id, s.name, v.name AS vendor, s.is_ai, st.name AS software_type
                  FROM software s
                  LEFT JOIN vendor v ON s.vendor_id=v.id
                  LEFT JOIN software_type st ON s.software_type_id=st.id
                  ORDER BY s.name""",
        "count": "SELECT COUNT(*) FROM software",
        "columns": ["id", "name", "vendor", "is_ai", "software_type"],
    },
    "SoftwareType": {
        "sql": "SELECT id, name FROM software_type ORDER BY name",
        "count": "SELECT COUNT(*) FROM software_type",
        "columns": ["id", "name"],
    },
    "Version": {
        "sql": """SELECT sv.id, sv.version_string, s.name AS software, v.name AS vendor
                  FROM sw_version sv
                  JOIN software s ON sv.software_id=s.id
                  LEFT JOIN vendor v ON s.vendor_id=v.id
                  ORDER BY sv.id DESC""",
        "count": "SELECT COUNT(*) FROM sw_version",
        "columns": ["id", "version_string", "software", "vendor"],
    },
    "License": {
        "sql": "SELECT id, name FROM license ORDER BY name",
        "count": "SELECT COUNT(*) FROM license",
        "columns": ["id", "name"],
    },
    "Vulnerability": {
        # Self-contained vocabulary: source-specific columns (misp_*, avid_*) are
        # aliased to neutral names; redundant ones (misp threat level/date, raw
        # provenance) are not exposed. Source identifiers live in external refs.
        "sql": """SELECT v.vuln_id, v.title, v.description,
                         v.cvss_base_score, v.cvss_severity, v.cvss_vector,
                         v.date_published, v.date_updated,
                         v.credit, v.references_json,
                         v.misp_tags     AS tags,
                         v.risk_domain,
                         v.sep_view       AS effect_category,
                         v.lifecycle_view AS lifecycle_stage,
                         v.avid_class     AS record_type,
                         v.exploited_in_wild,
                         v.exploitation_verified_date,
                         v.ransomware_use,
                         GROUP_CONCAT(DISTINCT vt.id) AS types
                  FROM vulnerability v
                  LEFT JOIN vulnerability_is_a via ON via.vuln_id=v.vuln_id
                  LEFT JOIN vulnerability_type vt ON via.type_id=vt.id
                  GROUP BY v.vuln_id
                  ORDER BY v.vuln_id DESC""",
        "count": "SELECT COUNT(*) FROM vulnerability",
        "columns": ["vuln_id", "title", "description", "cvss_base_score", "cvss_severity",
                     "cvss_vector", "date_published", "date_updated", "credit",
                     "references_json", "tags", "risk_domain", "effect_category",
                     "lifecycle_stage", "record_type", "exploited_in_wild",
                     "exploitation_verified_date", "ransomware_use", "types"],
    },
    "VulnerabilityType": {
        "sql": "SELECT id, description FROM vulnerability_type ORDER BY id",
        "count": "SELECT COUNT(*) FROM vulnerability_type",
        "columns": ["id", "description"],
    },
    "Attack": {
        "sql": "SELECT id, name, description FROM attack ORDER BY name",
        "count": "SELECT COUNT(*) FROM attack",
        "columns": ["id", "name", "description"],
    },
    "Impact": {
        "sql": "SELECT id, name, description FROM impact ORDER BY name",
        "count": "SELECT COUNT(*) FROM impact",
        "columns": ["id", "name", "description"],
    },
}


EDGE_QUERIES = {
    "produce": {
        "sql": """SELECT v.id AS vendor_id, v.name AS vendor_name,
                         s.id AS software_id, s.name AS software_name
                  FROM software s
                  JOIN vendor v ON s.vendor_id = v.id
                  ORDER BY v.name, s.name""",
        "count": "SELECT COUNT(*) FROM software WHERE vendor_id IS NOT NULL",
        "columns": ["vendor_id", "vendor_name", "software_id", "software_name"],
    },
    "isA_softwareType": {
        "sql": """SELECT s.id AS software_id, s.name AS software_name,
                         st.id AS software_type_id, st.name AS software_type_name
                  FROM software s
                  JOIN software_type st ON s.software_type_id = st.id
                  ORDER BY st.name, s.name""",
        "count": "SELECT COUNT(*) FROM software WHERE software_type_id IS NOT NULL",
        "columns": ["software_id", "software_name", "software_type_id", "software_type_name"],
    },
    "hasVersion": {
        "sql": """SELECT s.id AS software_id, s.name AS software_name,
                         sv.id AS sw_version_id, sv.version_string
                  FROM sw_version sv
                  JOIN software s ON sv.software_id = s.id
                  ORDER BY s.name, sv.id DESC""",
        "count": "SELECT COUNT(*) FROM sw_version",
        "columns": ["software_id", "software_name", "sw_version_id", "version_string"],
    },
    "hasLicense": {
        "sql": """SELECT sv.id AS sw_version_id, sv.version_string,
                         l.id AS license_id, l.name AS license_name
                  FROM sw_version sv
                  JOIN license l ON sv.license_id = l.id
                  ORDER BY sv.id DESC""",
        "count": "SELECT COUNT(*) FROM sw_version WHERE license_id IS NOT NULL",
        "columns": ["sw_version_id", "version_string", "license_id", "license_name"],
    },
    "isA_vulnType": {
        "sql": """SELECT vuln.vuln_id, vuln.title AS vulnerability_name,
                         vt.id AS type_id, vt.description AS type_name
                  FROM vulnerability_is_a via
                  JOIN vulnerability vuln ON via.vuln_id = vuln.vuln_id
                  JOIN vulnerability_type vt ON via.type_id = vt.id
                  ORDER BY vuln.vuln_id DESC""",
        "count": "SELECT COUNT(*) FROM vulnerability_is_a",
        "columns": ["vuln_id", "vulnerability_name", "type_id", "type_name"],
    },
    "vulnerableTo": {
        "sql": """SELECT sv.id AS sw_version_id, sv.version_string,
                         vuln.vuln_id, vuln.title AS vulnerability_name
                  FROM sw_version_vulnerable_to svt
                  JOIN sw_version sv ON svt.sw_version_id = sv.id
                  JOIN vulnerability vuln ON svt.vuln_id = vuln.vuln_id
                  ORDER BY vuln.vuln_id DESC""",
        "count": "SELECT COUNT(*) FROM sw_version_vulnerable_to",
        "columns": ["sw_version_id", "version_string", "vuln_id", "vulnerability_name"],
    },
    "dependsOn": {
        "sql": """SELECT sv1.id AS from_version_id, sv1.version_string AS from_version,
                         sv2.id AS to_version_id, sv2.version_string AS to_version
                  FROM sw_version_depends_on dep
                  JOIN sw_version sv1 ON dep.from_version_id = sv1.id
                  JOIN sw_version sv2 ON dep.to_version_id = sv2.id
                  ORDER BY sv1.id DESC""",
        "count": "SELECT COUNT(*) FROM sw_version_depends_on",
        "columns": ["from_version_id", "from_version", "to_version_id", "to_version"],
    },
    "exploits": {
        "sql": """SELECT a.id AS attack_id, a.name AS attack_name,
                         v.vuln_id, v.title AS vulnerability_name
                  FROM attack_exploits_vuln j
                  JOIN attack a ON j.attack_id = a.id
                  JOIN vulnerability v ON j.vuln_id = v.vuln_id
                  ORDER BY v.vuln_id DESC""",
        "count": "SELECT COUNT(*) FROM attack_exploits_vuln",
        "columns": ["attack_id", "attack_name", "vuln_id", "vulnerability_name"],
    },
    "resultsIn": {
        "sql": """SELECT v.vuln_id, v.title AS vulnerability_name,
                         i.id AS impact_id, i.name AS impact_name
                  FROM vuln_results_in_impact j
                  JOIN vulnerability v ON j.vuln_id = v.vuln_id
                  JOIN impact i ON j.impact_id = i.id
                  ORDER BY v.vuln_id DESC""",
        "count": "SELECT COUNT(*) FROM vuln_results_in_impact",
        "columns": ["vuln_id", "vulnerability_name", "impact_id", "impact_name"],
    },
}

# Backward-compatible labels and display-label aliases.
EDGE_ALIASES = {
    "is-a": "isA_vulnType",
    "has-a": "hasLicense",
    "vulnerable-to": "vulnerableTo",
    "depends-on": "dependsOn",
}


# Per-column filter operators. Column names are validated against the spec's
# own column list before use; values are always passed as bound parameters.
_FILTER_OPS = {
    "contains": lambda c: (f"CAST(t.[{c}] AS TEXT) LIKE ?", lambda v: [f"%{v}%"]),
    "starts":   lambda c: (f"CAST(t.[{c}] AS TEXT) LIKE ?", lambda v: [f"{v}%"]),
    "eq":       lambda c: (f"t.[{c}] = ?", lambda v: [v]),
    "neq":      lambda c: (f"t.[{c}] <> ?", lambda v: [v]),
    "gte":      lambda c: (f"t.[{c}] >= ?", lambda v: [v]),
    "lte":      lambda c: (f"t.[{c}] <= ?", lambda v: [v]),
}


def _build_where(spec, q, filters):
    """Build a parameterized WHERE body for the wrapped spec subquery.

    `q` is a global keyword matched (case-insensitively) against every column.
    `filters` is a list of {column, op, value}; each is ANDed in. Returns
    (where_body, params) where where_body is '' when there is nothing to filter.
    """
    cols = set(spec["columns"])
    clauses: list[str] = []
    params: list = []

    q = (q or "").strip()
    if q:
        like = f"%{q}%"
        ors = " OR ".join(f"CAST(t.[{c}] AS TEXT) LIKE ?" for c in spec["columns"])
        clauses.append(f"({ors})")
        params.extend([like] * len(spec["columns"]))

    for f in filters or []:
        col = f.get("column")
        op = f.get("op")
        val = f.get("value")
        if col not in cols:
            continue
        if val is None or val == "" or val == []:
            continue
        if op == "in" and isinstance(val, list):
            placeholders = ",".join("?" * len(val))
            clauses.append(f"t.[{col}] IN ({placeholders})")
            params.extend(val)
        elif op in _FILTER_OPS:
            sql_frag, mk_params = _FILTER_OPS[op](col)
            clauses.append(sql_frag)
            params.extend(mk_params(val))

    return (" AND ".join(clauses), params)


def _query_spec(db, spec, limit, offset, q, filters, facet_cols):
    """Run a CLASS/EDGE query spec with global search + per-column filters.

    The spec SQL is wrapped as a subquery so filtering spans every record (not
    just the current page) and the returned total reflects the filtered set.
    `facet_cols` requests distinct values per column (to populate dropdowns).
    Returns (rows, total, facets)."""
    where, params = _build_where(spec, q, filters)
    base = f"SELECT * FROM ({spec['sql']}) AS t"
    if where:
        base += f" WHERE {where}"
        total = db.execute(f"SELECT COUNT(*) FROM ({base})", params).fetchone()[0]
    else:
        total = db.execute(spec["count"]).fetchone()[0]
    rows = rows_to_dicts(
        db.execute(base + " LIMIT ? OFFSET ?", (*params, limit, offset)).fetchall()
    )

    facets: dict[str, list] = {}
    valid = set(spec["columns"])
    for c in facet_cols:
        if c not in valid:
            continue
        vals = db.execute(
            f"SELECT DISTINCT t.[{c}] AS v FROM ({spec['sql']}) AS t "
            f"WHERE t.[{c}] IS NOT NULL AND t.[{c}] <> '' ORDER BY v LIMIT 80"
        ).fetchall()
        facets[c] = [r["v"] for r in vals]

    return rows, total, facets


def _parse_filters(raw):
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


@app.route("/api/edge-data/<edge_label>")
def edge_data(edge_label):
    canonical = EDGE_ALIASES.get(edge_label, edge_label)
    spec = EDGE_QUERIES.get(canonical)
    if not spec:
        return jsonify({"error": f"Unknown edge: {edge_label}"}), 404
    db = get_db()
    limit = min(int(request.args.get("limit", 50)), 500)
    offset = int(request.args.get("offset", 0))
    filters = _parse_filters(request.args.get("filters"))
    facet_cols = [c for c in (request.args.get("facets") or "").split(",") if c]
    rows, total, facets = _query_spec(db, spec, limit, offset, request.args.get("q"), filters, facet_cols)
    db.close()
    return jsonify({
        "edgeLabel": canonical,
        "columns": spec["columns"],
        "data": rows,
        "total": total,
        "limit": limit,
        "offset": offset,
        "facets": facets,
    })


@app.route("/api/class-data/<class_name>")
def class_data(class_name):
    spec = CLASS_QUERIES.get(class_name)
    if not spec:
        return jsonify({"error": f"Unknown class: {class_name}"}), 404
    db = get_db()
    limit = min(int(request.args.get("limit", 50)), 500)
    offset = int(request.args.get("offset", 0))
    filters = _parse_filters(request.args.get("filters"))
    facet_cols = [c for c in (request.args.get("facets") or "").split(",") if c]
    rows, total, facets = _query_spec(db, spec, limit, offset, request.args.get("q"), filters, facet_cols)
    db.close()
    return jsonify({
        "className": class_name,
        "columns": spec["columns"],
        "data": rows,
        "total": total,
        "limit": limit,
        "offset": offset,
        "facets": facets,
    })


@app.route("/api/stats")
def stats():
    db = get_db()
    tables = ["vendor", "software", "software_type", "sw_version", "license",
              "hardware", "hw_version", "vulnerability", "vulnerability_type",
              "sw_version_vulnerable_to", "hw_version_vulnerable_to",
              "vulnerability_is_a", "sw_version_depends_on", "sw_version_operate_on"]
    counts = {}
    for t in tables:
        counts[t] = db.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
    db.close()
    return jsonify({"counts": counts})


@app.route("/api/schema")
def schema():
    db = get_db()
    tables = rows_to_dicts(db.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall())
    db.close()
    return jsonify({"tables": tables})


@app.route("/api/vulnerabilities")
def vulnerabilities():
    db = get_db()
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))
    total = db.execute("SELECT COUNT(*) FROM vulnerability").fetchone()[0]
    rows = rows_to_dicts(db.execute("""
        SELECT v.vuln_id, v.title, v.description,
               v.cvss_base_score, v.cvss_severity, v.cvss_vector,
               v.date_published, v.date_updated,
               v.credit, v.references_json,
               v.misp_tags AS tags,
               GROUP_CONCAT(DISTINCT vt.id) AS types
        FROM vulnerability v
        LEFT JOIN vulnerability_is_a via ON via.vuln_id=v.vuln_id
        LEFT JOIN vulnerability_type vt ON via.type_id=vt.id
        GROUP BY v.vuln_id
        ORDER BY v.vuln_id DESC LIMIT ? OFFSET ?
    """, (limit, offset)).fetchall())
    db.close()
    return jsonify({"data": rows, "total": total, "limit": limit, "offset": offset})


def _publish_vuln(row: dict) -> dict:
    """Map a raw vulnerability row to our self-contained, source-neutral
    vocabulary. Source-specific columns (misp_*, avid_*) become neutral fields;
    redundant/branded provenance columns are dropped from the exposed payload
    (the originating source ids live in the external-references table)."""
    rename = {
        "misp_tags": "tags",
        "sep_view": "effect_category",
        "lifecycle_view": "lifecycle_stage",
        "avid_class": "record_type",
    }
    drop = {"misp_threat_level", "misp_event_date", "source"}
    out = {}
    for k, v in row.items():
        if k in drop:
            continue
        out[rename.get(k, k)] = v
    return out


@app.route("/api/vulnerability/<vuln_id>")
def vulnerability_detail(vuln_id):
    db = get_db()
    vuln = db.execute("SELECT * FROM vulnerability WHERE vuln_id=?", (vuln_id,)).fetchone()
    if not vuln:
        db.close(); return jsonify({"error": "not found"}), 404
    result = _publish_vuln(dict(vuln))
    result["external_ids"] = rows_to_dicts(db.execute(
        "SELECT source, external_id FROM vulnerability_external_id WHERE vuln_id=?",
        (vuln_id,)).fetchall())
    result["types"] = rows_to_dicts(db.execute(
        "SELECT vt.id, vt.description FROM vulnerability_is_a via JOIN vulnerability_type vt ON via.type_id=vt.id WHERE via.vuln_id=?",
        (vuln_id,)).fetchall())
    result["affected_software"] = rows_to_dicts(db.execute("""
        SELECT ve.name AS vendor, s.name AS software, sv.version_string
        FROM sw_version_vulnerable_to svt
        JOIN sw_version sv ON svt.sw_version_id=sv.id
        JOIN software s ON sv.software_id=s.id
        LEFT JOIN vendor ve ON s.vendor_id=ve.id
        WHERE svt.vuln_id=?
    """, (vuln_id,)).fetchall())
    result["affected_hardware"] = rows_to_dicts(db.execute("""
        SELECT ve.name AS vendor, h.name AS hardware, hv.version_string
        FROM hw_version_vulnerable_to hvt
        JOIN hw_version hv ON hvt.hw_version_id=hv.id
        JOIN hardware h ON hv.hardware_id=h.id
        LEFT JOIN vendor ve ON h.vendor_id=ve.id
        WHERE hvt.vuln_id=?
    """, (vuln_id,)).fetchall())
    db.close()
    return jsonify(result)


@app.route("/api/relationships")
def relationships():
    db = get_db()
    limit = min(int(request.args.get("limit", 50)), 500)
    offset = int(request.args.get("offset", 0))
    total = db.execute("SELECT COUNT(*) FROM sw_version_vulnerable_to").fetchone()[0]
    rows = rows_to_dicts(db.execute("""
        SELECT vuln.vuln_id, vuln.title, vuln.cvss_base_score, vuln.cvss_severity,
               v.name AS vendor, s.name AS software, s.is_ai, st.name AS software_type,
               sv.version_string
        FROM sw_version_vulnerable_to svt
        JOIN sw_version sv ON svt.sw_version_id=sv.id
        JOIN software s ON sv.software_id=s.id
        LEFT JOIN vendor v ON s.vendor_id=v.id
        LEFT JOIN software_type st ON s.software_type_id=st.id
        JOIN vulnerability vuln ON svt.vuln_id=vuln.vuln_id
        ORDER BY vuln.vuln_id DESC
        LIMIT ? OFFSET ?
    """, (limit, offset)).fetchall())
    db.close()
    return jsonify({"data": rows, "total": total, "limit": limit, "offset": offset})


@app.route("/api/software")
def software_list():
    db = get_db()
    limit = min(int(request.args.get("limit", 50)), 500)
    offset = int(request.args.get("offset", 0))
    total = db.execute("SELECT COUNT(*) FROM software").fetchone()[0]
    rows = rows_to_dicts(db.execute("""
        SELECT s.id, s.name, v.name as vendor, s.is_ai, st.name as software_type
        FROM software s
        LEFT JOIN vendor v ON s.vendor_id=v.id
        LEFT JOIN software_type st ON s.software_type_id=st.id
        ORDER BY s.name LIMIT ? OFFSET ?
    """, (limit, offset)).fetchall())
    db.close()
    return jsonify({"data": rows, "total": total, "limit": limit, "offset": offset})


@app.route("/api/types")
def types():
    db = get_db()
    rows = rows_to_dicts(db.execute("SELECT id, description FROM vulnerability_type ORDER BY id").fetchall())
    db.close()
    return jsonify({"data": rows})


# ── NL → SQL ──

@app.route("/api/nl-query", methods=["POST"])
def nl_query():
    body = request.get_json(force=True)
    question = (body.get("question") or "").strip()
    if not question:
        return jsonify({"error": "question is required"}), 400
    from utils.openai_api import get_response
    messages = [{"role": "system", "content": SCHEMA_PROMPT}, {"role": "user", "content": question}]
    try:
        sql = get_response(messages, temperature=0).strip().replace("```sql", "").replace("```", "").strip()
    except Exception as e:
        return jsonify({"error": f"LLM error: {e}", "sql": ""}), 500
    return jsonify({"sql": sql})


# ── Execute SQL ──

@app.route("/api/sql", methods=["POST"])
def run_sql():
    body = request.get_json(force=True)
    sql = (body.get("sql") or "").strip()
    if not sql:
        return jsonify({"error": "sql is required"}), 400
    if not sql.upper().startswith("SELECT"):
        return jsonify({"error": "Only SELECT queries allowed"}), 400
    db = get_db()
    try:
        cur = db.execute(sql)
        headers = [desc[0] for desc in cur.description]
        rows = [list(r) for r in cur.fetchall()]
    except Exception as e:
        db.close(); return jsonify({"error": str(e), "sql": sql}), 400
    db.close()
    return jsonify({"sql": sql, "headers": headers, "rows": rows})


# ── SPARQL ──

SPARQL_PREFIXES = """
PREFIX asc: <http://aisecurechain.org/ontology#>
PREFIX data: <http://aisecurechain.org/data/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
"""

SPARQL_SCHEMA_PROMPT = """You are a SPARQL expert. Write queries for an RDF knowledge graph with this ontology:

PREFIXES (always include these):
""" + SPARQL_PREFIXES + """

CLASSES:
  asc:Vendor, asc:Software, asc:SoftwareType, asc:Version,
  asc:License, asc:Vulnerability, asc:VulnerabilityType,
  asc:Attack, asc:Impact

OBJECT PROPERTIES (edges):
  asc:produce          — Vendor → Software
  asc:isA_softwareType — Software → SoftwareType
  asc:hasVersion       — Software → Version
  asc:hasLicense       — Version → License
  asc:dependsOn        — Version → Version
  asc:vulnerableTo     — Version → Vulnerability
  asc:isA_vulnType     — Vulnerability → VulnerabilityType   (weakness type, e.g. CWE)
  asc:exploits         — Attack → Vulnerability              (how the vuln is attacked)
  asc:resultsIn        — Vulnerability → Impact              (consequence of exploiting it)

DATA PROPERTIES:
  asc:name, asc:description, asc:versionString, asc:vulnId
  asc:vulnId           — universal vulnerability identifier (CVE-xxx, AVID-xxx, GHSA-xxx, etc.)
  asc:title            — short title of vulnerability
  asc:datePublished    — ISO date string
  asc:dateUpdated      — ISO date string
  asc:cvssBaseScore    — xsd:float (e.g. 7.5)
  asc:cvssBaseSeverity — LOW / MEDIUM / HIGH / CRITICAL
  asc:cvssVector       — CVSS vector string
  asc:references       — URL (multi-valued)
  asc:credit           — researcher name
  asc:tags             — comma-separated keyword tags
  asc:isAI             — xsd:boolean on Software (true = this specific software is AI-related)
  asc:riskDomain       — risk domain (Security, Ethics, Performance)
  asc:effectCategory   — effect/impact category (taxonomy code + label)
  asc:lifecycleStage   — ML lifecycle stage (e.g. "Deployment", "Evaluation")
  asc:recordType       — kind of record (e.g. "CVE Entry", "LLM Evaluation", "Incident")
  rdfs:label           — all instances have a human-readable label (also names Attack/Impact)

VALUE VOCABULARIES (use these EXACT tokens; they are case-sensitive):
  asc:cvssBaseSeverity : "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "NONE"   (UPPERCASE)
  asc:riskDomain       : "Security" | "Performance" | "Ethics"  (a row may combine them, e.g. "Ethics, Performance")
  asc:recordType       : "CVE Entry" | "LLM Evaluation" | "Third-party Report" | "Incident" | "Case Study"
  asc:isAI             : true / false (xsd:boolean)
  asc:vulnId           : exact upper-case ids, e.g. "CVE-2024-5184", "GHSA-...", "AVID-2023-V013", "AISC-2026-7AEC83"

MATCHING RULES (critical for getting non-empty, correct results):
- Names/titles are stored in their SOURCE casing and are often short repo-style
  slugs (e.g. "tensorflow", "langchain-ai", "vllm"), NOT the user's prose
  ("TensorFlow", "LangChain"). NEVER match asc:name / rdfs:label / asc:title with
  exact "=". ALWAYS bind the value and FILTER with a case-insensitive substring:
      ?sw asc:name ?n . FILTER(CONTAINS(LCASE(?n), LCASE("langchain")))
- asc:description / asc:title hold rich free text → search with CONTAINS(LCASE(...)).
- asc:riskDomain, asc:effectCategory, asc:lifecycleStage can hold MULTIPLE
  comma-joined values in one literal, so match them with CONTAINS, not "=":
      ?v asc:riskDomain ?rd . FILTER(CONTAINS(?rd, "Ethics"))
- Attack / Impact are named via asc:name / rdfs:label (match with CONTAINS):
      ?atk asc:exploits ?vuln . ?atk rdfs:label ?al . FILTER(CONTAINS(LCASE(?al), "prompt injection"))
      ?vuln asc:resultsIn ?imp . ?imp rdfs:label ?il . FILTER(CONTAINS(LCASE(?il), "remote code execution"))
- asc:cvssBaseSeverity is an exact UPPERCASE token, so "=" is fine there.
- For an exact vulnerability id, asc:vulnId "CVE-2024-5184" (exact) is correct.

EXAMPLE PATTERNS:
  # Software produced by a vendor (case-insensitive name)
  ?vendor asc:produce ?sw ; asc:name ?vn .
  ?sw asc:name ?sn .
  FILTER(CONTAINS(LCASE(?vn), "google"))

  # Which software/vendor is affected by a specific CVE (reverse path)
  ?ver asc:vulnerableTo ?vuln . ?vuln asc:vulnId "CVE-2024-5184" .
  ?sw asc:hasVersion ?ver ; asc:name ?sn .
  OPTIONAL { ?vendor asc:produce ?sw ; asc:name ?vendorName . }

  # Full path: Vendor → Software → Version → Vulnerability
  ?vendor asc:produce ?sw . ?sw asc:hasVersion ?ver . ?ver asc:vulnerableTo ?vuln .
  ?vuln asc:vulnId ?id .

  # Critical / high severity vulnerabilities, most severe first
  ?vuln a asc:Vulnerability ; asc:vulnId ?id ; asc:cvssBaseScore ?score ; asc:cvssBaseSeverity ?sev .
  FILTER(?sev IN ("HIGH", "CRITICAL"))
  ORDER BY DESC(?score)

  # Vulnerabilities about a topic (free-text)
  ?vuln a asc:Vulnerability ; asc:vulnId ?id ; asc:description ?desc .
  FILTER(CONTAINS(LCASE(?desc), "prompt injection"))

  # AI software only
  ?sw a asc:Software ; asc:isAI true ; asc:name ?sn .

  # Vulnerabilities of a given CWE type
  ?vuln asc:isA_vulnType ?vt ; asc:vulnId ?id . ?vt rdfs:label ?cwe .
  FILTER(CONTAINS(?cwe, "CWE-79"))

  # Counting (e.g. how many critical CVEs)
  SELECT (COUNT(DISTINCT ?vuln) AS ?n) WHERE {
    ?vuln a asc:Vulnerability ; asc:cvssBaseSeverity "CRITICAL" . }

  # Date range
  ?vuln a asc:Vulnerability ; asc:vulnId ?id ; asc:datePublished ?d .
  FILTER(?d >= "2024-01-01" && ?d < "2025-01-01")

IMPORTANT:
- Use ONLY the classes/properties listed above; do NOT invent new ones.
- Always SELECT at least one human-readable field (asc:vulnId, asc:name, or
  asc:title) so the result is meaningful — avoid returning only blank-node vars.
- Prefer SELECT DISTINCT to avoid duplicate rows from multi-valued joins.
- asc:isAI belongs to Software, not SoftwareType.
- Return ONLY a single SELECT query, with the PREFIX lines, no markdown, no prose.
- Add LIMIT 50 unless the user asks for a specific number or a COUNT.
"""


@app.route("/api/rdf/stats")
def rdf_stats():
    g = get_rdf()
    classes = ["Vendor", "Software", "SoftwareType", "Version",
               "License", "Vulnerability", "VulnerabilityType"]
    counts = {}
    for c in classes:
        q = f'SELECT (COUNT(?x) AS ?cnt) WHERE {{ ?x a <http://aisecurechain.org/ontology#{c}> }}'
        for row in g.query(q):
            counts[c] = int(row.cnt)
    counts["triples"] = len(g)
    return jsonify(counts)


@app.route("/api/rdf/ontology-graph")
def rdf_ontology_graph():
    """T-box only: OWL classes + object properties (domain → range) as a small graph for Explorer."""
    from rdflib import RDF, RDFS, OWL

    g = get_rdf()
    nodes = {}
    links = []
    seen_edges = set()

    def add_class_node(uri):
        key = str(uri)
        if key not in nodes and key.startswith(ONT):
            label = key.split("#")[-1]
            nodes[key] = {
                "id": key,
                "label": label,
                "class": "OntologyClass",
                "color": "#2563eb",
                "dataProperties": ontology_class_display_properties(label),
            }

    for s, _, o in g.triples((None, RDF.type, OWL.Class)):
        if str(s).startswith(ONT):
            add_class_node(s)

    for p, _, _ in g.triples((None, RDF.type, OWL.ObjectProperty)):
        pstr = str(p)
        if not pstr.startswith(ONT):
            continue
        dom = rng = None
        for _, _, d in g.triples((p, RDFS.domain, None)):
            dom = d
            break
        for _, _, r in g.triples((p, RDFS.range, None)):
            rng = r
            break
        if dom is None or rng is None:
            continue
        if not str(dom).startswith(ONT) or not str(rng).startswith(ONT):
            continue
        add_class_node(dom)
        add_class_node(rng)
        plabel = pstr.split("#")[-1]
        for _, _, lit in g.triples((p, RDFS.label, None)):
            plabel = str(lit)
            break
        ek = (str(dom), str(rng), plabel)
        if ek not in seen_edges:
            seen_edges.add(ek)
            links.append({"source": str(dom), "target": str(rng), "label": plabel})

    dprops = []
    for dp, _, _ in g.triples((None, RDF.type, OWL.DatatypeProperty)):
        if str(dp).startswith(ONT):
            dprops.append(str(dp).split("#")[-1])

    return jsonify({
        "nodes": list(nodes.values()),
        "links": links,
        "datatype_properties": sorted(dprops),
    })


@app.route("/api/rdf/sparql", methods=["POST"])
def sparql_query():
    body = request.get_json(force=True)
    sparql = (body.get("sparql") or "").strip()
    if not sparql:
        return jsonify({"error": "sparql is required"}), 400
    if not sparql.upper().lstrip().startswith(("SELECT", "PREFIX", "ASK", "CONSTRUCT", "DESCRIBE")):
        return jsonify({"error": "Only read queries allowed"}), 400
    g = get_rdf()
    try:
        results = g.query(sparql)
        headers = [str(v) for v in results.vars] if results.vars else []
        rows = [[str(cell) if cell is not None else None for cell in row] for row in results]
    except Exception as e:
        return jsonify({"error": str(e), "sparql": sparql}), 400
    return jsonify({"sparql": sparql, "headers": headers, "rows": rows})


def _clean_sparql(raw: str) -> str:
    """Strip markdown fences / stray prose the model sometimes adds."""
    s = (raw or "").strip()
    if "```" in s:
        # keep the content of the first fenced block if present
        parts = s.split("```")
        for p in parts:
            q = p.strip()
            if q.lower().startswith("sparql"):
                q = q[len("sparql"):].strip()
            if q.upper().startswith(("PREFIX", "SELECT", "ASK", "CONSTRUCT", "DESCRIBE")):
                return q
        s = s.replace("```sparql", "").replace("```", "").strip()
    return s


def _validate_sparql(sparql: str):
    """Parse-check a SPARQL query (cheap, no execution). Returns (ok, error)."""
    if not sparql:
        return False, "empty query"
    if not sparql.upper().lstrip().startswith(("SELECT", "PREFIX", "ASK", "CONSTRUCT", "DESCRIBE")):
        return False, "query must be a SELECT/ASK/CONSTRUCT/DESCRIBE (with its PREFIX lines)"
    try:
        from rdflib.plugins.sparql import prepareQuery
        prepareQuery(sparql)  # raises on syntax / undefined-prefix errors
        return True, None
    except Exception as e:  # noqa: BLE001
        return False, str(e)


@app.route("/api/rdf/nl-query", methods=["POST"])
def rdf_nl_query():
    body = request.get_json(force=True)
    question = (body.get("question") or "").strip()
    if not question:
        return jsonify({"error": "question is required"}), 400
    from utils.openai_api import get_response

    messages = [
        {"role": "system", "content": SPARQL_SCHEMA_PROMPT},
        {"role": "user", "content": question},
    ]
    sparql = ""
    last_err = None
    # Generate, then parse-validate; on a syntax/prefix error feed it back so the
    # model can repair (up to 3 attempts). This turns most "dead" queries into
    # working ones instead of surfacing a raw failure in the UI.
    for attempt in range(3):
        try:
            sparql = _clean_sparql(get_response(messages, temperature=0))
        except Exception as e:  # noqa: BLE001
            return jsonify({"error": f"LLM error: {e}", "sparql": ""}), 500
        ok, err = _validate_sparql(sparql)
        if ok:
            return jsonify({"sparql": sparql, "repaired": attempt > 0})
        last_err = err
        messages.append({"role": "assistant", "content": sparql})
        messages.append({
            "role": "user",
            "content": (
                f"That query is invalid: {err}\n"
                "Return a corrected single query that fixes this. "
                "Remember to include the PREFIX lines and use only the listed "
                "properties. Output the query only."
            ),
        })

    # Could not produce a valid query — return the last attempt plus the reason.
    return jsonify({"sparql": sparql, "warning": f"could not fully validate: {last_err}"})


# ── Graph visualization ──

CLASS_COLORS = {
    "Vendor": "#6366f1",
    "Software": "#22c55e",
    "SoftwareType": "#84cc16",
    "Version": "#f59e0b",
    "License": "#60a5fa",
    "Vulnerability": "#ef4444",
    "VulnerabilityType": "#ec4899",
    "Attack": "#a855f7",
    "Impact": "#0ea5e9",
}

PROP_LABELS = {
    "produce": "produce",
    "isA_softwareType": "is-a",
    "hasVersion": "has-a",
    "hasLicense": "has-a",
    "dependsOn": "depends-on",
    "vulnerableTo": "vulnerable-to",
    "isA_vulnType": "is-a",
    "exploits": "exploits",
    "resultsIn": "results-in",
}

DATATYPE_PROPS = {
    "name", "description", "versionString", "vulnId",
    "title", "datePublished", "dateUpdated",
    "cvssBaseScore", "cvssBaseSeverity", "cvssVector",
    "references", "credit",
    "tags", "isAI",
    "riskDomain", "effectCategory", "lifecycleStage", "recordType",
    "exploitedInWild", "exploitationVerifiedDate", "ransomwareUse",
}

CLASS_DATATYPE_PROPS = {
    "Vendor": ["name"],
    "Software": ["name", "isAI"],
    "SoftwareType": ["name"],
    "Version": ["versionString"],
    "License": ["name"],
    "Vulnerability": ["vulnId", "title", "description", "cvssBaseScore", "cvssBaseSeverity",
                       "cvssVector", "datePublished", "dateUpdated",
                       "references", "credit", "tags",
                       "riskDomain", "effectCategory", "lifecycleStage", "recordType",
                       "exploitedInWild", "exploitationVerifiedDate", "ransomwareUse"],
    "VulnerabilityType": ["name", "description"],
    "Attack": ["name", "description"],
    "Impact": ["name", "description"],
}


def ontology_class_display_properties(class_name: str) -> list[str]:
    """UML attribute list in Explorer; must match ``CLASS_QUERIES[*]['columns']`` when present."""
    spec = CLASS_QUERIES.get(class_name)
    if spec:
        return list(spec["columns"])
    return list(CLASS_DATATYPE_PROPS.get(class_name, []))


DATA_NS = "http://aisecurechain.org/data/"


def _uri_from_data_fragment(g, raw):
    """Map a literal id (CVE-…, CWE-…, sw_12, etc.) to a data URI if it exists in the graph."""
    from rdflib import URIRef, RDF

    frag = re.sub(r"[^A-Za-z0-9_\-.]", "_", str(raw).strip())
    if not frag:
        return None
    u = URIRef(DATA_NS + frag)
    if (u, RDF.type, None) in g:
        return u
    return None


def _add_sparql_binding_seeds(g, row, seeds):
    """Collect seed URIs from one SPARQL result row (URIs + literals that name KB entities)."""
    from rdflib import URIRef, Literal

    for cell in row:
        if cell is None:
            continue
        if isinstance(cell, URIRef) and str(cell).startswith("http://aisecurechain.org/"):
            seeds.add(cell)
        elif isinstance(cell, Literal):
            s = str(cell)
            if s.startswith("http://aisecurechain.org/"):
                seeds.add(URIRef(s))
            else:
                u = _uri_from_data_fragment(g, s)
                if u:
                    seeds.add(u)


def _add_seeds_from_sparql_text(g, sparql_str, seeds):
    """CVE/CWE tokens in the query text often correspond to data URIs."""
    for m in re.finditer(r"CVE-\d{4}-\d{4,12}", sparql_str, re.I):
        u = _uri_from_data_fragment(g, m.group(0))
        if u:
            seeds.add(u)
    for m in re.finditer(r"CWE-\d+", sparql_str, re.I):
        u = _uri_from_data_fragment(g, m.group(0).upper())
        if u:
            seeds.add(u)


def _label_search_seeds(g, keyword, seeds, per_query=6):
    """Find instances whose rdfs:label contains the keyword (case-insensitive)."""
    if len(keyword) < 3:
        return
    safe = keyword.replace("\\", "\\\\").replace('"', '\\"')
    sparql_find = f"""
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT DISTINCT ?entity WHERE {{
        ?entity rdfs:label ?lbl .
        FILTER(CONTAINS(LCASE(STR(?lbl)), LCASE("{safe}")))
    }} LIMIT {per_query}
    """
    try:
        for row in g.query(sparql_find):
            seeds.add(row.entity)
    except Exception:
        pass


def _node_class(g, uri):
    """Return the ontology class name for an instance URI."""
    from rdflib import RDF
    for _, _, o in g.triples((uri, RDF.type, None)):
        s = str(o)
        if s.startswith(ONT):
            return s[len(ONT):]
    return "Unknown"


def _node_label(g, uri):
    from rdflib import RDFS
    for _, _, o in g.triples((uri, RDFS.label, None)):
        return str(o)
    return str(uri).split("/")[-1]


def _node_properties(g, uri):
    """Collect datatype properties for a node (non-edge attributes)."""
    from rdflib import Literal as RDFLiteral
    props = {}
    for _, p, o in g.triples((uri, None, None)):
        pname = str(p).replace(ONT, "")
        if pname in DATATYPE_PROPS and isinstance(o, RDFLiteral):
            val = o.toPython()
            if isinstance(val, (datetime.date, datetime.datetime)):
                val = val.isoformat()[:10]
            if pname == "description" and isinstance(val, str) and len(val) > 200:
                val = val[:200] + "…"
            if pname in props:
                existing = props[pname]
                if isinstance(existing, list):
                    existing.append(val)
                else:
                    props[pname] = [existing, val]
            else:
                props[pname] = val
    return props


@app.route("/api/rdf/subgraph")
def rdf_subgraph():
    """Return nodes+links for a 1-hop neighbourhood around a search term."""
    g = get_rdf()
    from rdflib import RDF, RDFS, Literal as RDFLiteral, URIRef
    q = (request.args.get("q") or "").strip()
    cls = request.args.get("class", "")
    limit = min(int(request.args.get("limit", 80)), 300)

    if not q:
        return jsonify({"error": "q is required"}), 400

    sparql_find = f"""
    PREFIX asc: <{ONT}>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT DISTINCT ?entity WHERE {{
        ?entity rdfs:label ?lbl .
        FILTER(CONTAINS(LCASE(STR(?lbl)), LCASE("{q}")))
        {"?entity a asc:" + cls + " ." if cls else ""}
    }} LIMIT 10
    """
    seeds = [row.entity for row in g.query(sparql_find)]
    if not seeds:
        return jsonify({"nodes": [], "links": []})

    nodes_map = {}
    links = []

    def add_node(uri):
        key = str(uri)
        if key not in nodes_map:
            c = _node_class(g, uri)
            nodes_map[key] = {
                "id": key,
                "label": _node_label(g, uri),
                "class": c,
                "color": CLASS_COLORS.get(c, "#94a3b8"),
                "properties": _node_properties(g, uri),
            }

    for seed in seeds:
        add_node(seed)
        for s, p, o in g.triples((seed, None, None)):
            pname = str(p).replace(ONT, "")
            if pname in PROP_LABELS and isinstance(o, URIRef):
                add_node(o)
                links.append({"source": str(s), "target": str(o), "label": PROP_LABELS[pname]})
        for s, p, o in g.triples((None, None, seed)):
            pname = str(p).replace(ONT, "")
            if pname in PROP_LABELS and isinstance(s, URIRef):
                add_node(s)
                links.append({"source": str(s), "target": str(o), "label": PROP_LABELS[pname]})
        if len(links) >= limit:
            break

    links = links[:limit]
    return jsonify({"nodes": list(nodes_map.values()), "links": links})


@app.route("/api/rdf/subgraph-from-sparql")
def rdf_subgraph_from_sparql():
    """Execute a SPARQL query, collect all URI results as seeds, return 1-hop neighbourhood."""
    g = get_rdf()
    from rdflib import URIRef
    sparql_str = (request.args.get("sparql") or "").strip()
    limit = min(int(request.args.get("limit", 120)), 300)
    if not sparql_str:
        return jsonify({"error": "sparql is required"}), 400

    try:
        results = g.query(sparql_str)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    seeds = set()
    for row in results:
        for cell in row:
            if isinstance(cell, URIRef) and str(cell).startswith("http://aisecurechain.org/"):
                seeds.add(cell)
            elif cell is not None:
                s = str(cell)
                if s.startswith("http://aisecurechain.org/"):
                    seeds.add(URIRef(s))
    if not seeds:
        return jsonify({"nodes": [], "links": []})

    nodes_map = {}
    links = []

    def add_node(uri):
        key = str(uri)
        if key not in nodes_map:
            c = _node_class(g, uri)
            nodes_map[key] = {
                "id": key, "label": _node_label(g, uri),
                "class": c, "color": CLASS_COLORS.get(c, "#94a3b8"),
                "properties": _node_properties(g, uri),
            }

    for seed in list(seeds)[:30]:
        add_node(seed)
        for s, p, o in g.triples((seed, None, None)):
            pname = str(p).replace(ONT, "")
            if pname in PROP_LABELS and isinstance(o, URIRef):
                add_node(o)
                links.append({"source": str(s), "target": str(o), "label": PROP_LABELS[pname]})
        for s, p, o in g.triples((None, None, seed)):
            pname = str(p).replace(ONT, "")
            if pname in PROP_LABELS and isinstance(s, URIRef):
                add_node(s)
                links.append({"source": str(s), "target": str(o), "label": PROP_LABELS[pname]})
        if len(links) >= limit:
            break

    seen = set()
    deduped = []
    for l in links[:limit]:
        key = (str(l["source"]), str(l["target"]), l["label"])
        if key not in seen:
            seen.add(key)
            deduped.append(l)

    return jsonify({"nodes": list(nodes_map.values()), "links": deduped})


@app.route("/api/rdf/subgraph-for-question", methods=["GET", "POST"])
def rdf_subgraph_for_question():
    """Build a graph for a NL question: SPARQL bindings (incl. literals), CVE/CWE in query text, then keywords."""
    g = get_rdf()
    if request.method == "POST" and request.is_json:
        body = request.get_json(silent=True) or {}
        question = (body.get("q") or "").strip()
        sparql_str = (body.get("sparql") or "").strip()
        limit = min(int(body.get("limit", 120)), 300)
    else:
        question = (request.args.get("q") or "").strip()
        sparql_str = (request.args.get("sparql") or "").strip()
        limit = min(int(request.args.get("limit", 120)), 300)

    if not question and not sparql_str:
        return jsonify({"error": "q or sparql required"}), 400

    seeds = set()

    if sparql_str:
        _add_seeds_from_sparql_text(g, sparql_str, seeds)
        try:
            results = g.query(sparql_str)
            for row in results:
                _add_sparql_binding_seeds(g, row, seeds)
        except Exception:
            pass

    if not seeds and question:
        words = re.findall(r"[A-Za-z][A-Za-z0-9\-]{2,}", question)
        for w in words[:6]:
            _label_search_seeds(g, w, seeds)
            if len(seeds) >= 10:
                break

    # No natural-language question: mine quoted strings from SPARQL for label matches
    if not seeds and sparql_str:
        for q in re.findall(r'"([^"]{3,80})"', sparql_str)[:5]:
            _label_search_seeds(g, q, seeds)
            if len(seeds) >= 8:
                break

    if not seeds:
        return jsonify({"nodes": [], "links": []})

    nodes_map = {}
    links = []

    def add_node(uri):
        key = str(uri)
        if key not in nodes_map:
            c = _node_class(g, uri)
            nodes_map[key] = {
                "id": key, "label": _node_label(g, uri),
                "class": c, "color": CLASS_COLORS.get(c, "#94a3b8"),
                "properties": _node_properties(g, uri),
            }

    for seed in list(seeds)[:20]:
        add_node(seed)
        for s, p, o in g.triples((seed, None, None)):
            pname = str(p).replace(ONT, "")
            if pname in PROP_LABELS and isinstance(o, URIRef):
                add_node(o)
                links.append({"source": str(s), "target": str(o), "label": PROP_LABELS[pname]})
        for s, p, o in g.triples((None, None, seed)):
            pname = str(p).replace(ONT, "")
            if pname in PROP_LABELS and isinstance(s, URIRef):
                add_node(s)
                links.append({"source": str(s), "target": str(o), "label": PROP_LABELS[pname]})
        if len(links) >= limit:
            break

    seen = set()
    deduped = []
    for l in links[:limit]:
        key = (str(l["source"]), str(l["target"]), l["label"])
        if key not in seen:
            seen.add(key)
            deduped.append(l)

    return jsonify({"nodes": list(nodes_map.values()), "links": deduped})


# ── Local instance knowledge graph (SQLite-backed, no Neo4j required) ─────

def _kg_node(nodes: dict[str, dict], kg_id: str, label: str, typ: str, props: dict | None = None) -> None:
    if kg_id not in nodes:
        nodes[kg_id] = {
            "id": kg_id,
            "label": label or kg_id,
            "type": typ,
            "labels": [typ],
            "properties": props or {},
        }


def _kg_link(links: dict[tuple[str, str, str], dict], source: str, target: str, rel_type: str) -> None:
    links[(source, target, rel_type)] = {
        "source": source,
        "target": target,
        "type": rel_type,
        "label": rel_type,
        "properties": {},
    }


# Version strings that carry no real version information. They exist only to
# keep the Software→Version→Vulnerability chain connected when the source data
# doesn't specify an affected version (very common for AI models). In the graph
# we collapse these so Software links straight to the Vulnerability.
_PLACEHOLDER_VERSIONS = {"unspecified", "0", "*", "n/a", "-", "none", ""}


def _is_placeholder_version(vs) -> bool:
    return (vs or "").strip().lower() in _PLACEHOLDER_VERSIONS


def _kg_vulnerability_row(db, vuln_id: str):
    return db.execute(
        """SELECT vuln_id, title, description, date_published, date_updated,
                  cvss_base_score, cvss_severity, credit, source, risk_domain,
                  sep_view, lifecycle_view, avid_class, references_json,
                  exploited_in_wild, exploitation_verified_date, ransomware_use
           FROM vulnerability WHERE vuln_id=?""",
        (vuln_id,),
    ).fetchone()


def _canonical_id_url(source: str | None, ext_id: str | None) -> str | None:
    """Build a canonical advisory URL from an external id (CVE/GHSA/AVID)."""
    ext = (ext_id or "").strip()
    up = ext.upper()
    if up.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{ext}"
    if up.startswith("GHSA-"):
        return f"https://github.com/advisories/{ext}"
    if up.startswith("AVID-") or (source or "").upper() == "AVID":
        return f"https://avidml.org/database/{ext.lower()}/"
    return None


def _vuln_source_urls(db, row) -> list[str]:
    """The URLs a vulnerability node was drawn from: its recorded source URL,
    its reference links, and canonical advisory URLs for its external ids.
    Deduped, http(s) only, order-preserving (most specific first)."""
    urls: list[str] = []
    seen: set[str] = set()

    def add(u: str | None) -> None:
        u = (u or "").strip()
        if u.startswith("http") and u not in seen:
            seen.add(u)
            urls.append(u)

    cols = row.keys()
    # 1. Explicit source URL (set for pipeline-extracted vulns).
    add(row["source"] if "source" in cols else None)
    # 2. Reference links (populated for ~all AVID/CVE/GHSA vulns).
    refs = row["references_json"] if "references_json" in cols else None
    if refs:
        try:
            parsed = json.loads(refs)
            if isinstance(parsed, list):
                for u in parsed:
                    add(u if isinstance(u, str) else None)
        except (json.JSONDecodeError, TypeError):
            pass
    # 3. Canonical URLs reconstructed from external ids.
    for r in db.execute(
        "SELECT source, external_id FROM vulnerability_external_id WHERE vuln_id=?",
        (row["vuln_id"],),
    ).fetchall():
        add(_canonical_id_url(r["source"], r["external_id"]))
    return urls


def _kg_add_vulnerability_subgraph(db, vuln_id: str, nodes: dict, links: dict, limit: int) -> None:
    v = _kg_vulnerability_row(db, vuln_id)
    if not v:
        return
    vid = f"Vulnerability:{v['vuln_id']}"
    vprops = _publish_vuln(dict(v))
    vprops.pop("references_json", None)  # raw JSON string → replaced by clean list
    vprops["source_urls"] = _vuln_source_urls(db, v)
    _kg_node(nodes, vid, v["title"] or v["vuln_id"], "Vulnerability", vprops)

    for row in db.execute(
        """SELECT vt.id, vt.description
           FROM vulnerability_is_a via
           JOIN vulnerability_type vt ON vt.id=via.type_id
           WHERE via.vuln_id=?""",
        (vuln_id,),
    ).fetchall():
        tid = f"VulnerabilityType:{row['id']}"
        _kg_node(nodes, tid, row["id"], "VulnerabilityType", dict(row))
        _kg_link(links, vid, tid, "IS_A_VULN_TYPE")

    for row in db.execute(
        """SELECT sv.id AS version_id, sv.version_string,
                  s.id AS software_id, s.name AS software_name, s.is_ai,
                  v.id AS vendor_id, v.name AS vendor_name
           FROM sw_version_vulnerable_to svt
           JOIN sw_version sv ON sv.id=svt.sw_version_id
           JOIN software s ON s.id=sv.software_id
           LEFT JOIN vendor v ON v.id=s.vendor_id
           WHERE svt.vuln_id=?
           LIMIT ?""",
        (vuln_id, limit),
    ).fetchall():
        sid = f"Software:{row['software_id']}"
        _kg_node(nodes, sid, row["software_name"], "Software", {
            "id": row["software_id"], "name": row["software_name"], "is_ai": row["is_ai"],
        })
        if _is_placeholder_version(row["version_string"]):
            # No real version info — link software straight to the vuln.
            _kg_link(links, sid, vid, "AFFECTS")
        else:
            verid = f"Version:{row['version_id']}"
            _kg_node(nodes, verid, row["version_string"], "Version", {
                "id": row["version_id"], "version_string": row["version_string"],
            })
            _kg_link(links, sid, verid, "HAS_VERSION")
            _kg_link(links, verid, vid, "VULNERABLE_TO")
        if row["vendor_id"] is not None and row["vendor_name"]:
            vendid = f"Vendor:{row['vendor_id']}"
            _kg_node(nodes, vendid, row["vendor_name"], "Vendor", {
                "id": row["vendor_id"], "name": row["vendor_name"],
            })
            _kg_link(links, vendid, sid, "PRODUCES")

    # Attack ──exploits──▶ Vulnerability ──resultsIn──▶ Impact
    for row in db.execute(
        """SELECT a.id, a.name, a.description
           FROM attack_exploits_vuln j JOIN attack a ON a.id=j.attack_id
           WHERE j.vuln_id=? LIMIT ?""",
        (vuln_id, limit),
    ).fetchall():
        aid = f"Attack:{row['id']}"
        _kg_node(nodes, aid, row["name"], "Attack", dict(row))
        _kg_link(links, aid, vid, "EXPLOITS")

    for row in db.execute(
        """SELECT i.id, i.name, i.description
           FROM vuln_results_in_impact j JOIN impact i ON i.id=j.impact_id
           WHERE j.vuln_id=? LIMIT ?""",
        (vuln_id, limit),
    ).fetchall():
        iid = f"Impact:{row['id']}"
        _kg_node(nodes, iid, row["name"], "Impact", dict(row))
        _kg_link(links, vid, iid, "RESULTS_IN")


def _kg_add_type_subgraph(db, type_id: str, nodes: dict, links: dict, limit: int) -> None:
    vt = db.execute("SELECT id, description FROM vulnerability_type WHERE id=?", (type_id,)).fetchone()
    if not vt:
        return
    tid = f"VulnerabilityType:{vt['id']}"
    _kg_node(nodes, tid, vt["id"], "VulnerabilityType", dict(vt))
    rows = db.execute(
        """SELECT vuln_id FROM vulnerability_is_a
           WHERE type_id=? ORDER BY vuln_id DESC LIMIT ?""",
        (type_id, limit),
    ).fetchall()
    for row in rows:
        _kg_add_vulnerability_subgraph(db, row["vuln_id"], nodes, links, max(1, limit // 4))


def _kg_add_software_subgraph(db, software_id: int, nodes: dict, links: dict, limit: int) -> None:
    rows = db.execute(
        """SELECT s.id AS software_id, s.name AS software_name, s.is_ai,
                  v.id AS vendor_id, v.name AS vendor_name,
                  sv.id AS version_id, sv.version_string, svt.vuln_id
           FROM software s
           LEFT JOIN vendor v ON v.id=s.vendor_id
           LEFT JOIN sw_version sv ON sv.software_id=s.id
           LEFT JOIN sw_version_vulnerable_to svt ON svt.sw_version_id=sv.id
           WHERE s.id=?
           LIMIT ?""",
        (software_id, limit),
    ).fetchall()
    for row in rows:
        sid = f"Software:{row['software_id']}"
        _kg_node(nodes, sid, row["software_name"], "Software", {
            "id": row["software_id"], "name": row["software_name"], "is_ai": row["is_ai"],
        })
        if row["vendor_id"] is not None and row["vendor_name"]:
            vendid = f"Vendor:{row['vendor_id']}"
            _kg_node(nodes, vendid, row["vendor_name"], "Vendor", {
                "id": row["vendor_id"], "name": row["vendor_name"],
            })
            _kg_link(links, vendid, sid, "PRODUCES")
        # Only render real versions; placeholders are collapsed when the vuln
        # subgraph links software straight to the vulnerability below.
        if row["version_id"] is not None and not _is_placeholder_version(row["version_string"]):
            verid = f"Version:{row['version_id']}"
            _kg_node(nodes, verid, row["version_string"], "Version", {
                "id": row["version_id"], "version_string": row["version_string"],
            })
            _kg_link(links, sid, verid, "HAS_VERSION")
        if row["vuln_id"]:
            _kg_add_vulnerability_subgraph(db, row["vuln_id"], nodes, links, max(1, limit // 4))


def _kg_payload(nodes: dict, links: dict):
    return {"nodes": list(nodes.values()), "links": list(links.values())}


def _kg_largest_component(nodes: dict, links: dict) -> tuple[dict, dict]:
    """Keep only the single largest connected component so the overview renders
    as one big graph instead of scattered islands."""
    if not nodes:
        return nodes, links

    parent: dict[str, str] = {nid: nid for nid in nodes}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for src, tgt, _ in links:
        if src in parent and tgt in parent:
            union(src, tgt)

    sizes: dict[str, int] = {}
    for nid in nodes:
        root = find(nid)
        sizes[root] = sizes.get(root, 0) + 1
    if not sizes:
        return nodes, links
    biggest = max(sizes, key=lambda r: sizes[r])
    keep = {nid for nid in nodes if find(nid) == biggest}

    kept_nodes = {nid: n for nid, n in nodes.items() if nid in keep}
    kept_links = {
        k: v for k, v in links.items()
        if k[0] in keep and k[1] in keep
    }
    return kept_nodes, kept_links


def _kg_add_attack_subgraph(db, attack_id: int, nodes: dict, links: dict, limit: int) -> None:
    """Attack neighbourhood: the vulnerabilities it exploits (expanded into their
    own subgraphs so impacts and affected software come along)."""
    a = db.execute("SELECT id, name, description FROM attack WHERE id=?", (attack_id,)).fetchone()
    if not a:
        return
    aid = f"Attack:{a['id']}"
    _kg_node(nodes, aid, a["name"] or str(a["id"]), "Attack", dict(a))
    for row in db.execute(
        "SELECT vuln_id FROM attack_exploits_vuln WHERE attack_id=? LIMIT ?", (attack_id, limit)).fetchall():
        _kg_add_vulnerability_subgraph(db, row["vuln_id"], nodes, links, max(2, limit // 4))


def _kg_add_impact_subgraph(db, impact_id: int, nodes: dict, links: dict, limit: int) -> None:
    """Impact neighbourhood: the vulnerabilities that result in it."""
    i = db.execute("SELECT id, name, description FROM impact WHERE id=?", (impact_id,)).fetchone()
    if not i:
        return
    iid = f"Impact:{i['id']}"
    _kg_node(nodes, iid, i["name"] or str(i["id"]), "Impact", dict(i))
    for row in db.execute(
        "SELECT vuln_id FROM vuln_results_in_impact WHERE impact_id=? LIMIT ?", (impact_id, limit)).fetchall():
        _kg_add_vulnerability_subgraph(db, row["vuln_id"], nodes, links, max(2, limit // 4))


@app.route("/api/kg/status")
def kg_status():
    db = get_db()
    try:
        def _c(sql):
            try:
                return db.execute(sql).fetchone()[0]
            except sqlite3.Error:
                return 0
        counts = {
            "vulnerabilities": _c("SELECT COUNT(*) FROM vulnerability"),
            "vulnerability_types": _c("SELECT COUNT(*) FROM vulnerability_type"),
            "software": _c("SELECT COUNT(*) FROM software"),
            "vendors": _c("SELECT COUNT(*) FROM vendor"),
            "attacks": _c("SELECT COUNT(*) FROM attack"),
            "impacts": _c("SELECT COUNT(*) FROM impact"),
        }
        return jsonify({"ok": True, "backend": "sqlite", "counts": counts})
    finally:
        db.close()


@app.route("/api/kg/overview")
def kg_overview():
    """One large, connected knowledge graph.

    Anchored on the densest VulnerabilityType (CWE) hubs so vulns that share a
    type, and software that shares a vendor, stitch into a single component.
    Only the largest connected component is returned, so the view is never a
    set of scattered islands.
    """
    limit = min(int(request.args.get("limit", 700)), 1500)
    # `seeds` kept for backward compatibility but no longer drives the build.
    hub_types = min(int(request.args.get("types", 30)), 60)
    db = get_db()
    nodes: dict[str, dict] = {}
    links: dict[tuple[str, str, str], dict] = {}
    try:
        type_rows = db.execute(
            """SELECT type_id, COUNT(*) AS c
               FROM vulnerability_is_a
               GROUP BY type_id
               ORDER BY c DESC
               LIMIT ?""",
            (hub_types,),
        ).fetchall()

        # Budget vulns per hub so the total stays within `limit`.
        per_type = max(8, limit // max(len(type_rows), 1) // 3)
        sw_per_vuln = 3

        for trow in type_rows:
            vrows = db.execute(
                """SELECT vuln_id FROM vulnerability_is_a
                   WHERE type_id=?
                   ORDER BY vuln_id DESC
                   LIMIT ?""",
                (trow["type_id"], per_type),
            ).fetchall()
            for vrow in vrows:
                _kg_add_vulnerability_subgraph(
                    db, vrow["vuln_id"], nodes, links, sw_per_vuln
                )
            if len(nodes) >= limit:
                break

        nodes, links = _kg_largest_component(nodes, links)
        payload = _kg_payload(nodes, links)
        payload["meta"] = {
            "node_count": len(payload["nodes"]),
            "link_count": len(payload["links"]),
            "hub_types": len(type_rows),
        }
        return jsonify(payload)
    finally:
        db.close()


@app.route("/api/kg/search")
def kg_search():
    q = (request.args.get("q") or "").strip()
    limit = min(int(request.args.get("limit", 120)), 300)
    if not q:
        return jsonify({"error": "q is required"}), 400
    like = f"%{q}%"
    db = get_db()
    nodes: dict[str, dict] = {}
    links: dict[tuple[str, str, str], dict] = {}
    try:
        for row in db.execute(
            """SELECT vuln_id FROM vulnerability
               WHERE vuln_id LIKE ? OR title LIKE ? OR description LIKE ?
               LIMIT ?""",
            (like, like, like, limit // 2),
        ).fetchall():
            _kg_add_vulnerability_subgraph(db, row["vuln_id"], nodes, links, max(4, limit // 8))

        for row in db.execute(
            "SELECT id FROM vulnerability_type WHERE id LIKE ? OR description LIKE ? LIMIT ?",
            (like, like, limit // 4),
        ).fetchall():
            _kg_add_type_subgraph(db, row["id"], nodes, links, max(8, limit // 4))

        for row in db.execute(
            "SELECT id FROM software WHERE name LIKE ? LIMIT ?",
            (like, limit // 4),
        ).fetchall():
            _kg_add_software_subgraph(db, row["id"], nodes, links, max(8, limit // 4))

        for row in db.execute(
            """SELECT s.id FROM software s
               JOIN vendor v ON v.id=s.vendor_id
               WHERE v.name LIKE ? LIMIT ?""",
            (like, limit // 4),
        ).fetchall():
            _kg_add_software_subgraph(db, row["id"], nodes, links, max(8, limit // 4))

        # Attack / Impact: match by name/description and expand into the
        # vulnerabilities they connect to.
        try:
            for row in db.execute(
                "SELECT id FROM attack WHERE name LIKE ? OR description LIKE ? LIMIT ?",
                (like, like, limit // 4),
            ).fetchall():
                _kg_add_attack_subgraph(db, row["id"], nodes, links, max(6, limit // 6))
            for row in db.execute(
                "SELECT id FROM impact WHERE name LIKE ? OR description LIKE ? LIMIT ?",
                (like, like, limit // 4),
            ).fetchall():
                _kg_add_impact_subgraph(db, row["id"], nodes, links, max(6, limit // 6))
        except sqlite3.Error:
            pass

        return jsonify(_kg_payload(nodes, links))
    finally:
        db.close()


@app.route("/api/kg/neighbors", methods=["POST"])
def kg_neighbors():
    body = request.get_json(force=True) or {}
    node_id = (body.get("id") or "").strip()
    limit = min(int(body.get("limit", 120)), 300)
    if ":" not in node_id:
        return jsonify({"error": "id must be in Type:value format"}), 400
    typ, raw = node_id.split(":", 1)
    db = get_db()
    nodes: dict[str, dict] = {}
    links: dict[tuple[str, str, str], dict] = {}
    try:
        if typ == "Vulnerability":
            _kg_add_vulnerability_subgraph(db, raw, nodes, links, limit)
        elif typ == "VulnerabilityType":
            _kg_add_type_subgraph(db, raw, nodes, links, limit)
        elif typ == "Software":
            _kg_add_software_subgraph(db, int(raw), nodes, links, limit)
        elif typ == "Version":
            row = db.execute("SELECT vuln_id FROM sw_version_vulnerable_to WHERE sw_version_id=?", (raw,)).fetchone()
            if row:
                _kg_add_vulnerability_subgraph(db, row["vuln_id"], nodes, links, limit)
        elif typ == "Vendor":
            for row in db.execute("SELECT id FROM software WHERE vendor_id=? LIMIT ?", (raw, limit)).fetchall():
                _kg_add_software_subgraph(db, row["id"], nodes, links, max(8, limit // 4))
        elif typ == "Attack":
            _kg_add_attack_subgraph(db, int(raw), nodes, links, limit)
        elif typ == "Impact":
            _kg_add_impact_subgraph(db, int(raw), nodes, links, limit)
        return jsonify(_kg_payload(nodes, links))
    finally:
        db.close()


# ── URL Extraction Pipeline ──

@app.route("/api/extract", methods=["POST"])
def extract_from_url():
    """Crawl a URL, run the ontology-aware extraction pipeline, optionally insert into DB."""
    import asyncio
    body = request.get_json(force=True)
    url = (body.get("url") or "").strip()
    skip_db = bool(body.get("skip_db", False))

    if not url:
        return jsonify({"error": "url is required"}), 400
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "url must start with http:// or https://"}), 400

    from extract_pipeline import run_pipeline

    try:
        result = asyncio.run(run_pipeline(url, skip_db=skip_db))
    except Exception as e:
        return jsonify({"error": f"Pipeline error: {e}", "step": "pipeline"}), 500

    if result.errors and not result.canonical_entities:
        step = "crawl" if any("crawl" in e.lower() for e in result.errors) else "extract"
        # Also register this URL in the tracked list so the user can retry it.
        try:
            _register_url_result(url, status="error", error="; ".join(result.errors)[:500])
        except Exception as _e:
            print(f"[extract] failed to register URL: {_e}")
        return jsonify({
            "error": "; ".join(result.errors),
            "step": step,
            "warnings": result.warnings,
            "markdown": result.markdown,
            "markdown_length": result.markdown_length,
        }), 502 if step == "crawl" else 500

    try:
        total_entities = len(result.canonical_entities or [])
        if skip_db:
            _register_url_result(
                url,
                entities_count=total_entities,
                preview_result=result,
            )
        else:
            _register_url_result(
                url,
                entities_count=total_entities,
                preview_result=result,
                merged=True,
            )
    except Exception as _e:
        print(f"[extract] failed to register URL: {_e}")

    payload = _result_to_api_payload(result)
    payload["cached"] = False
    payload["status"] = "extracted" if skip_db else "merged"
    return jsonify(payload)


# ── Data Source Manager ─────────────────────────────────────────────────

# Auto-seed on first request; cheap because seed_from_yaml is idempotent.
_sources_seeded = False


def _ensure_user_source(db) -> None:
    """Always make sure a catch-all 'user' source exists for manually added URLs."""
    row = db.execute("SELECT 1 FROM data_source WHERE id='user'").fetchone()
    if not row:
        db.execute(
            """INSERT INTO data_source (id, name, tier, category, discovery_type, enabled)
               VALUES ('user', 'User', 0, 'user', 'manual', 1)"""
        )
        db.commit()


def _ensure_sources_seeded() -> None:
    global _sources_seeded
    if _sources_seeded:
        return
    try:
        from extract_pipeline.persist import ensure_persist_schema
        from sources.registry import recover_interrupted_runs, seed_from_yaml
        db = get_db()
        ensure_persist_schema(conn=db)
        # Recovery step: if the previous process died mid-ingestion, its
        # daemon threads are gone but rows may still be marked "running".
        # Guard: if another server instance is already listening, those
        # "running" rows belong to it and are genuinely alive — a stray
        # second `python app.py` must not cancel them.
        import socket
        with socket.socket() as _s:
            _other_server_alive = _s.connect_ex(("127.0.0.1", 5093)) == 0
        repaired = 0 if _other_server_alive else recover_interrupted_runs(db)
        seed_from_yaml(db)
        _ensure_user_source(db)
        db.close()
        if repaired:
            print(f"[sources] recovered {repaired} interrupted runs")
    except Exception as e:
        print(f"[sources] seed_from_yaml failed: {e}")
    _sources_seeded = True


# Ensure interrupted running jobs are cleared right after server startup.
_ensure_sources_seeded()


def _register_url_result(
    url: str,
    *,
    status: str | None = None,
    entities_count: int | None = None,
    error: str | None = None,
    preview_result=None,
    merged: bool = False,
) -> None:
    """UPSERT a manually-extracted URL into the source_url list.

    Lets a user enter arbitrary URLs at the top of the page and still see
    them as a row in the unified URL registry, with the freshest status.
    If the URL is already tracked under another source, update that row
    in place instead of duplicating it under the 'user' source.
    """
    import time
    db = get_db()
    try:
        _ensure_user_source(db)
        row = db.execute("SELECT * FROM source_url WHERE url=?", (url,)).fetchone()
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        raw_status = row["status"] if row else "never"
        next_status = status or raw_status
        preview_json = row["preview_json"] if row else None
        previewed_at = row["previewed_at"] if row else None
        merged_at = row["merged_at"] if row else None
        last_ingested = row["last_ingested"] if row else None

        if preview_result is not None:
            preview_json = _serialize_preview_result(preview_result)
            previewed_at = now
            if entities_count is None:
                entities_count = len(preview_result.canonical_entities or [])
            if status is None:
                next_status = raw_status if raw_status in ("fresh", "stale") else "never"
            error = None

        if merged:
            next_status = "fresh"
            merged_at = now
            last_ingested = now
            error = None

        if next_status == "fresh" and not last_ingested:
            last_ingested = now

        if row:
            db.execute(
                """UPDATE source_url
                   SET status=?, last_ingested=?, last_checked=?,
                       entities_count=?, error=?, preview_json=?,
                       previewed_at=?, merged_at=?
                   WHERE id=?""",
                (
                    next_status,
                    last_ingested,
                    now,
                    entities_count,
                    error,
                    preview_json,
                    previewed_at,
                    merged_at,
                    row["id"],
                ),
            )
        else:
            db.execute(
                "DELETE FROM source_url_deleted WHERE source_id='user' AND url=?",
                (url,),
            )
            db.execute(
                """INSERT INTO source_url
                   (source_id, url, status, last_ingested, last_checked, entities_count, error,
                    preview_json, previewed_at, merged_at)
                   VALUES ('user', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    url,
                    next_status,
                    last_ingested,
                    now,
                    entities_count,
                    error,
                    preview_json,
                    previewed_at,
                    merged_at,
                ),
            )
        db.commit()
    finally:
        db.close()


# ── Flat URL list (simplified UI) ────────────────────────────────────────

@app.route("/api/urls", methods=["GET"])
def api_urls_list():
    """Return every tracked URL across all sources, flat and status-ordered."""
    _ensure_sources_seeded()
    db = get_db()
    rows = db.execute(
        """SELECT id, url, status, entities_count, last_ingested, error, source_id,
                  preview_json, previewed_at, merged_at
           FROM source_url"""
    ).fetchall()
    db.close()
    status_order = {"error": 0, "never": 1, "stale": 2, "extracted": 3, "merged": 4}
    urls = [_url_row_to_payload(r) for r in rows]
    urls.sort(key=lambda r: r["id"], reverse=True)
    urls.sort(key=lambda r: str(r.get("last_activity") or ""), reverse=True)
    urls.sort(key=lambda r: 1 if not r.get("last_activity") else 0)
    urls.sort(key=lambda r: status_order.get(r["status"], 5))
    return jsonify({"urls": urls})


@app.route("/api/urls", methods=["POST"])
def api_urls_add():
    """Add a URL to the tracked list. If already present, return the existing row."""
    _ensure_sources_seeded()
    body = request.get_json(force=True) or {}
    url = (body.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "url must start with http:// or https://"}), 400
    db = get_db()
    _ensure_user_source(db)
    existing = db.execute("SELECT * FROM source_url WHERE url=?", (url,)).fetchone()
    if existing:
        db.close()
        return jsonify({"url": dict(existing), "created": False})
    cur = db.cursor()
    cur.execute(
        "DELETE FROM source_url_deleted WHERE source_id='user' AND url=?",
        (url,),
    )
    cur.execute(
        """INSERT INTO source_url (source_id, url, status)
           VALUES ('user', ?, 'never')""",
        (url,),
    )
    db.commit()
    row = db.execute("SELECT * FROM source_url WHERE id=?", (cur.lastrowid,)).fetchone()
    db.close()
    return jsonify({"url": dict(row), "created": True})


@app.route("/api/urls", methods=["DELETE"])
def api_urls_clear_all():
    """Delete every tracked URL row from the flat list."""
    _ensure_sources_seeded()
    db = get_db()
    try:
        running = db.execute(
            "SELECT COUNT(*) FROM ingestion_run WHERE status='running'"
        ).fetchone()[0]
        if running:
            return jsonify({
                "error": f"{running} extraction task(s) still running; stop them first"
            }), 409

        cur = db.cursor()
        cur.execute(
            """INSERT OR REPLACE INTO source_url_deleted (source_id, url, deleted_at)
               SELECT source_id, url, CURRENT_TIMESTAMP FROM source_url"""
        )
        cur.execute("DELETE FROM source_url")
        deleted = cur.rowcount
        db.commit()
        return jsonify({"ok": True, "deleted": deleted})
    finally:
        db.close()


@app.route("/api/urls/<int:url_id>", methods=["DELETE"])
def api_urls_delete(url_id: int):
    from sources.registry import delete_source_url
    db = get_db()
    ok = delete_source_url(db, url_id)
    db.close()
    return jsonify({"ok": ok})


@app.route("/api/urls/<int:url_id>/preview", methods=["POST"])
def api_urls_preview(url_id: int):
    from sources.registry import get_source_url
    import asyncio
    from extract_pipeline import run_pipeline

    _ensure_sources_seeded()
    db = get_db()
    row = get_source_url(db, url_id)
    db.close()
    if not row:
        return jsonify({"error": "url not found"}), 404

    display_status = _display_status(dict(row))
    if row.get("preview_json") and display_status in ("extracted", "merged"):
        try:
            result = _deserialize_preview_result(row["preview_json"])
            payload = _result_to_api_payload(result)
            payload["cached"] = True
            payload["status"] = display_status
            return jsonify(payload)
        except Exception as e:
            print(f"[preview] failed to decode cached preview for {url_id}: {e}")

    try:
        result = asyncio.run(run_pipeline(row["url"], skip_db=True))
    except Exception as e:
        _register_url_result(row["url"], status="error", error=f"Pipeline error: {e}")
        return jsonify({"error": f"Pipeline error: {e}"}), 500

    if result.errors and not result.canonical_entities:
        step = "crawl" if any("crawl" in e.lower() for e in result.errors) else "extract"
        _register_url_result(row["url"], status="error", error="; ".join(result.errors)[:500])
        return jsonify({
            "error": "; ".join(result.errors),
            "step": step,
            "warnings": result.warnings,
            "markdown": result.markdown,
            "markdown_length": result.markdown_length,
        }), 502 if step == "crawl" else 500

    _register_url_result(
        row["url"],
        entities_count=len(result.canonical_entities or []),
        preview_result=result,
    )
    payload = _result_to_api_payload(result)
    payload["cached"] = False
    payload["status"] = "extracted"
    return jsonify(payload)


@app.route("/api/urls/<int:url_id>/merge", methods=["POST"])
def api_urls_merge(url_id: int):
    from extract_pipeline.persist import persist_canonical
    from sources.freshness import _sha1
    from sources.registry import get_source_url

    _ensure_sources_seeded()
    db = get_db()
    row = get_source_url(db, url_id)
    db.close()
    if not row:
        return jsonify({"error": "url not found"}), 404
    if not row.get("preview_json"):
        return jsonify({"error": "no cached extraction preview for this URL"}), 400

    try:
        result = _deserialize_preview_result(row["preview_json"])
    except Exception as e:
        return jsonify({"error": f"invalid cached preview: {e}"}), 500

    try:
        stats = persist_canonical(
            result.canonical_entities,
            result.canonical_relations,
            source_url=result.url,
        )
        result.db_stats = stats
    except Exception as e:
        _register_url_result(row["url"], status="error", error=f"DB persist failed: {e}")
        return jsonify({"error": f"DB persist failed: {e}"}), 500

    md = result.markdown or ""
    content_hash = _sha1(md) if md else None

    db = get_db()
    try:
        db.execute(
            """UPDATE source_url
               SET status='fresh',
                   last_ingested=?,
                   last_checked=?,
                   merged_at=?,
                   content_hash=?,
                   entities_count=?,
                   error=NULL
               WHERE id=?""",
            (
                _now_iso(),
                _now_iso(),
                _now_iso(),
                content_hash,
                len(result.canonical_entities or []),
                url_id,
            ),
        )
        db.commit()
    finally:
        db.close()

    payload = _result_to_api_payload(result)
    payload["cached"] = True
    payload["status"] = "merged"
    return jsonify(payload)


@app.route("/api/urls/<int:url_id>/extract", methods=["POST"])
def api_urls_extract(url_id: int):
    from sources.registry import get_source_url
    from sources.ingest import ingest_url_async
    db = get_db()
    row = get_source_url(db, url_id)
    db.close()
    if not row:
        return jsonify({"error": "url not found"}), 404
    run_id = ingest_url_async(row)
    return jsonify({"run_id": run_id, "url_id": url_id, "status": "running"})


@app.route("/api/sources", methods=["GET"])
def api_sources_list():
    _ensure_sources_seeded()
    from sources.registry import list_sources, overall_stats
    db = get_db()
    data = list_sources(db)
    totals = overall_stats(db)
    db.close()
    return jsonify({"sources": data, "totals": totals})


@app.route("/api/sources/seed", methods=["POST"])
def api_sources_seed():
    from sources.registry import seed_from_yaml
    db = get_db()
    stats = seed_from_yaml(db)
    db.close()
    global _sources_seeded
    _sources_seeded = True
    return jsonify(stats)


@app.route("/api/sources/<source_id>", methods=["GET"])
def api_source_detail(source_id):
    _ensure_sources_seeded()
    from sources.registry import get_source, list_source_urls, list_recent_runs
    db = get_db()
    src = get_source(db, source_id)
    if not src:
        db.close(); return jsonify({"error": f"unknown source: {source_id}"}), 404
    urls = list_source_urls(db, source_id, limit=int(request.args.get("limit", 200)))
    runs = list_recent_runs(db, source_id=source_id, limit=20)
    db.close()
    return jsonify({"source": src, "urls": urls, "recent_runs": runs})


@app.route("/api/sources/<source_id>/enable", methods=["POST"])
def api_source_enable(source_id):
    from sources.registry import set_source_enabled
    db = get_db()
    ok = set_source_enabled(db, source_id, True)
    db.close()
    return jsonify({"ok": ok, "source_id": source_id, "enabled": True})


@app.route("/api/sources/<source_id>/disable", methods=["POST"])
def api_source_disable(source_id):
    from sources.registry import set_source_enabled
    db = get_db()
    ok = set_source_enabled(db, source_id, False)
    db.close()
    return jsonify({"ok": ok, "source_id": source_id, "enabled": False})


@app.route("/api/sources/<source_id>/urls", methods=["POST"])
def api_source_add_url(source_id):
    from sources.registry import add_source_url
    body = request.get_json(force=True) or {}
    url = (body.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "url must start with http(s)://"}), 400
    db = get_db()
    row = add_source_url(db, source_id, url, title=body.get("title"))
    db.close()
    return jsonify(row or {"error": "failed"})


@app.route("/api/sources/urls/<int:url_id>", methods=["DELETE"])
def api_source_delete_url(url_id):
    from sources.registry import delete_source_url
    db = get_db()
    ok = delete_source_url(db, url_id)
    db.close()
    return jsonify({"ok": ok})


@app.route("/api/sources/<source_id>/check", methods=["POST"])
def api_source_check_freshness(source_id):
    """Run freshness checks on all URLs of a source (parallelised)."""
    from sources.registry import list_source_urls
    from sources.freshness import check_many
    body = request.get_json(silent=True) or {}
    deep = bool(body.get("deep", True))
    db = get_db()
    urls = list_source_urls(db, source_id, limit=500)
    if not urls:
        db.close(); return jsonify({"checked": 0, "results": []})
    results = check_many(db, urls, deep=deep)
    db.close()
    summary = {
        "checked": len(results),
        "fresh": sum(1 for r in results if r["status"] == "fresh"),
        "stale": sum(1 for r in results if r["status"] == "stale"),
        "never": sum(1 for r in results if r["status"] == "never"),
        "error": sum(1 for r in results if r["status"] == "error"),
    }
    return jsonify({"summary": summary, "results": results})


@app.route("/api/sources/<source_id>/discover", methods=["POST"])
def api_source_discover(source_id):
    from sources.discovery import discover_urls
    body = request.get_json(silent=True) or {}
    max_new = int(body.get("max_new", 30))
    db = get_db()
    out = discover_urls(db, source_id, max_new=max_new)
    db.close()
    return jsonify(out)


@app.route("/api/sources/discover-all", methods=["POST"])
def api_sources_discover_all():
    """Run discovery for every source with a non-manual discovery type.

    Used by the UI to populate 0-URL sources in one click. Runs in-process
    (not background) so the response reflects the outcome per source.
    """
    _ensure_sources_seeded()
    from sources.discovery import discover_urls
    from sources.registry import list_sources
    body = request.get_json(silent=True) or {}
    max_new = int(body.get("max_new", 30))
    db = get_db()
    sources = list_sources(db)
    total_added = 0
    total_discovered = 0
    per_source = []
    for s in sources:
        if (s.get("discovery_type") or "manual").lower() == "manual":
            continue
        try:
            out = discover_urls(db, s["id"], max_new=max_new)
        except Exception as e:  # noqa: BLE001
            per_source.append({"source_id": s["id"], "error": str(e)})
            continue
        total_added += out.get("added", 0)
        total_discovered += out.get("discovered", 0)
        per_source.append({
            "source_id": s["id"],
            "discovered": out.get("discovered", 0),
            "added": out.get("added", 0),
            "warnings": out.get("warnings", []),
        })
    db.close()
    return jsonify({
        "total_discovered": total_discovered,
        "total_added": total_added,
        "per_source": per_source,
    })


@app.route("/api/sources/<source_id>/ingest", methods=["POST"])
def api_source_ingest(source_id):
    from sources.ingest import ingest_source_async
    body = request.get_json(silent=True) or {}
    only_stale = bool(body.get("only_stale", True))
    limit = int(body.get("limit", 20))
    db = get_db()
    out = ingest_source_async(db, source_id, only_stale=only_stale, limit=limit)
    db.close()
    return jsonify(out)


@app.route("/api/sources/<source_id>/extract-new", methods=["POST"])
def api_source_extract_new(source_id):
    """One-click: discover any new URLs for this source, then ingest all
    URLs whose status is 'never' or 'stale'. Returns counts + background
    run ids the UI can poll via /api/sources/runs."""
    from sources.discovery import discover_urls
    from sources.ingest import ingest_source_async
    body = request.get_json(silent=True) or {}
    max_new = int(body.get("max_new", 30))
    limit = int(body.get("limit", 20))
    db = get_db()
    discovery = discover_urls(db, source_id, max_new=max_new)
    ingest = ingest_source_async(db, source_id, only_stale=True, limit=limit)
    db.close()
    return jsonify({
        "discovered": discovery["discovered"],
        "added": discovery["added"],
        "queued": ingest["queued"],
        "run_ids": ingest["run_ids"],
        "warnings": discovery.get("warnings", []),
    })


@app.route("/api/sources/urls/<int:url_id>/ingest", methods=["POST"])
def api_source_url_ingest(url_id):
    from sources.registry import get_source_url
    from sources.ingest import ingest_url_async
    db = get_db()
    row = get_source_url(db, url_id)
    db.close()
    if not row:
        return jsonify({"error": "url not found"}), 404
    run_id = ingest_url_async(row)
    return jsonify({"run_id": run_id, "url_id": url_id, "status": "running"})


@app.route("/api/sources/runs", methods=["GET"])
def api_source_runs():
    _ensure_sources_seeded()
    from sources.registry import list_recent_runs
    db = get_db()
    runs = list_recent_runs(
        db,
        source_id=request.args.get("source_id"),
        limit=int(request.args.get("limit", 50)),
    )
    db.close()
    return jsonify({"runs": runs})


@app.route("/api/sources/runs/<int:run_id>/stop", methods=["POST"])
def api_source_run_stop(run_id: int):
    _ensure_sources_seeded()
    from sources.registry import cancel_run
    db = get_db()
    ok = cancel_run(db, run_id)
    db.close()
    return jsonify({"ok": ok, "run_id": run_id, "status": "cancelled" if ok else "not_running"})


@app.route("/api/sources/runs/stop-all", methods=["POST"])
def api_source_runs_stop_all():
    _ensure_sources_seeded()
    from sources.registry import cancel_running_runs
    body = request.get_json(silent=True) or {}
    source_id = body.get("source_id")
    db = get_db()
    n = cancel_running_runs(db, source_id=source_id)
    db.close()
    return jsonify({"cancelled": n, "source_id": source_id})


@app.route("/api/extract/preview", methods=["POST"])
def extract_preview():
    """Crawl-only: return the markdown without extraction."""
    import asyncio
    body = request.get_json(force=True)
    url = (body.get("url") or "").strip()

    if not url:
        return jsonify({"error": "url is required"}), 400
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "url must start with http:// or https://"}), 400

    from extract_pipeline import crawl_url_to_markdown

    try:
        markdown, err = asyncio.run(crawl_url_to_markdown(url))
    except Exception as e:
        return jsonify({"error": f"Crawl error: {e}"}), 500

    if err:
        return jsonify({"error": f"Failed to crawl: {err}"}), 502

    return jsonify({
        "url": url,
        "markdown": markdown,
        "markdown_length": len(markdown),
    })


if __name__ == "__main__":
    # Internal-only port: the CRA dev server on 3508 proxies /api here.
    app.run(debug=False, host="0.0.0.0", port=5093)
