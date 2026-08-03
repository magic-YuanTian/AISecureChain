"""
Persist-layer tests — verify that duplication checks work end-to-end:

    * Re-inserting identical content → 0 new entity rows.
    * Re-inserting with alias spelling → 0 new entity rows + alias recorded.
    * Cross-reference vulns → both rows present + same_as edge.
"""

from __future__ import annotations

import sqlite3

from extract_pipeline.merger import merge_graphs
from extract_pipeline.models import (
    ExtractedEntity,
    ExtractedRelation,
    ExtractionGraph,
)
from extract_pipeline.persist import persist_canonical


def _mk(cls, lid, **attrs):
    return ExtractedEntity(**{"class": cls, "local_id": lid, "attributes": attrs})


def _vendor_cve_graph(vendor_name="OpenAI", vuln_id="CVE-2024-0101", refs=None):
    refs = refs or []
    return ExtractionGraph(
        entities=[
            _mk("Vendor", "v1", name=vendor_name),
            _mk("Software", "s1", name="ChatGPT", is_ai=True),
            _mk("Version", "ver1", version_string="1.0"),
            _mk("Vulnerability", "vu", vuln_id=vuln_id, title="Test vuln", cvss_base_score=7.5, references=refs),
            _mk("VulnerabilityType", "cwe", id="CWE-79"),
        ],
        relations=[
            ExtractedRelation(predicate="produce", subject="v1", object="s1"),
            ExtractedRelation(predicate="hasVersion", subject="s1", object="ver1"),
            ExtractedRelation(predicate="vulnerableTo", subject="ver1", object="vu"),
            ExtractedRelation(predicate="isA_vulnType", subject="vu", object="cwe"),
        ],
    )


def _count(db, table):
    c = sqlite3.connect(db)
    try:
        return c.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()[0]
    finally:
        c.close()


def _corrupt_vuln_foreign_keys(db):
    c = sqlite3.connect(db)
    try:
        c.execute("PRAGMA foreign_keys=OFF")
        c.executescript(
            """
            CREATE TABLE vulnerability_is_a_bad (
                vuln_id TEXT NOT NULL REFERENCES vulnerability_new(vuln_id),
                type_id TEXT NOT NULL REFERENCES vulnerability_type(id),
                PRIMARY KEY (vuln_id, type_id)
            );
            INSERT INTO vulnerability_is_a_bad SELECT vuln_id, type_id FROM vulnerability_is_a;
            DROP TABLE vulnerability_is_a;
            ALTER TABLE vulnerability_is_a_bad RENAME TO vulnerability_is_a;

            CREATE TABLE sw_version_vulnerable_to_bad (
                sw_version_id INTEGER NOT NULL REFERENCES sw_version(id),
                vuln_id       TEXT NOT NULL REFERENCES vulnerability_new(vuln_id),
                PRIMARY KEY (sw_version_id, vuln_id)
            );
            INSERT INTO sw_version_vulnerable_to_bad
            SELECT sw_version_id, vuln_id FROM sw_version_vulnerable_to;
            DROP TABLE sw_version_vulnerable_to;
            ALTER TABLE sw_version_vulnerable_to_bad RENAME TO sw_version_vulnerable_to;

            CREATE TABLE hw_version_vulnerable_to_bad (
                hw_version_id INTEGER NOT NULL REFERENCES hw_version(id),
                vuln_id       TEXT NOT NULL REFERENCES vulnerability_new(vuln_id),
                PRIMARY KEY (hw_version_id, vuln_id)
            );
            INSERT INTO hw_version_vulnerable_to_bad
            SELECT hw_version_id, vuln_id FROM hw_version_vulnerable_to;
            DROP TABLE hw_version_vulnerable_to;
            ALTER TABLE hw_version_vulnerable_to_bad RENAME TO hw_version_vulnerable_to;

            CREATE TABLE vulnerability_external_id_bad (
                vuln_id     TEXT NOT NULL,
                source      TEXT NOT NULL,
                external_id TEXT NOT NULL,
                PRIMARY KEY (vuln_id, source, external_id),
                FOREIGN KEY (vuln_id) REFERENCES vulnerability_new(vuln_id)
            );
            INSERT INTO vulnerability_external_id_bad
            SELECT vuln_id, source, external_id FROM vulnerability_external_id;
            DROP TABLE vulnerability_external_id;
            ALTER TABLE vulnerability_external_id_bad RENAME TO vulnerability_external_id;
            """
        )
        c.commit()
    finally:
        c.execute("PRAGMA foreign_keys=ON")
        c.close()


# ── Core tests ──────────────────────────────────────────────────────────────

def test_first_insert_populates_all_tables(tmp_db):
    ents, rels = merge_graphs([_vendor_cve_graph()])
    stats = persist_canonical(ents, rels, source_url="https://ex/1", db_path=tmp_db)

    assert stats["vendors_inserted"] == 1
    assert stats["software_inserted"] == 1
    assert stats["versions_inserted"] == 1
    assert stats["vulnerabilities_inserted"] == 1
    assert stats["vuln_types_inserted"] == 1
    assert _count(tmp_db, "vendor") == 1
    assert _count(tmp_db, "software") == 1
    assert _count(tmp_db, "vulnerability") == 1


def test_exact_reinsert_is_idempotent(tmp_db):
    """Re-running with identical input must produce zero new rows."""
    ents, rels = merge_graphs([_vendor_cve_graph()])
    persist_canonical(ents, rels, source_url="https://ex/1", db_path=tmp_db)
    row_counts_before = {
        t: _count(tmp_db, t)
        for t in ["vendor", "software", "sw_version", "vulnerability", "vulnerability_type"]
    }
    stats2 = persist_canonical(ents, rels, source_url="https://ex/1", db_path=tmp_db)
    row_counts_after = {t: _count(tmp_db, t) for t in row_counts_before}

    assert row_counts_before == row_counts_after, "Re-insert must not create new rows"
    assert stats2["vendors_reused"] == 1
    assert stats2["software_reused"] == 1
    assert stats2["vulnerabilities_reused"] == 1
    assert stats2["vendors_inserted"] == 0


def test_alias_spellings_reuse_vendor(tmp_db):
    """OpenAI / Open AI / OpenAI Inc. should all collapse to ONE vendor."""
    g1 = _vendor_cve_graph(vendor_name="OpenAI", vuln_id="CVE-2024-0201")
    ents1, rels1 = merge_graphs([g1])
    persist_canonical(ents1, rels1, source_url="https://ex/a", db_path=tmp_db)

    g2 = _vendor_cve_graph(vendor_name="Open AI", vuln_id="CVE-2024-0202")
    ents2, rels2 = merge_graphs([g2])
    s2 = persist_canonical(ents2, rels2, source_url="https://ex/b", db_path=tmp_db)

    g3 = _vendor_cve_graph(vendor_name="OpenAI Inc.", vuln_id="CVE-2024-0203")
    ents3, rels3 = merge_graphs([g3])
    s3 = persist_canonical(ents3, rels3, source_url="https://ex/c", db_path=tmp_db)

    assert _count(tmp_db, "vendor") == 1, "Alias spellings must all collapse to one vendor row"
    assert s2["vendors_reused"] == 1
    assert s3["vendors_reused"] == 1
    # All 3 vuln rows are distinct (different IDs) though
    assert _count(tmp_db, "vulnerability") == 3


def test_cross_reference_writes_same_as(tmp_db):
    """A page mentioning CVE-X and GHSA-Y referencing each other → same_as edge."""
    g = ExtractionGraph(
        entities=[
            _mk("Vulnerability", "a", vuln_id="CVE-2024-0301",
                references=["https://github.com/advisories/GHSA-aaaa-bbbb-cccc"]),
            _mk("Vulnerability", "b", vuln_id="GHSA-aaaa-bbbb-cccc"),
        ],
        relations=[],
    )
    ents, rels = merge_graphs([g])
    stats = persist_canonical(ents, rels, source_url="https://ex/x", db_path=tmp_db)

    assert _count(tmp_db, "vulnerability") == 2
    assert stats["same_as_edges_written"] == 1

    c = sqlite3.connect(tmp_db)
    rows = c.execute(
        "SELECT entity_type, left_key, right_key, reason FROM entity_same_as"
    ).fetchall()
    c.close()
    assert len(rows) == 1
    assert rows[0][0] == "Vulnerability"
    assert {rows[0][1], rows[0][2]} == {"CVE-2024-0301", "GHSA-AAAA-BBBB-CCCC"}
    assert "cross-reference" in rows[0][3]


def test_vuln_enrichment_fills_blanks_not_overwrites(tmp_db):
    """Re-insert with new fields fills blanks but never overwrites existing values."""
    g1 = ExtractionGraph(entities=[_mk("Vulnerability", "v", vuln_id="CVE-2024-0401", title="original")])
    ents, rels = merge_graphs([g1])
    persist_canonical(ents, rels, db_path=tmp_db)

    g2 = ExtractionGraph(entities=[_mk(
        "Vulnerability", "v", vuln_id="CVE-2024-0401",
        title="NEW title (should be ignored)",
        cvss_severity="HIGH",
    )])
    ents2, rels2 = merge_graphs([g2])
    persist_canonical(ents2, rels2, db_path=tmp_db)

    c = sqlite3.connect(tmp_db)
    row = c.execute("SELECT title, cvss_severity FROM vulnerability WHERE vuln_id=?",
                    ("CVE-2024-0401",)).fetchone()
    c.close()
    assert row[0] == "original", "Existing title must not be overwritten"
    assert row[1] == "HIGH", "Blank field must be filled"


def test_titled_no_id_vuln_is_minted_and_persisted(tmp_db):
    # A finding with a title but no official CVE/GHSA id is no longer dropped:
    # the merger mints an internal AISC id and persist stores it.
    g = ExtractionGraph(entities=[_mk("Vulnerability", "v", title="No id here")])
    ents, rels = merge_graphs([g])
    stats = persist_canonical(ents, rels, db_path=tmp_db)

    assert _count(tmp_db, "vulnerability") == 1
    assert stats["vulnerabilities_inserted"] == 1
    conn = sqlite3.connect(tmp_db)
    vid = conn.execute("SELECT vuln_id FROM vulnerability").fetchone()[0]
    conn.close()
    assert vid.startswith("AISC-")


def test_truly_empty_vuln_skipped(tmp_db):
    # No id AND no title → nothing to mint from → still dropped.
    g = ExtractionGraph(entities=[_mk("Vulnerability", "v")])
    ents, rels = merge_graphs([g])
    persist_canonical(ents, rels, db_path=tmp_db)
    assert _count(tmp_db, "vulnerability") == 0


def test_persist_repairs_stale_vulnerability_new_foreign_keys(tmp_db):
    _corrupt_vuln_foreign_keys(tmp_db)

    ents, rels = merge_graphs([_vendor_cve_graph(vuln_id="CVE-2024-0999")])
    stats = persist_canonical(ents, rels, source_url="https://ex/repair", db_path=tmp_db)

    assert stats["vulnerabilities_inserted"] == 1
    assert _count(tmp_db, "vulnerability") == 1

    c = sqlite3.connect(tmp_db)
    try:
        for table in [
            "vulnerability_is_a",
            "sw_version_vulnerable_to",
            "hw_version_vulnerable_to",
            "vulnerability_external_id",
        ]:
            refs = c.execute(f"PRAGMA foreign_key_list({table})").fetchall()
            assert all(ref[2] != "vulnerability_new" for ref in refs)
    finally:
        c.close()
