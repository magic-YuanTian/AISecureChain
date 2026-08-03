"""
Duplication detection + ``same_as`` linking.

Three levels of equivalence:

    Level 1 — Exact canonical match
        Same normalized identifier already exists in the DB. Reuse the PK,
        do NOT insert a new row.

    Level 2 — Normalized / alias match
        The name differs in case/whitespace/punctuation/known aliases
        (e.g. "OpenAI Inc." ≡ "openai"). We reuse the existing entity and
        record the new spelling in ``entity_alias`` so future lookups are
        O(1).

    Level 3 — Cross-identity match
        Two entities with different canonical keys describe the same
        real-world thing (e.g. a page contains both CVE-X and GHSA-Y for
        the same advisory). We insert BOTH records and write a row in
        ``entity_same_as`` so downstream consumers can unify them.

Every ``same_as`` edge carries a ``reason`` (why we think they're the same)
and a ``confidence`` so a human can audit / override later.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable


# ── Normalization ────────────────────────────────────────────────────────────

# Only strip unambiguous legal-entity suffixes. Words like "AI", "Labs",
# "Tech" are NOT stripped because they are frequently part of the real name
# (e.g. "LangChain AI" is a different thing from "LangChain" in many contexts,
# and a human-authored alias in VENDOR_ALIASES below handles those).
_CORP_SUFFIX_RE = re.compile(
    r"\s+(inc|inc\.|llc|ltd|ltd\.|limited|corp|corp\.|corporation|co|co\.|gmbh|sa|s\.a\.|ag|plc|bv|b\.v\.)\.?$",
    flags=re.IGNORECASE,
)

# Hand-curated aliases. Keys are normalized form; value is canonical normalized name.
VENDOR_ALIASES: dict[str, str] = {
    "open ai": "openai",
    "open-ai": "openai",
    "openai inc": "openai",
    "google llc": "google",
    "google inc": "google",
    "alphabet": "google",
    "microsoft corp": "microsoft",
    "microsoft corporation": "microsoft",
    "meta platforms": "meta",
    "meta ai": "meta",
    "facebook": "meta",
    "amazon web services": "aws",
    "amazon": "aws",
    "hugging face": "huggingface",
    "hugging-face": "huggingface",
    "langchain ai": "langchain",
    "anthropic pbc": "anthropic",
}


def normalize_name(name: str) -> str:
    """Aggressive normalization for vendor/software/license names."""
    if not name:
        return ""
    s = name.strip().lower()
    # Replace punctuation / dashes / underscores with space
    s = re.sub(r"[\-_/]+", " ", s)
    s = re.sub(r"[^\w\s.]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    # Strip corporate suffixes iteratively
    prev = None
    while prev != s:
        prev = s
        s = _CORP_SUFFIX_RE.sub("", s).strip()
    return s


def normalize_vendor(name: str) -> str:
    s = normalize_name(name)
    return VENDOR_ALIASES.get(s, s)


def normalize_vuln_id(vid: str) -> str:
    if not vid:
        return ""
    return re.sub(r"\s+", "", vid.strip().upper())


def normalize_cwe_id(cid: str) -> str:
    if not cid:
        return ""
    s = cid.strip().upper().replace(" ", "")
    if re.fullmatch(r"\d+", s):
        s = f"CWE-{s}"
    return s


# ── Level 1 / 2 lookups against an open SQLite connection ────────────────────

def find_existing_vendor(cur: sqlite3.Cursor, name: str) -> int | None:
    """Return vendor.id for any name that normalizes to the same form."""
    norm = normalize_vendor(name)
    if not norm:
        return None
    cur.execute(
        "SELECT entity_key FROM entity_alias WHERE entity_type = 'Vendor' AND alias_norm = ?",
        (norm,),
    )
    row = cur.fetchone()
    if row:
        try:
            return int(row[0])
        except (TypeError, ValueError):
            pass
    # Fallback: scan existing vendors (small table). Cache via alias on hit.
    cur.execute("SELECT id, name FROM vendor")
    for vid, vname in cur.fetchall():
        if normalize_vendor(vname) == norm:
            return vid
    return None


def find_existing_software(
    cur: sqlite3.Cursor, name: str, vendor_id: int | None
) -> int | None:
    norm = normalize_name(name)
    if not norm:
        return None
    cur.execute(
        "SELECT id, name FROM software WHERE IFNULL(vendor_id, -1) = IFNULL(?, -1)",
        (vendor_id,),
    )
    for sid, sname in cur.fetchall():
        if normalize_name(sname) == norm:
            return sid
    # The incoming record has no vendor: fall back to an unambiguous name-only
    # match so we reuse an existing (often better-specified, vendor-bearing)
    # row instead of creating a vendorless duplicate. Only reuse when exactly
    # one existing software shares the name, to avoid merging distinct products.
    if vendor_id is None:
        cur.execute("SELECT id, name FROM software")
        matches = [sid for sid, sname in cur.fetchall() if normalize_name(sname) == norm]
        if len(matches) == 1:
            return matches[0]
    return None


def find_existing_license(cur: sqlite3.Cursor, name: str) -> int | None:
    norm = normalize_name(name)
    if not norm:
        return None
    cur.execute("SELECT id, name FROM license")
    for lid, lname in cur.fetchall():
        if normalize_name(lname) == norm:
            return lid
    return None


def find_existing_vuln(cur: sqlite3.Cursor, vuln_id: str) -> str | None:
    norm = normalize_vuln_id(vuln_id)
    if not norm:
        return None
    cur.execute("SELECT vuln_id FROM vulnerability WHERE UPPER(vuln_id) = ?", (norm,))
    row = cur.fetchone()
    return row[0] if row else None


def register_alias(
    cur: sqlite3.Cursor, entity_type: str, alias_norm: str, entity_key: str | int
) -> None:
    if not alias_norm:
        return
    cur.execute(
        "INSERT OR IGNORE INTO entity_alias (entity_type, alias_norm, entity_key) VALUES (?, ?, ?)",
        (entity_type, alias_norm, str(entity_key)),
    )


# ── Level 3: cross-identity same_as detection ────────────────────────────────

# Extract vuln-ID-like tokens from arbitrary strings
_VULN_ID_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,7}|GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}|AVID-\d{4}-V\d{3})\b"
)


def _collect_vuln_id_mentions(attrs: dict[str, Any]) -> set[str]:
    """Find any vuln-ID-like token in title/description/references."""
    haystack: list[str] = []
    for k in ("title", "description", "credit"):
        v = attrs.get(k)
        if isinstance(v, str):
            haystack.append(v)
    refs = attrs.get("references")
    if isinstance(refs, list):
        for r in refs:
            if isinstance(r, str):
                haystack.append(r)
    blob = " ".join(haystack)
    return {normalize_vuln_id(m) for m in _VULN_ID_RE.findall(blob)}


@dataclass
class SameAsPair:
    entity_type: str
    left_key: str
    right_key: str
    confidence: float
    reason: str


def detect_vuln_same_as(vulns: list[dict[str, Any]]) -> list[SameAsPair]:
    """
    Given a list of vulnerability records (each a dict with ``vuln_id`` and
    optional ``title``/``description``/``references``), return ``same_as``
    pairs for records that plausibly describe the same vulnerability.

    Heuristics (any ONE is enough to link):

        H1  One record's ``references`` / description explicitly mentions
            the other's vuln_id.
        H2  Same normalized title AND same cvss_base_score.
        H3  Same CVSS vector string AND same date_published (very strong).
    """
    pairs: list[SameAsPair] = []
    seen: set[tuple[str, str]] = set()

    def _add(a_id: str, b_id: str, conf: float, reason: str) -> None:
        if not a_id or not b_id or a_id == b_id:
            return
        key = tuple(sorted([a_id, b_id]))
        if key in seen:
            return
        seen.add(key)
        pairs.append(
            SameAsPair(
                entity_type="Vulnerability",
                left_key=key[0],
                right_key=key[1],
                confidence=conf,
                reason=reason,
            )
        )

    for a in vulns:
        a_id = normalize_vuln_id(a.get("vuln_id", ""))
        if not a_id:
            continue
        a_mentions = _collect_vuln_id_mentions(a)
        a_title = (a.get("title") or "").strip().lower()
        a_cvss = a.get("cvss_base_score")
        a_vec = (a.get("cvss_vector") or "").strip()
        a_date = (a.get("date_published") or "").strip()

        for b in vulns:
            b_id = normalize_vuln_id(b.get("vuln_id", ""))
            if not b_id or a_id >= b_id:
                continue
            b_mentions = _collect_vuln_id_mentions(b)
            b_title = (b.get("title") or "").strip().lower()
            b_cvss = b.get("cvss_base_score")
            b_vec = (b.get("cvss_vector") or "").strip()
            b_date = (b.get("date_published") or "").strip()

            # H1: cross-reference
            if b_id in a_mentions or a_id in b_mentions:
                _add(a_id, b_id, 0.95, "cross-reference in text/references")
                continue

            # H2: same title + same CVSS
            if a_title and a_title == b_title and a_cvss is not None and a_cvss == b_cvss:
                _add(a_id, b_id, 0.85, "identical title + CVSS base score")
                continue

            # H3: same CVSS vector + same publish date
            if a_vec and a_vec == b_vec and a_date and a_date == b_date:
                _add(a_id, b_id, 0.9, "identical CVSS vector + publish date")
                continue

    return pairs


def detect_vendor_same_as(vendors: list[dict[str, Any]]) -> list[SameAsPair]:
    """Vendors that share a normalized name (after alias-strip)."""
    pairs: list[SameAsPair] = []
    seen: set[tuple[str, str]] = set()
    for a in vendors:
        for b in vendors:
            a_name = a.get("name")
            b_name = b.get("name")
            if not a_name or not b_name or a_name >= b_name:
                continue
            if normalize_vendor(a_name) == normalize_vendor(b_name):
                key = tuple(sorted([a_name, b_name]))
                if key in seen:
                    continue
                seen.add(key)
                pairs.append(
                    SameAsPair(
                        entity_type="Vendor",
                        left_key=key[0],
                        right_key=key[1],
                        confidence=0.9,
                        reason="name normalizes to same form",
                    )
                )
    return pairs


def ensure_same_as_schema(cur: sqlite3.Cursor) -> None:
    """Idempotent: create same_as / alias tables if they don't exist."""
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS entity_same_as (
            entity_type TEXT NOT NULL,
            left_key    TEXT NOT NULL,
            right_key   TEXT NOT NULL,
            confidence  REAL NOT NULL DEFAULT 1.0,
            reason      TEXT,
            source_url  TEXT,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (entity_type, left_key, right_key)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS entity_alias (
            entity_type TEXT NOT NULL,
            alias_norm  TEXT NOT NULL,
            entity_key  TEXT NOT NULL,
            PRIMARY KEY (entity_type, alias_norm)
        )
        """
    )


def write_same_as(
    cur: sqlite3.Cursor,
    pairs: Iterable[SameAsPair],
    source_url: str | None = None,
) -> int:
    n = 0
    for p in pairs:
        cur.execute(
            """
            INSERT OR IGNORE INTO entity_same_as
                (entity_type, left_key, right_key, confidence, reason, source_url)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (p.entity_type, p.left_key, p.right_key, p.confidence, p.reason, source_url),
        )
        if cur.rowcount:
            n += 1
    return n
