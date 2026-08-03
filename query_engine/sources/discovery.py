"""
Auto-discovery of new URLs for a data source.

Given the ``discovery_type`` + ``discovery_url`` stored on a ``data_source``
row, we attempt to extract a fresh list of candidate URLs:

    rss          Parse <item><link> or <entry><link href=...>.
    html_listing Fetch the page and harvest <a href> links that look like
                 detail pages for the same host or an allow-listed pattern.
    api          Best-effort stub — currently returns an empty list and
                 logs a warning; easy to extend per-source later.
    manual       No-op.

All new URLs are UPSERTed into ``source_url`` with status ``never`` so
they show up in the UI as "ready to ingest".

Everything is best-effort: network failures return an empty list + a
warning string, never an exception, so the caller can surface it.
"""

from __future__ import annotations

import re
import sqlite3
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError as e:  # pragma: no cover
    raise RuntimeError("The `requests` package is required for discovery.") from e

from .registry import add_source_url, get_source
from .schema import ensure_schema

USER_AGENT = "AISecureChain-Discovery/1.0"
TIMEOUT = 15

# Conservative per-source cap so one discovery run never dumps thousands
# of URLs into the DB in a single click.
DEFAULT_MAX_NEW = 30


# ── RSS / Atom parsing ────────────────────────────────────────────────────

_RSS_LINK_PATTERNS = [
    ".//item/link",           # RSS 2.0
    ".//{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}link",  # Atom
]


def _parse_feed(xml_bytes: bytes) -> list[tuple[str, str]]:
    """Return list of (url, title) from an RSS/Atom feed."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return []

    out: list[tuple[str, str]] = []

    # RSS 2.0
    for item in root.iterfind(".//item"):
        link_el = item.find("link")
        title_el = item.find("title")
        link = (link_el.text or "").strip() if link_el is not None else ""
        title = (title_el.text or "").strip() if title_el is not None else ""
        if link:
            out.append((link, title))

    # Atom
    ns = {"a": "http://www.w3.org/2005/Atom"}
    for entry in root.iterfind(".//a:entry", ns):
        link_el = entry.find("a:link", ns)
        title_el = entry.find("a:title", ns)
        if link_el is None:
            continue
        href = link_el.attrib.get("href", "").strip()
        title = (title_el.text or "").strip() if title_el is not None else ""
        if href:
            out.append((href, title))

    return out


# ── HTML listing page parsing ────────────────────────────────────────────

class _AnchorCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._in_a = False
        self._current_href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._in_a = True
                self._current_href = href
                self._text = []

    def handle_endtag(self, tag):
        if tag == "a" and self._in_a and self._current_href:
            self.links.append((self._current_href, "".join(self._text).strip()))
            self._in_a = False
            self._current_href = None
            self._text = []

    def handle_data(self, data):
        if self._in_a:
            self._text.append(data)


# Heuristics — detail-page URL patterns we trust per-source.
# Anything matching *keeps* the URL; everything else is filtered out.
DETAIL_URL_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "ghsa": [re.compile(r"/advisories/GHSA-[a-z0-9-]+", re.I)],
    "huntr": [re.compile(r"/bounties/[0-9a-f-]{8,}", re.I)],
    "avid": [re.compile(r"/database/avid-\d{4}-[a-z0-9]+/?", re.I)],
    "patchstack": [re.compile(r"/database/vulnerability/", re.I)],
    "protect-ai": [re.compile(r"/threat-research/[a-z0-9-]+", re.I)],
    "langchain-security": [re.compile(r"/advisories/GHSA-[a-z0-9-]+", re.I)],
    "hf-security": [re.compile(r"/blog/[a-z0-9-]+", re.I)],
    "wiz-research": [re.compile(r"/blog/[a-z0-9-]+", re.I)],
    "lakera": [re.compile(r"/blog/[a-z0-9-]+", re.I)],
}


def _extract_links_from_html(html: bytes, base_url: str, source_id: str) -> list[tuple[str, str]]:
    try:
        text = html.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return []
    parser = _AnchorCollector()
    try:
        parser.feed(text)
    except Exception:  # noqa: BLE001
        return []

    patterns = DETAIL_URL_PATTERNS.get(source_id, [])
    base_host = urlparse(base_url).hostname

    keep: list[tuple[str, str]] = []
    seen = set()
    for href, title in parser.links:
        href = href.strip()
        if not href or href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
            continue
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if base_host and parsed.hostname and parsed.hostname != base_host:
            # Allow github.com when the source already points there.
            if base_host.endswith("github.com") and parsed.hostname.endswith("github.com"):
                pass
            else:
                continue
        if patterns and not any(p.search(parsed.path) for p in patterns):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        keep.append((absolute, title))
    return keep


# ── Public entry point ──────────────────────────────────────────────────

def discover_urls(
    conn: sqlite3.Connection,
    source_id: str,
    *,
    max_new: int = DEFAULT_MAX_NEW,
) -> dict[str, Any]:
    """Discover candidate URLs for ``source_id`` and UPSERT them into ``source_url``.

    Returns a dict:
        {
          "discovered": int,  # URLs found in the feed
          "added":      int,  # URLs actually new to the DB
          "warnings":   list[str],
          "items":      list[{url,title}]  # truncated to max_new
        }
    """
    ensure_schema(conn)
    src = get_source(conn, source_id)
    if not src:
        return {"discovered": 0, "added": 0, "warnings": [f"unknown source: {source_id}"], "items": []}

    dtype = (src.get("discovery_type") or "manual").lower()
    durl = src.get("discovery_url")
    warnings: list[str] = []
    items: list[tuple[str, str]] = []

    if dtype == "manual" or not durl:
        warnings.append(f"source '{source_id}' has no discovery endpoint (type={dtype}).")
        return {"discovered": 0, "added": 0, "warnings": warnings, "items": []}

    try:
        r = requests.get(
            durl,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            timeout=TIMEOUT,
            allow_redirects=True,
        )
        if r.status_code >= 400:
            warnings.append(f"discovery HTTP {r.status_code}")
            return {"discovered": 0, "added": 0, "warnings": warnings, "items": []}
    except Exception as e:  # noqa: BLE001
        warnings.append(f"discovery request failed: {e}")
        return {"discovered": 0, "added": 0, "warnings": warnings, "items": []}

    if dtype == "rss":
        items = _parse_feed(r.content)
    elif dtype == "html_listing":
        items = _extract_links_from_html(r.content, r.url or durl, source_id)
    elif dtype == "api":
        warnings.append(f"API discovery for '{source_id}' not implemented yet.")
    else:
        warnings.append(f"unknown discovery type '{dtype}'.")

    # Trim to a sane limit.
    truncated = items[:max_new]

    # Batch-insert in a single transaction to minimise lock time on the
    # database (background ingest threads may also be writing).
    added = 0
    cur = conn.cursor()
    for url, title in truncated:
        url = url.strip()
        if not url:
            continue
        existed = cur.execute(
            "SELECT 1 FROM source_url WHERE source_id=? AND url=?",
            (source_id, url),
        ).fetchone()
        if existed:
            continue
        cur.execute(
            "INSERT INTO source_url (source_id, url, title, status) VALUES (?,?,?,?)",
            (source_id, url, (title or None), "never"),
        )
        added += 1
    conn.commit()

    return {
        "discovered": len(items),
        "added": added,
        "warnings": warnings,
        "items": [{"url": u, "title": t} for (u, t) in truncated],
    }


__all__ = ["discover_urls"]
