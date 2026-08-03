"""
Markdown chunker — splits a page into semantically meaningful chunks so that
pages with multiple records (e.g. a blog listing 10 CVEs, or an advisory index)
are processed as separate units.

Strategy:
    1. Split by top-level headers first (``## H2``); then ``### H3`` if needed.
    2. Each chunk has a soft ``max_chars`` cap. Oversized sections are further
       split with a small overlap so records straddling a boundary are not lost.
    3. Short leading/trailing noise (nav, cookie banners) stays in its own chunk.
    4. If the page has no headers at all, fall back to paragraph-based splits.
"""

from __future__ import annotations

import re


DEFAULT_MAX_CHARS = 6000
DEFAULT_OVERLAP = 300
MIN_CHUNK_CHARS = 200


def _split_on_pattern(text: str, pattern: str) -> list[str]:
    """Split keeping the delimiter at the start of each chunk."""
    parts = re.split(f"(?={pattern})", text, flags=re.MULTILINE)
    return [p for p in parts if p.strip()]


def _size_split(text: str, max_chars: int, overlap: int) -> list[str]:
    """Hard cap: cut at paragraph boundaries with optional overlap."""
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        if end < len(text):
            # Try to find a paragraph break near `end`
            nl = text.rfind("\n\n", start, end)
            if nl != -1 and nl > start + max_chars // 2:
                end = nl
        chunks.append(text[start:end].strip())
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return [c for c in chunks if c]


def chunk_markdown(
    markdown: str,
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
    overlap: int = DEFAULT_OVERLAP,
) -> list[str]:
    """Split markdown into extraction-ready chunks."""
    md = markdown.strip()
    if not md:
        return []
    if len(md) <= max_chars:
        return [md]

    # Try H2 split first
    chunks = _split_on_pattern(md, r"^##\s")
    if len(chunks) <= 1:
        chunks = _split_on_pattern(md, r"^#\s")
    if len(chunks) <= 1:
        chunks = _split_on_pattern(md, r"^###\s")

    # Enforce size cap per chunk
    sized: list[str] = []
    for c in chunks:
        sized.extend(_size_split(c, max_chars, overlap))

    # Drop pathologically small chunks by merging with neighbour
    merged: list[str] = []
    for c in sized:
        if merged and len(c) < MIN_CHUNK_CHARS:
            merged[-1] = merged[-1] + "\n\n" + c
        else:
            merged.append(c)

    # Absolute fallback: if we somehow produced nothing useful, use paragraph chunks
    if not merged:
        return _size_split(md, max_chars, overlap)

    return merged
