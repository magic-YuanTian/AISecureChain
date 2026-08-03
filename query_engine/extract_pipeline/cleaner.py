"""Markdown cleanup before chunking/extraction.

The crawler intentionally preserves a lot of page chrome. That is useful for
debugging, but bad for extraction: nav menus, product promos, related posts,
share widgets, and footers look like real entities to the LLM. This module keeps
the article body and drops common boilerplate before the LLM sees it.
"""

from __future__ import annotations

import re


_DROP_LINE_PATTERNS = [
    r"^\s*Menu\s*$",
    r"^\s*Dark mode\b",
    r"^\s*Search(?:Loading)?\s*$",
    r"^\s*Clear\s*$",
    r"^\s*// Press enter to search\s*$",
    r"^\s*// Copy link\s*$",
    r"^\s*Link copied\s*$",
    r"^\s*Copy link\s*$",
    r"^\s*Share on (Twitter|Facebook|Linkedin)\b",
]

_STOP_SECTION_PATTERNS = [
    r"^\s*\* \* \*\s*$",
    r"^\s*// Tags\s*$",
    r"^\s*Related posts?\s*$",
    r"^\s*\[\s*See more\s*\]",
    r"^\s*#{1,3}\s*Related\b",
    r"^\s*#{1,3}\s*Also (?:read|see)\b",
    r"^\s*#{1,3}\s*You (?:may|might) also\b",
    r"^\s*#{1,3}\s*Trending\b",
    r"^\s*#{1,3}\s*Most (?:popular|read)\b",
    r"^\s*#{1,3}\s*Latest (?:news|posts|articles)\b",
    r"^\s*#{1,3}\s*Recommended(?!\s+by\s+LinkedIn)\b",
    r"^\s*#{1,3}\s*More (?:from|on|stories)\b",
    r"^\s*#{1,3}\s*Popular (?:articles|posts|stories)\b",
    r"^\s*#{1,3}\s*Editor'?s? (?:picks?|choice)\b",
    r"^\s*#{1,3}\s*Featured\s+(?:articles?|posts?|stories?)\b",
    r"^\s*#{1,3}\s*(?:Newsletter|Subscribe|Sign up)\b",
    r"^\s*#{1,3}\s*(?:Top|Trending) Stories\b",
    r"^\s*#{1,3}\s*Comments?\s*$",
    r"^\s*#{1,3}\s*Leave a (?:Reply|Comment)\b",
    r"^\s*#{1,3}\s*About the (?:Author|Writer)\b",
    r"^\s*#{1,3}\s*Share (?:this|article)\b",
    r"^\s*#{1,3}\s*Get (?:the|our) (?:newsletter|latest)\b",
    r"^\s*#{1,3}\s*Don'?t miss\b",
]

_PROMO_START_PATTERNS = [
    r"^\s*!\[.*\]\(.*\)\s*Dropbox Dash: AI that understands your work\s*$",
    r"^\s*Dropbox Dash: AI that understands your work\s*$",
]

_PROMO_END_PATTERNS = [
    r"^\s*\[?Learn more\s*(?:→|->)\]?",
]


def _matches_any(line: str, patterns: list[str]) -> bool:
    return any(re.search(p, line, flags=re.IGNORECASE) for p in patterns)


_LINK_LINE_RE = re.compile(r"^\s*\[.*\]\(https?://")
_BULLET_LINK_RE = re.compile(r"^\s*[\*\-]\s+\[.*\]\(https?://")
_HEADING_LINK_RE = re.compile(r"^\s*#{1,4}\s+\[.*\]\(https?://")
_IMG_LINE_RE = re.compile(r"^\s*!\[")
_BYLINE_RE = re.compile(r"^\s*By\s+\[")


def _is_chrome_line(line: str) -> bool:
    """Return True if line is likely page chrome (link, image, byline)."""
    stripped = line.strip()
    return bool(
        _LINK_LINE_RE.match(stripped)
        or _BULLET_LINK_RE.match(stripped)
        or _HEADING_LINK_RE.match(stripped)
        or _IMG_LINE_RE.match(stripped)
        or _BYLINE_RE.match(stripped)
    )


def _remove_dense_link_blocks(lines: list[str]) -> list[str]:
    """Remove blocks of 4+ consecutive lines that are mostly links/images.

    News sites often include sidebar article lists (trending, related, latest)
    that appear as dense runs of linked headlines, bullet-point link lists,
    or featured article cards. These confuse the LLM into extracting each
    headline as a separate vulnerability.
    """
    result: list[str] = []
    i = 0
    while i < len(lines):
        # Look ahead for a dense link/chrome block
        j = i
        chrome_count = 0
        while j < len(lines):
            stripped = lines[j].strip()
            if not stripped:
                j += 1
                continue
            if _is_chrome_line(stripped):
                chrome_count += 1
                j += 1
            else:
                break
        non_empty = sum(1 for k in range(i, j) if lines[k].strip())
        if chrome_count >= 4 and non_empty > 0 and chrome_count / non_empty >= 0.6:
            # Skip this dense chrome block
            i = j
        else:
            result.append(lines[i])
            i += 1
    return result


def clean_markdown_boilerplate(markdown: str) -> str:
    """Drop common non-article boilerplate from crawled Markdown.

    The cleanup is deliberately conservative:
    - keep content before the first heading only if there is no heading
    - stop at known footer/share/related-post sections
    - remove compact product-promo blocks embedded in articles
    """
    md = markdown.strip()
    if not md:
        return ""

    lines = md.splitlines()

    # Prefer the first article H1. This removes nav/sidebar blocks above title.
    first_h1 = next((i for i, line in enumerate(lines) if re.match(r"^#\s+\S", line)), None)
    if first_h1 is not None:
        lines = lines[first_h1:]

    cleaned: list[str] = []
    skipping_promo = False
    for line in lines:
        stripped = line.strip()

        if _matches_any(stripped, _STOP_SECTION_PATTERNS):
            break

        if skipping_promo:
            if _matches_any(stripped, _PROMO_END_PATTERNS):
                skipping_promo = False
            continue

        if _matches_any(stripped, _PROMO_START_PATTERNS):
            skipping_promo = True
            continue

        if _matches_any(stripped, _DROP_LINE_PATTERNS):
            continue

        cleaned.append(line)

    # Remove dense link blocks (sidebar article lists, trending sections).
    # These appear as consecutive lines that are mostly markdown links with
    # short descriptions — a hallmark of sidebar/footer content.
    cleaned = _remove_dense_link_blocks(cleaned)

    # Collapse excessive blank lines introduced by deletions.
    out = "\n".join(cleaned)
    out = re.sub(r"\n{3,}", "\n\n", out).strip()
    return out


__all__ = ["clean_markdown_boilerplate"]
