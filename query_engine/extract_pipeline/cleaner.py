"""Markdown cleanup before chunking/extraction.

The crawler intentionally preserves a lot of page chrome. That is useful for
debugging, but bad for extraction: nav menus, product promos, related posts,
share widgets, and footers look like real entities to the LLM. This module keeps
the article body and drops common boilerplate before the LLM sees it.

Two modes (``AISC_CLEAN_MODE``):
  - ``regex`` (default): deterministic stop-patterns + dense-link scrub.
  - ``llm``: send the page markdown to the same extraction LLM (``AISC_LLM_*``)
    with a strict "article body only, do not summarize" prompt, then fall back
    to regex if the model returns empty / collapses the page too aggressively.
"""

from __future__ import annotations

import os
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

_LLM_CLEAN_SYSTEM = """\
You clean crawled web-page markdown for a security-entity extraction pipeline.

Return ONLY the main article body as markdown.
Remove navigation, cookie banners, share widgets, related/recommended posts,
"more like this", newsletters, webinars, expert insights sidebars, comments,
author bios that appear after the article, and site footers.
Keep the title, byline/date when they belong to the article, and every article
paragraph, list, quote, and code block verbatim.

Do NOT summarize, paraphrase, rewrite, or invent text. You may only delete
sections/lines. If unsure whether something is chrome, keep it.
Output the cleaned markdown only — no preamble or explanation."""

# If the LLM returns less than this fraction of the input, treat as failure.
_LLM_MIN_KEEP_RATIO = 0.25
_LLM_MIN_CHARS = 200


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


def clean_markdown_regex(markdown: str) -> str:
    """Deterministic boilerplate scrub (stop patterns + dense-link blocks)."""
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


def _strip_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```(?:markdown|md)?\s*\n?", "", t, count=1, flags=re.IGNORECASE)
        t = re.sub(r"\n?```\s*$", "", t)
    return t.strip()


def clean_markdown_llm(markdown: str) -> str:
    """Ask the configured extraction LLM to return article-body markdown only."""
    from utils.openai_api import get_response  # type: ignore

    md = markdown.strip()
    if not md:
        return ""

    messages = [
        {"role": "system", "content": _LLM_CLEAN_SYSTEM},
        {
            "role": "user",
            "content": (
                "Clean the following crawled markdown. Return only the article body.\n\n"
                f"```markdown\n{md}\n```"
            ),
        },
    ]
    raw = get_response(messages, temperature=0)
    cleaned = _strip_fence(raw or "")

    if len(cleaned) < _LLM_MIN_CHARS:
        return ""
    if len(cleaned) < _LLM_MIN_KEEP_RATIO * len(md):
        return ""
    return cleaned


def clean_markdown_boilerplate(markdown: str) -> str:
    """Drop common non-article boilerplate from crawled Markdown.

    Mode is selected by ``AISC_CLEAN_MODE`` (``regex`` | ``llm``). LLM mode
    uses the same ``AISC_LLM_*`` model as extraction (e.g. Gemma 26B) and falls
    back to regex if the model returns empty or collapses the page too far.
    """
    mode = (os.environ.get("AISC_CLEAN_MODE") or "regex").strip().lower()
    if mode == "llm":
        cleaned = clean_markdown_llm(markdown)
        if cleaned:
            return cleaned
        # Guardrail: keep going with regex rather than feeding empty / truncated body.
        return clean_markdown_regex(markdown)
    return clean_markdown_regex(markdown)


__all__ = [
    "clean_markdown_boilerplate",
    "clean_markdown_regex",
    "clean_markdown_llm",
]
