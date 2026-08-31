#!/usr/bin/env python3
"""Extract three OWASP Top-10 YAML catalogs for the identifier prompt.

Sources
-------
* LLM / ASI / ML PDFs — pymupdf text + heading regex.
* LLM PDF fallback: official markdown at
  https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final
  if the PDF has no selectable text. Pass ``--llm-markdown-dir`` for a local clone.

Kept per type: description, common examples, attack scenarios
(+ LLM01 "Types of Prompt Injection"). Mitigations, risk tables, references,
and appendices are dropped. Text is verbatim.

Usage
-----
  cd query_engine
  ./myenv/bin/python scripts/extract_owasp_yaml.py
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.request
from pathlib import Path

import yaml

QE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = QE_ROOT.parent
DEFAULT_OUT = QE_ROOT / "data" / "owasp"

LLM_MD_BASE = (
    "https://raw.githubusercontent.com/GenAI-Security-Project/"
    "GenAI-LLM-Top10/main/2026/final/"
)
LLM_MD_FILES = [
    "LLM01_PromptInjection.md",
    "LLM02_SensitiveInformationDisclosure.md",
    "LLM03_ExcessiveAgency.md",
    "LLM04_SupplyChain.md",
    "LLM05_DataModelPoisoning.md",
    "LLM06_UnboundedConsumption.md",
    "LLM07_Misinformation.md",
    "LLM08_HiddenContextExposure.md",
    "LLM09_VectorAndEmbeddingWeaknesses.md",
    "LLM10_ImproperOutputHandling.md",
]

PDF_LLM = "OWASP GenAI LLM Top 10 2026.pdf"
PDF_ASI = "OWASP Top 10 Agentic Applications 2026.pdf"
PDF_ML = "OWASP Machine Learning Security Top 10.pdf"

CHAPTER_START = re.compile(
    r"^(?P<prefix>LLM|ASI|ML)(?P<num>0[1-9]|10):(?:(?P<year>20\d{2})\s+)?(?P<title>.*)$",
    re.MULTILINE,
)

# Headings we KEEP (order matters for slicing).
KEEP_HEADINGS = (
    "Description",
    "Types of Prompt Injection",
    "Common Examples of Risk",
    "Common Examples of the Vulnerability",
    "Example Attack Scenarios",
)
# Everything else is a hard stop for the previous keep-section.
DROP_HEADINGS = (
    "Prevention and Mitigation Strategies",
    "Prevention and Mitigation Guidelines",
    "How to Prevent",
    "Risk Factors",
    "References",
    "Appendix A",
    "Appendix B",
    "Appendix C",
    "Appendix D",
    "Appendix E",
    "Acknowledgements",
    "Glossary",
    "Appendices",
)
# End the catalog entirely (do not start a new type from TOC/ack tables).
END_CATALOG_HEADINGS = (
    "Appendix A",
    "Appendix B",
    "Appendix C",
    "Appendix D",
    "Appendix E",
    "Acknowledgements",
    "Glossary",
    "Appendices",
)
ALL_SECTION_HEADINGS = KEEP_HEADINGS + DROP_HEADINGS
TYPE_SUBHEADINGS = (
    "Direct Prompt Injection",
    "Indirect Prompt Injection",
)

HEADER_NOISE = [
    re.compile(r"(?im)^page\s+\d+\s*$"),
    re.compile(r"(?im)^genai\.owasp\.org\s*$"),
    re.compile(r"(?m)^--\s*\d+\s+of\s+\d+\s+--\s*$"),
    re.compile(r"(?m)^\d+\s*$"),  # lone page numbers in TOC leftovers
]


def _require_pymupdf():
    try:
        import pymupdf  # noqa: F401
    except ImportError as exc:
        raise SystemExit(
            "pymupdf is required:  pip install pymupdf"
        ) from exc


def pdf_pages_text(path: Path) -> list[str]:
    _require_pymupdf()
    import contextlib
    import io
    import pymupdf

    # MuPDF prints zlib errors to stderr for the image-only LLM PDF.
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        doc = pymupdf.open(path)
        pages = [(page.get_text("text") or "") for page in doc]
    return pages


def strip_noise(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if any(p.match(stripped) for p in HEADER_NOISE):
            continue
        lines.append(line)
    return "\n".join(lines)


def _line_matches_heading(s: str, h: str) -> bool:
    """Exact heading, or PDF 'Appendix A: Related …' / trailing punctuation."""
    if s == h:
        return True
    if not s.startswith(h):
        return False
    rest = s[len(h) :].strip()
    return (not rest) or rest[0] in ".:—"


def is_heading_line(line: str) -> bool:
    s = line.strip()
    if CHAPTER_START.match(s):
        return True
    return any(_line_matches_heading(s, h) for h in ALL_SECTION_HEADINGS)


def normalize_heading(line: str) -> str | None:
    s = line.strip()
    s = re.sub(r"^#+\s+", "", s)
    if CHAPTER_START.match(s):
        return s
    for h in ALL_SECTION_HEADINGS:
        if _line_matches_heading(s, h):
            return h
    return None


def joined_heading(lines: list[str], i: int) -> tuple[str | None, int]:
    """Match a heading on this line, or this line + the next (PDF wrap)."""
    h = normalize_heading(lines[i])
    if h:
        return h, 1
    if i + 1 < len(lines):
        combo = lines[i].strip() + " " + lines[i + 1].strip()
        h = normalize_heading(combo)
        if h:
            return h, 2
    return None, 1


def reflow_paragraph(text: str) -> str:
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"(\w)-\n(\w)", r"\1\2", text)
    chunks = re.split(r"\n\s*\n", text.strip())
    out = []
    for chunk in chunks:
        joined = re.sub(r"\s*\n\s*", " ", chunk).strip()
        if joined:
            out.append(joined)
    return "\n\n".join(out)


def split_items(text: str) -> list[str]:
    """Numbered OWASP lists or 'Scenario #N:' blocks → list of reflowed strings."""
    text = text.strip()
    if not text:
        return []
    text = re.sub(r"(?m)^#{1,4}\s+", "", text)
    if re.search(r"(?m)^Scenario #\d+", text):
        parts = re.split(r"(?m)(?=^Scenario #\d+)", text)
        return [reflow_paragraph(p) for p in parts if p.strip()]
    if re.search(r"(?m)^\d+\.\s+\S", text):
        parts = re.split(r"(?m)(?=^\d+\.\s+)", text)
        items = []
        for p in parts:
            p = p.strip()
            if not p:
                continue
            p = re.sub(r"^\d+\.\s+", "", p, count=1)
            p = re.sub(r"\*\*([^*]+)\*\*", r"\1", p)
            items.append(reflow_paragraph(p))
        return items
    return [reflow_paragraph(re.sub(r"\*\*([^*]+)\*\*", r"\1", text))]


def parse_types_section(text: str) -> dict[str, str]:
    """LLM01 markdown #### subheads, or PDF 'Direct/Indirect Prompt Injection' lines."""
    text = text.strip()
    parts = re.split(r"(?m)^####\s+", text)
    if len(parts) > 1:
        out: dict[str, str] = {}
        preamble = parts[0].strip()
        if preamble:
            out["overview"] = reflow_paragraph(preamble)
        for block in parts[1:]:
            lines = block.splitlines()
            name = lines[0].strip()
            body = "\n".join(lines[1:]).strip()
            out[name] = reflow_paragraph(body)
        return out
    sub = "|".join(re.escape(h) for h in TYPE_SUBHEADINGS)
    chunks = re.split(rf"(?m)^({sub})\s*$", text)
    if len(chunks) == 1:
        blob = reflow_paragraph(text)
        return {"overview": blob} if blob else {}
    out: dict[str, str] = {}
    preamble = chunks[0].strip()
    if preamble:
        out["overview"] = reflow_paragraph(preamble)
    for i in range(1, len(chunks), 2):
        name = chunks[i].strip()
        body = chunks[i + 1] if i + 1 < len(chunks) else ""
        out[name] = reflow_paragraph(body)
    return out


def _title_wrap_end(lines: list[str], i: int) -> int:
    """Index after optional wrapped title lines following a chapter header."""
    j = i + 1
    while j < len(lines) and lines[j].strip() and not normalize_heading(lines[j]):
        if CHAPTER_START.match(re.sub(r"^#+\s+", "", lines[j].strip())):
            break
        nxt, _ = joined_heading(lines, j)
        if nxt and nxt in ALL_SECTION_HEADINGS:
            break
        j += 1
    return j


def is_real_chapter(lines: list[str], i: int, expected_prefix: str) -> re.Match | None:
    """True chapter header: LLMxx:yyyy Title, then Description — not a body cite."""
    stripped = re.sub(r"^#+\s+", "", lines[i].strip())
    m = CHAPTER_START.match(stripped)
    if not m or m.group("prefix") != expected_prefix:
        return None
    j = _title_wrap_end(lines, i)
    while j < len(lines) and not lines[j].strip():
        j += 1
    if j >= len(lines):
        return None
    heading, _ = joined_heading(lines, j)
    if heading != "Description":
        return None
    return m


def lines_to_entries(lines: list[str], expected_prefix: str) -> list[dict]:
    """State machine over stripped PDF/markdown lines."""
    entries: list[dict] = []
    current: dict | None = None
    section: str | None = None
    buf: list[str] = []

    def flush_buf():
        nonlocal buf, section, current
        if current is None or section is None:
            buf = []
            return
        raw = "\n".join(buf).strip()
        buf = []
        if section == "Description":
            current["description"] = reflow_paragraph(raw)
        elif section == "Types of Prompt Injection":
            current["types"] = parse_types_section(raw)
        elif section in (
            "Common Examples of Risk",
            "Common Examples of the Vulnerability",
        ):
            current["common_examples"] = split_items(raw)
        elif section == "Example Attack Scenarios":
            current["attack_scenarios"] = split_items(raw)

    def finish_entry():
        nonlocal current
        flush_buf()
        if current and current.get("description"):
            entries.append(current)
        current = None

    i = 0
    while i < len(lines):
        line = lines[i]
        m = is_real_chapter(lines, i, expected_prefix)
        # Wrapped PDF titles: "ASI01: Agent Goal" then "Hijack"
        if m:
            finish_entry()
            title = m.group("title").strip()
            j = _title_wrap_end(lines, i)
            if j > i + 1:
                title = (title + " " + " ".join(
                    lines[k].strip() for k in range(i + 1, j) if lines[k].strip()
                )).strip()
            current = {
                "id": f"{m.group('prefix')}{m.group('num')}",
                "year": int(m.group("year")) if m.group("year") else None,
                "title": re.sub(r"\s+", " ", title),
                "description": "",
                "common_examples": [],
                "attack_scenarios": [],
            }
            if not current["year"]:
                current.pop("year")
            section = None
            buf = []
            i = j
            continue

        heading, consumed = joined_heading(lines, i)
        if heading and heading in ALL_SECTION_HEADINGS:
            if heading in END_CATALOG_HEADINGS:
                finish_entry()
                break
            flush_buf()
            section = heading if heading in KEEP_HEADINGS else None
            buf = []
            i += consumed
            continue

        if current is not None and section is not None:
            buf.append(line)
        i += 1

    finish_entry()
    return [e for e in entries if e["id"].startswith(expected_prefix)]


def parse_pdf_catalog(
    pdf_path: Path,
    prefix: str,
    skip_until: str | None = None,
    start_page: int = 0,
) -> list[dict]:
    pages = pdf_pages_text(pdf_path)
    if start_page:
        pages = pages[start_page:]
    if not any(p.strip() for p in pages):
        return []
    text = strip_noise("\n".join(pages))
    if skip_until and skip_until in text:
        idx = text.index(skip_until)
        last = None
        for m in CHAPTER_START.finditer(text[:idx]):
            last = m.start()
        text = text[last if last is not None else idx :]
    lines = text.splitlines()
    return lines_to_entries(lines, prefix)


def parse_llm_markdown(md: str) -> dict:
    lines = md.replace("\r\n", "\n").splitlines()
    # drop a leading `# path` if raw github wrapped it — files start with ##
    entries = lines_to_entries(lines, "LLM")
    if len(entries) != 1:
        raise ValueError(f"expected 1 LLM entry, got {len(entries)}")
    return entries[0]


def fetch_llm_markdown(markdown_dir: Path | None) -> tuple[list[dict], str]:
    entries = []
    if markdown_dir:
        source = f"local:{markdown_dir}"
        for name in LLM_MD_FILES:
            path = markdown_dir / name
            if not path.exists():
                raise FileNotFoundError(path)
            entries.append(parse_llm_markdown(path.read_text(encoding="utf-8")))
        return entries, source

    source = LLM_MD_BASE
    for name in LLM_MD_FILES:
        url = LLM_MD_BASE + name
        with urllib.request.urlopen(url, timeout=60) as resp:
            md = resp.read().decode("utf-8")
        entries.append(parse_llm_markdown(md))
    return entries, source


def dump_yaml(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(
            payload,
            f,
            sort_keys=False,
            allow_unicode=True,
            width=88,
            default_flow_style=False,
        )


def _check(entries: list[dict], prefix: str, n: int = 10) -> None:
    ids = [e["id"] for e in entries]
    want = [f"{prefix}{i:02d}" for i in range(1, n + 1)]
    if ids != want:
        raise SystemExit(f"{prefix}: expected {want}, got {ids}")
    missing_desc = [e["id"] for e in entries if not e.get("description")]
    if missing_desc:
        raise SystemExit(f"{prefix}: empty description: {missing_desc}")
    leaked = [
        e["id"]
        for e in entries
        for blob in (e.get("attack_scenarios") or [])
        if "Appendix A" in blob or "Coverage matrix" in blob
    ]
    if leaked:
        raise SystemExit(f"{prefix}: appendix leaked into attack_scenarios: {leaked}")
    if prefix == "LLM":
        n01 = len(next(e["attack_scenarios"] for e in entries if e["id"] == "LLM01"))
        if n01 < 9:
            raise SystemExit(f"LLM01: expected 9 attack scenarios, got {n01}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pdf-dir", type=Path, default=REPO_ROOT, help="Directory containing the three PDFs")
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    ap.add_argument(
        "--llm-markdown-dir",
        type=Path,
        default=None,
        help="Local 2026/final/ markdown dir. Default: fetch from GitHub.",
    )
    args = ap.parse_args()
    pdf_dir: Path = args.pdf_dir
    out_dir: Path = args.out_dir

    llm_pdf = pdf_dir / PDF_LLM
    asi_pdf = pdf_dir / PDF_ASI
    ml_pdf = pdf_dir / PDF_ML
    for p in (llm_pdf, asi_pdf, ml_pdf):
        if not p.exists():
            raise SystemExit(f"missing PDF: {p}")

    llm_from_pdf = parse_pdf_catalog(
        llm_pdf,
        "LLM",
        skip_until="A prompt-injection vulnerability occurs when input",
        start_page=9,  # printed p.10
    )
    if llm_from_pdf:
        llm_entries, llm_src = llm_from_pdf, str(llm_pdf)
        print(f"LLM: parsed {len(llm_entries)} from PDF")
    else:
        print("LLM PDF has no extractable text; using official 2026 markdown")
        llm_entries, llm_src = fetch_llm_markdown(args.llm_markdown_dir)

    # Skip TOC / at-a-glance pages: start at the first real Description body.
    asi_entries = parse_pdf_catalog(
        asi_pdf,
        "ASI",
        skip_until="AI Agents exhibit autonomous ability",
        start_page=9,  # printed p.9 — skip ToC / at-a-glance
    )
    ml_entries = parse_pdf_catalog(
        ml_pdf,
        "ML",
        skip_until="Input Manipulation Attacks is an umbrella",
        start_page=8,  # printed p.9 — skip ToC
    )

    _check(llm_entries, "LLM")
    _check(asi_entries, "ASI")
    _check(ml_entries, "ML")

    dump_yaml(
        out_dir / "llm_2026.yaml",
        {
            "list": "OWASP Top 10 for LLM / GenAI Applications",
            "edition": 2026,
            "source": llm_src,
            "pdf": str(llm_pdf.name),
            "kept": ["description", "types (LLM01)", "common_examples", "attack_scenarios"],
            "entries": llm_entries,
        },
    )
    dump_yaml(
        out_dir / "asi_2026.yaml",
        {
            "list": "OWASP Top 10 for Agentic Applications",
            "edition": 2026,
            "source": str(asi_pdf),
            "kept": ["description", "common_examples", "attack_scenarios"],
            "entries": asi_entries,
        },
    )
    dump_yaml(
        out_dir / "ml_2023.yaml",
        {
            "list": "OWASP Machine Learning Security Top 10",
            "edition": 2023,
            "source": str(ml_pdf),
            "kept": ["description", "attack_scenarios"],
            "note": (
                "This draft has no Common Examples heading; attack_scenarios "
                "are the only example text. ML04 description in the PDF confuses "
                "membership inference with training-data manipulation — left verbatim."
            ),
            "entries": ml_entries,
        },
    )

    def _stats(label, ents):
        ex = sum(len(e.get("common_examples") or []) for e in ents)
        sc = sum(len(e.get("attack_scenarios") or []) for e in ents)
        print(f"{label}: {len(ents)} types, {ex} examples, {sc} scenarios → {out_dir}")

    _stats("LLM", llm_entries)
    _stats("ASI", asi_entries)
    _stats("ML ", ml_entries)
    return 0


if __name__ == "__main__":
    sys.exit(main())
