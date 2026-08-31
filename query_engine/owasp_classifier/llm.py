"""OWASP classifier LLM call.

One finding (title + description) in; JSON labels out. Uses the same
AISC_LLM_* client as the extract pipeline. Not wired into extract persist.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator

_PKG = Path(__file__).resolve().parent
SYSTEM_PROMPT_PATH = _PKG / "prompts" / "system_prompt.txt"

ALLOWED_IDS = tuple(
    [f"LLM{i:02d}" for i in range(1, 11)]
    + [f"ASI{i:02d}" for i in range(1, 11)]
    + [f"ML{i:02d}" for i in range(1, 11)]
)

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_UNCLOSED_THINK_RE = re.compile(r"<think>.*", re.DOTALL | re.IGNORECASE)
_MAX_LABELS = 3


class ProposedType(BaseModel):
    name: str
    why: str = ""


class OwaspLabel(BaseModel):
    id: str
    confidence: float = 0.0
    why: str = ""

    @field_validator("confidence", mode="before")
    @classmethod
    def _conf(cls, v: Any) -> float:
        try:
            n = float(v)
        except (TypeError, ValueError):
            return 0.0
        if n > 1.0 and n <= 100.0:
            n = n / 100.0
        return max(0.0, min(1.0, n))


class ClassificationResult(BaseModel):
    labels: list[OwaspLabel] = Field(default_factory=list)
    abstain: bool = False
    propose_new: ProposedType | None = None


def load_system_prompt() -> str:
    if not SYSTEM_PROMPT_PATH.is_file():
        raise FileNotFoundError(
            f"missing classifier prompt: {SYSTEM_PROMPT_PATH}"
        )
    return SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")


def format_user_message(
    *,
    title: str,
    description: str,
    vuln_id: str | None = None,
) -> str:
    vid = (vuln_id or "").strip() or "(none)"
    return (
        "Classify this vulnerability. Return JSON only.\n\n"
        f"vuln_id: {vid}\n"
        f"title: {(title or '').strip()}\n"
        f"description: {(description or '').strip()}\n"
    )


def _extract_json_blob(text: str) -> str:
    t = text.strip()
    if "</think>" in t.lower() or "<think>" in t.lower():
        t = (
            _THINK_RE.sub("", t) if "</think>" in t.lower()
            else _UNCLOSED_THINK_RE.sub("", t)
        ).strip()
    m = _FENCE_RE.search(t)
    if m:
        return m.group(1).strip()
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        return t[start : end + 1]
    return t


def _normalize_parsed(raw: dict[str, Any], valid_ids: set[str]) -> dict[str, Any]:
    labels_in = raw.get("labels") or []
    if not isinstance(labels_in, list):
        labels_in = []
    id_map = {i.lower(): i for i in valid_ids}
    labels: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in labels_in:
        if not isinstance(item, dict):
            continue
        lid = str(item.get("id") or item.get("type") or "").strip()
        canonical = id_map.get(lid.lower())
        if not canonical or canonical in seen:
            continue
        seen.add(canonical)
        labels.append({
            "id": canonical,
            "confidence": item.get("confidence", 0.0),
            "why": str(item.get("why") or item.get("reason") or "").strip(),
        })
    labels.sort(key=lambda x: float(x.get("confidence") or 0), reverse=True)
    labels = labels[:_MAX_LABELS]

    propose = raw.get("propose_new")
    if propose in ("", None, False):
        propose = None
    elif isinstance(propose, str):
        propose = {"name": propose, "why": ""}
    elif isinstance(propose, dict):
        name = str(propose.get("name") or "").strip()
        propose = {"name": name, "why": str(propose.get("why") or "").strip()} if name else None
    else:
        propose = None

    abstain = bool(raw.get("abstain"))
    if labels:
        abstain = False
        propose = None
    elif propose:
        abstain = False
    else:
        abstain = True

    return {"labels": labels, "abstain": abstain, "propose_new": propose}


def parse_classification(raw_text: str, valid_ids: set[str] | None = None) -> ClassificationResult:
    ids = set(valid_ids if valid_ids is not None else ALLOWED_IDS)
    blob = _extract_json_blob(raw_text)
    parsed = json.loads(blob)
    if not isinstance(parsed, dict):
        raise ValueError("classifier reply was not a JSON object")
    shaped = _normalize_parsed(parsed, ids)
    return ClassificationResult.model_validate(shaped)


def _qe_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _call_llm(messages: list[dict[str, str]], temperature: float = 0.0) -> tuple[str, dict]:
    sys.path.insert(0, str(_qe_root()))
    from utils.openai_api import get_response_with_usage  # type: ignore

    return get_response_with_usage(messages, temperature=temperature)


def classify_vulnerability(
    *,
    title: str,
    description: str,
    vuln_id: str | None = None,
    system_prompt: str | None = None,
    temperature: float = 0.0,
    retries: int = 1,
) -> tuple[ClassificationResult | None, dict, str | None]:
    """Return (result, usage, error). result is None when every attempt failed."""
    sys.path.insert(0, str(_qe_root()))
    from utils.openai_api import empty_usage, merge_usage  # type: ignore

    sys_prompt = system_prompt or load_system_prompt()
    user_msg = format_user_message(
        title=title, description=description, vuln_id=vuln_id,
    )
    print(
        f"[owasp-classifier] loaded prompt_chars={len(sys_prompt)} "
        f"title={title!r}",
        file=sys.stderr,
        flush=True,
    )
    valid = set(ALLOWED_IDS)
    usage_acc = empty_usage()
    last_err: str | None = None
    for attempt in range(retries + 1):
        messages: list[dict[str, str]] = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_msg},
        ]
        if attempt > 0:
            messages.append({
                "role": "system",
                "content": (
                    "Your previous reply could not be parsed. Respond with a "
                    "single JSON object only. No prose, no markdown fences."
                ),
            })
        try:
            raw, call_usage = _call_llm(messages, temperature)
            usage_acc = merge_usage(usage_acc, call_usage)
        except Exception as exc:  # noqa: BLE001
            last_err = f"LLM call failed: {exc}"
            continue
        try:
            result = parse_classification(raw, valid)
            return result, usage_acc, None
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            last_err = f"JSON parse failed: {exc}. raw={raw[:300]}"
            continue
    return None, usage_acc, last_err


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Classify one vulnerability against OWASP catalogs")
    ap.add_argument("--title", required=True)
    ap.add_argument("--description", required=True)
    ap.add_argument("--vuln-id", default="")
    args = ap.parse_args()
    result, usage, err = classify_vulnerability(
        title=args.title,
        description=args.description,
        vuln_id=args.vuln_id or None,
    )
    if err:
        print(err, file=sys.stderr)
        return 1
    print(json.dumps(result.model_dump() if result else {}, indent=2))
    print(
        f"# tokens prompt={usage.get('prompt_tokens')} "
        f"completion={usage.get('completion_tokens')}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
