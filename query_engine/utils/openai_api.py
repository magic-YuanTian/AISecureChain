"""The single place this project talks to a language model.

Everything that needs an LLM — the extraction pipeline, the validator, the API
server, the regression benchmark — calls :func:`get_response` and nothing else.
So swapping models, or switching to a completely different provider, means
touching this one function.

=============================================================================
 SETUP REQUIRED — no credentials ship with this file, by design
=============================================================================

    cp .env.example .env        # then fill in the AISC_LLM_* values

    AISC_LLM_ENDPOINT   base URL of your LLM server
    AISC_LLM_API_KEY    your key ("dummy" is fine for a local vLLM/Ollama)
    AISC_LLM_MODEL      model name for extraction / validate (e.g. gpt-4o)
    AISC_USE_OLLAMA     set to true to use the local Ollama server
    AISC_OLLAMA_MODEL   local Ollama model name (e.g. gemma3:4b)
    AISC_JUDGE_MODEL    optional; FP-auditor model (falls back to AISC_LLM_MODEL)
    AISC_JUDGE_ENDPOINT / AISC_JUDGE_API_KEY  optional overrides for the judge

The default implementation below speaks the OpenAI chat-completions protocol,
which also covers vLLM, Ollama, LM Studio and Azure OpenAI. For anything else,
replace the body of :func:`get_response` — the contract is documented there.
"""

from __future__ import annotations

import os
import json
import sys
from typing import Any

_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".env")

# Azure pins the chat-completions protocol to a dated version. It is a protocol
# constant, not a per-deployment setting, so it lives here rather than in .env.
_AZURE_API_VERSION = "2024-10-01-preview"
_OLLAMA_ENDPOINT = "http://localhost:11434/v1"


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _debug_llm(label: str, value: Any) -> None:
    """Print verbose LLM diagnostics without affecting normal output."""
    if not _env_truthy("AISC_VERBOSE_LLM"):
        return
    try:
        dump = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
        rendered = json.dumps(dump, indent=2, ensure_ascii=False, default=str)
    except Exception:
        rendered = repr(value)
    print(f"\n[llm-debug] {label}\n{rendered}", file=sys.stderr, flush=True)


def _load_env_file(path: str = _ENV_PATH) -> None:
    """Populate os.environ from .env, never overriding a real env var.

    Dependency-free on purpose: this module is imported by the pipeline, the
    API server and the benchmark, and must not fail because python-dotenv is
    missing from one of those environments.
    """
    if not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if key and key not in os.environ:
                    os.environ[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass


_load_env_file()


class LLMNotConfigured(RuntimeError):
    def __init__(self) -> None:
        super().__init__(
            "No LLM configured. Copy .env.example to .env and set "
            "AISC_LLM_API_KEY, AISC_LLM_ENDPOINT and AISC_LLM_MODEL — or "
            "implement get_response() in query_engine/utils/openai_api.py "
            "for your own provider."
        )


def empty_usage() -> dict[str, Any]:
    return {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cost": None,
        "calls": 0,
    }


def merge_usage(*parts: dict[str, Any] | None) -> dict[str, Any]:
    out = empty_usage()
    cost_sum = 0.0
    saw_cost = False
    for part in parts:
        if not part:
            continue
        out["prompt_tokens"] += int(part.get("prompt_tokens") or 0)
        out["completion_tokens"] += int(part.get("completion_tokens") or 0)
        out["total_tokens"] += int(part.get("total_tokens") or 0)
        out["calls"] += int(part.get("calls") or 0)
        if part.get("cost") is not None:
            cost_sum += float(part["cost"])
            saw_cost = True
    out["cost"] = cost_sum if saw_cost else None
    return out


def _usage_from_completion(completion: Any) -> dict[str, Any]:
    usage = empty_usage()
    usage["calls"] = 1
    u = getattr(completion, "usage", None)
    if u is None:
        return usage
    usage["prompt_tokens"] = int(getattr(u, "prompt_tokens", 0) or 0)
    usage["completion_tokens"] = int(getattr(u, "completion_tokens", 0) or 0)
    usage["total_tokens"] = int(getattr(u, "total_tokens", 0) or 0)
    cost = getattr(u, "cost", None)
    if cost is None:
        extra = getattr(u, "model_extra", None) or {}
        if isinstance(extra, dict):
            cost = extra.get("cost")
    if cost is None:
        dump = getattr(u, "model_dump", None)
        if callable(dump):
            try:
                cost = dump().get("cost")
            except Exception:
                cost = None
    if cost is not None:
        try:
            usage["cost"] = float(cost)
        except (TypeError, ValueError):
            usage["cost"] = None
    if usage["total_tokens"] == 0:
        usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
    return usage


def get_response_with_usage(
    messages: list[dict],
    temperature: float = 0,
    *,
    model: str | None = None,
    endpoint: str | None = None,
    api_key: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Send a chat request; return ``(text, usage)``."""
    use_ollama = _env_truthy("AISC_USE_OLLAMA")
    if use_ollama:
        endpoint = endpoint if endpoint is not None else _OLLAMA_ENDPOINT
        api_key = api_key if api_key is not None else "dummy"
        model = model if model is not None else os.environ.get("AISC_OLLAMA_MODEL", "gemma3:4b")
    else:
        endpoint = endpoint if endpoint is not None else os.environ.get("AISC_LLM_ENDPOINT", "")
        api_key = api_key if api_key is not None else os.environ.get("AISC_LLM_API_KEY", "")
        model = model if model is not None else os.environ.get("AISC_LLM_MODEL", "gpt-4o")
    if not api_key:
        raise LLMNotConfigured()

    from openai import AzureOpenAI, OpenAI
    from tenacity import retry, stop_after_attempt, wait_random_exponential

    @retry(wait=wait_random_exponential(min=1, max=60), stop=stop_after_attempt(6))
    def _call() -> tuple[str, dict[str, Any]]:
        _debug_llm("request messages", messages)
        if "azure" in (endpoint or ""):
            client = AzureOpenAI(azure_endpoint=endpoint, api_key=api_key,
                                 api_version=_AZURE_API_VERSION)
        else:
            client = OpenAI(api_key=api_key, base_url=endpoint or None)
        completion = client.chat.completions.create(
            model=model, messages=messages, temperature=temperature,
        )
        _debug_llm("raw completion object", completion)
        msg = completion.choices[0].message
        text = msg.content or getattr(msg, "reasoning_content", None) or ""
        _debug_llm("returned model content", text)
        _debug_llm("usage", _usage_from_completion(completion))
        return text, _usage_from_completion(completion)

    return _call()


def get_response(
    messages: list[dict],
    temperature: float = 0,
    *,
    model: str | None = None,
    endpoint: str | None = None,
    api_key: str | None = None,
) -> str:
    """Send a chat request, return the assistant's reply as text.

    THE CONTRACT — the rest of the codebase relies on exactly this:
        messages     [{"role": "system"|"user", "content": str}, ...]
        temperature  0 for the deterministic extraction path
        returns      the reply as a plain string (never None; "" if empty)
        raises       LLMNotConfigured when credentials are absent

    Optional model / endpoint / api_key kwargs override AISC_LLM_* for a
    single call (used by the regression FP judge via AISC_JUDGE_*).

    For token/cost tracing use :func:`get_response_with_usage`.
    """
    text, _usage = get_response_with_usage(
        messages,
        temperature=temperature,
        model=model,
        endpoint=endpoint,
        api_key=api_key,
    )
    return text


def get_judge_response(messages: list[dict], temperature: float = 0) -> str:
    """Chat call for the regression FP auditor (text only).

    Uses AISC_JUDGE_MODEL (and optional AISC_JUDGE_ENDPOINT / AISC_JUDGE_API_KEY)
    when set; otherwise falls back to the main AISC_LLM_* settings.
    """
    judge_model = os.environ.get("AISC_JUDGE_MODEL", "").strip() or None
    judge_endpoint = os.environ.get("AISC_JUDGE_ENDPOINT", "").strip()
    judge_key = os.environ.get("AISC_JUDGE_API_KEY", "").strip()
    return get_response(
        messages,
        temperature=temperature,
        model=judge_model,
        endpoint=judge_endpoint if judge_endpoint else None,
        api_key=judge_key if judge_key else None,
    )


if __name__ == "__main__":
    try:
        print(get_response([{"role": "user", "content": "Say OK"}]))
    except LLMNotConfigured as exc:
        print(exc)
