"""LLM access layer — the single place the project talks to a language model.

Everything that needs an LLM (the extraction pipeline, the validator, the API
server, the regression benchmark) goes through :func:`get_response`. Swapping
models is therefore a configuration change, never a code change.

=============================================================================
 SETUP REQUIRED — this module ships WITHOUT credentials by design
=============================================================================

No endpoint or key is hard-coded here, and none ever should be: this file is in
version control. Configure your own provider instead:

    cp .env.example .env      # then fill in the AISC_LLM_* values

Recognised variables (an already-exported shell variable always wins over
`.env`, which is how a benchmark run can target one model for one invocation):

    AISC_LLM_PROVIDER     "azure" (default) or "openai" for any
                          OpenAI-compatible server — api.openai.com, vLLM,
                          Ollama, LM Studio, …
    AISC_LLM_ENDPOINT     Azure endpoint, or the base URL of the compatible
                          server (e.g. http://localhost:8000/v1)
    AISC_LLM_API_KEY      API key ("dummy" is fine for a local vLLM)
    AISC_LLM_API_VERSION  Azure API version
    AISC_LLM_MODEL        deployment / model name (e.g. gpt-4o,
                          Qwen/Qwen3.5-9B)
    AISC_LLM_MAX_TOKENS   optional cap on generated tokens — self-hosted
                          servers often default low
    AISC_LLM_EXTRA_BODY   optional JSON forwarded as OpenAI `extra_body`, for
                          vendor switches. Example (disable Qwen's default
                          thinking mode so it returns plain JSON):
                          {"chat_template_kwargs":{"enable_thinking":false}}

Using a provider that is not OpenAI-compatible? Implement
:func:`get_response` yourself — see the contract on that function. Nothing else
in the codebase needs to change.
"""

from __future__ import annotations

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_ENV_PATH = os.path.join(_HERE, "..", "..", ".env")

_DEFAULT_API_VERSION = "2024-10-01-preview"
_DEFAULT_MODEL = "gpt-4o"


def _load_env_file(path: str = _ENV_PATH) -> None:
    """Populate os.environ from .env without clobbering real env vars.

    Deliberately dependency-free: this module is imported by the extraction
    pipeline, the API server and the benchmark, and must not fail merely
    because python-dotenv is absent from one of those environments.
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
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError:
        pass


_load_env_file()


def _int_or_none(v):
    try:
        return int(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _json_or_none(v):
    if not v:
        return None
    try:
        parsed = json.loads(v)
        return parsed if isinstance(parsed, dict) else None
    except Exception:  # noqa: BLE001 - malformed config must not crash startup
        return None


def llm_config() -> dict:
    """Resolve the active LLM configuration from the environment.

    Read fresh on every call, so a caller can point one run at a different
    model just by setting AISC_LLM_MODEL for that process.
    """
    return {
        "endpoint": os.environ.get("AISC_LLM_ENDPOINT", ""),
        "api_key": os.environ.get("AISC_LLM_API_KEY", ""),
        "api_version": os.environ.get("AISC_LLM_API_VERSION", _DEFAULT_API_VERSION),
        "model": os.environ.get("AISC_LLM_MODEL", _DEFAULT_MODEL),
        "provider": os.environ.get("AISC_LLM_PROVIDER", "azure"),
        "max_tokens": _int_or_none(os.environ.get("AISC_LLM_MAX_TOKENS")),
        "extra_body": _json_or_none(os.environ.get("AISC_LLM_EXTRA_BODY")),
    }


class LLMNotConfigured(RuntimeError):
    """Raised when no LLM credentials are available."""

    def __init__(self) -> None:
        super().__init__(
            "No LLM configured. Copy .env.example to .env and set AISC_LLM_API_KEY "
            "and AISC_LLM_ENDPOINT (see the module docstring in "
            "query_engine/utils/openai_api.py), or implement get_response() for "
            "your own provider."
        )


def _require_config() -> dict:
    cfg = llm_config()
    if not cfg["api_key"]:
        raise LLMNotConfigured()
    return cfg


def _make_client(cfg: dict):
    """Build an OpenAI-compatible client for the configured provider."""
    from openai import AzureOpenAI, OpenAI  # imported lazily: optional at import time

    if cfg["provider"] == "openai":
        # base_url None → api.openai.com; set it for vLLM/Ollama/etc.
        return OpenAI(api_key=cfg["api_key"], base_url=cfg["endpoint"] or None)
    return AzureOpenAI(
        azure_endpoint=cfg["endpoint"],
        api_key=cfg["api_key"],
        api_version=cfg["api_version"],
    )


def _query(client, model, messages, temperature=0, *, max_tokens=None, extra_body=None) -> str:
    kwargs = {"model": model, "messages": messages, "temperature": temperature}
    if max_tokens:
        kwargs["max_tokens"] = max_tokens
    if extra_body:
        kwargs["extra_body"] = extra_body
    completion = client.chat.completions.create(**kwargs)
    msg = completion.choices[0].message
    # Servers with a reasoning parser (vLLM --reasoning-parser) split chain of
    # thought into `reasoning_content` and leave `content` clean. If a model
    # returned ONLY reasoning, fall back to it rather than yielding None.
    return msg.content or getattr(msg, "reasoning_content", None) or ""


def get_response(messages: list[dict], temperature: float = 0) -> str:
    """Send a chat completion request and return the assistant's text.

    THE CONTRACT — everything else in the project depends only on this:
        messages     OpenAI-style [{"role": "system"|"user", "content": str}, …]
        temperature  0 for the deterministic extraction path
        returns      the reply as a plain string (never None; "" if empty)
        raises       LLMNotConfigured when no credentials are set

    The default implementation below covers Azure OpenAI and every
    OpenAI-compatible server. To use a provider that is neither (Anthropic,
    Bedrock, a bespoke gateway), replace this function body — that is the only
    change required anywhere in the codebase.
    """
    cfg = _require_config()

    from tenacity import retry, stop_after_attempt, wait_random_exponential

    @retry(wait=wait_random_exponential(min=1, max=60), stop=stop_after_attempt(6))
    def _call() -> str:
        client = _make_client(cfg)
        return _query(
            client, cfg["model"], messages, temperature,
            max_tokens=cfg["max_tokens"], extra_body=cfg["extra_body"],
        )

    return _call()


# ── Backwards-compatible aliases ─────────────────────────────────────────────
# Older modules import these names; keep them thin wrappers over get_response.

def make_gpt_4():
    """Return a callable with the same signature as :func:`get_response`."""
    return get_response


def query_openai(client, model, messages, temperature=0, *, max_tokens=None, extra_body=None):
    """Low-level single call against an already-built client."""
    return _query(client, model, messages, temperature,
                  max_tokens=max_tokens, extra_body=extra_body)


if __name__ == "__main__":
    cfg = llm_config()
    print("active LLM config:",
          {k: ("***" if k == "api_key" and v else v) for k, v in cfg.items()})
    try:
        print(get_response([{"role": "user", "content": "Say OK"}]))
    except LLMNotConfigured as exc:
        print(f"\n{exc}")
