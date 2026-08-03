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
    AISC_LLM_MODEL      model name, e.g. gpt-4o or Qwen/Qwen3.5-9B

The default implementation below speaks the OpenAI chat-completions protocol,
which also covers vLLM, Ollama, LM Studio and Azure OpenAI. For anything else,
replace the body of :func:`get_response` — the contract is documented there.
"""

from __future__ import annotations

import os

_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".env")

# Azure pins the chat-completions protocol to a dated version. It is a protocol
# constant, not a per-deployment setting, so it lives here rather than in .env.
_AZURE_API_VERSION = "2024-10-01-preview"


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


def get_response(messages: list[dict], temperature: float = 0) -> str:
    """Send a chat request, return the assistant's reply as text.

    THE CONTRACT — the rest of the codebase relies on exactly this:
        messages     [{"role": "system"|"user", "content": str}, ...]
        temperature  0 for the deterministic extraction path
        returns      the reply as a plain string (never None; "" if empty)
        raises       LLMNotConfigured when credentials are absent

    Swap in another provider by rewriting this body; nothing else changes.
    """
    endpoint = os.environ.get("AISC_LLM_ENDPOINT", "")
    api_key = os.environ.get("AISC_LLM_API_KEY", "")
    model = os.environ.get("AISC_LLM_MODEL", "gpt-4o")
    if not api_key:
        raise LLMNotConfigured()

    from openai import AzureOpenAI, OpenAI
    from tenacity import retry, stop_after_attempt, wait_random_exponential

    @retry(wait=wait_random_exponential(min=1, max=60), stop=stop_after_attempt(6))
    def _call() -> str:
        if "azure" in endpoint:
            # Azure speaks the same protocol but on a different URL layout, so
            # it needs its own client. The api-version is a protocol constant,
            # not something worth configuring.
            client = AzureOpenAI(azure_endpoint=endpoint, api_key=api_key,
                                 api_version=_AZURE_API_VERSION)
        else:
            # api.openai.com when endpoint is empty; otherwise any
            # OpenAI-compatible server (vLLM, Ollama, LM Studio, …).
            client = OpenAI(api_key=api_key, base_url=endpoint or None)
        completion = client.chat.completions.create(
            model=model, messages=messages, temperature=temperature,
        )
        msg = completion.choices[0].message
        # Reasoning models served with a parser put chain of thought in
        # `reasoning_content` and leave `content` clean; fall back to it so a
        # reply is never None.
        return msg.content or getattr(msg, "reasoning_content", None) or ""

    return _call()


if __name__ == "__main__":
    try:
        print(get_response([{"role": "user", "content": "Say OK"}]))
    except LLMNotConfigured as exc:
        print(exc)
