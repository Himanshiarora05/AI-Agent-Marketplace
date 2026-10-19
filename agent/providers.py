"""Chat-model connector for the audit agent.

Every supported provider exposes an OpenAI-compatible ``/chat/completions``
endpoint with tool calling, so one small stdlib client covers all of them.
Only providers with a free tier (or a local runtime) are listed.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    base_url: str
    default_model: str
    key_env: str | None
    signup_url: str


PROVIDERS = {
    # Google AI Studio free tier.
    "gemini": Provider(
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "gemini-2.5-flash",
        "GEMINI_API_KEY",
        "https://aistudio.google.com/apikey",
    ),
    # Groq free tier (rate limited).
    "groq": Provider(
        "https://api.groq.com/openai/v1",
        "llama-3.3-70b-versatile",
        "GROQ_API_KEY",
        "https://console.groq.com/keys",
    ),
    # OpenRouter models whose id ends in ":free".
    "openrouter": Provider(
        "https://openrouter.ai/api/v1",
        "meta-llama/llama-3.3-70b-instruct:free",
        "OPENROUTER_API_KEY",
        "https://openrouter.ai/keys",
    ),
    # Local models through Ollama; no key and no cost.
    "ollama": Provider(
        "http://localhost:11434/v1",
        "llama3.1",
        None,
        "https://ollama.com/download",
    ),
}


class ModelError(RuntimeError):
    pass


class ChatModel:
    """Minimal OpenAI-compatible chat client with tool calling and 429 backoff."""

    def __init__(self, provider="gemini", model=None, api_key=None, timeout=60.0, max_retries=3):
        if provider not in PROVIDERS:
            raise ModelError(f"Unknown provider '{provider}'. Choose one of: {', '.join(PROVIDERS)}")
        self.provider_name = provider
        self.provider = PROVIDERS[provider]
        self.model = model or self.provider.default_model
        self.timeout = timeout
        self.max_retries = max_retries
        key_env = self.provider.key_env
        self.api_key = api_key or (os.environ.get(key_env) if key_env else None)
        if key_env and not self.api_key:
            raise ModelError(
                f"Set {key_env} to use the '{provider}' provider. "
                f"Get a free key at {self.provider.signup_url}"
            )

    def chat(self, messages, tools=None, temperature=0.2):
        """Send one chat turn and return the assistant message dict."""
        body = {"model": self.model, "messages": messages, "temperature": temperature}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        data = self._post("/chat/completions", body)
        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError):
            raise ModelError(f"Unexpected response from {self.provider_name}: {json.dumps(data)[:500]}")

    def _post(self, path, body):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = json.dumps(body).encode("utf-8")
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(self.provider.base_url + path, data=payload, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                detail = exc.read(2000).decode("utf-8", errors="replace")
                # Free tiers rate limit aggressively; wait and retry.
                if exc.code in (429, 503) and attempt < self.max_retries:
                    retry_after = exc.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after and retry_after.isdigit() else 2 ** (attempt + 1)
                    time.sleep(min(wait, 30))
                    continue
                raise ModelError(f"{self.provider_name} returned HTTP {exc.code}: {detail[:500]}")
            except urllib.error.URLError as exc:
                raise ModelError(f"Could not reach {self.provider_name} at {self.provider.base_url}: {exc.reason}")
        raise ModelError(f"{self.provider_name} kept rate limiting after {self.max_retries} retries")
