"""Minimal, provider-agnostic LLM client.

Supports three providers, chosen by LLM_PROVIDER in .env:
  - "mock"      deterministic, no network or key needed (default; good for testing)
  - "openai"    any OpenAI-compatible /v1/chat/completions endpoint (OpenAI, Ollama, etc.)
  - "anthropic" Anthropic Messages API

Only `requests` is needed; no vendor SDK.
"""
import os

import requests

MOCK_SYSTEM_ECHO_LIMIT = 4000


class LLMError(RuntimeError):
    pass


def chat(system_prompt, messages, temperature=0.2, max_tokens=600):
    """messages: list of {"role": "user"|"assistant", "content": str}. Returns reply text."""
    provider = os.environ.get("LLM_PROVIDER", "mock").lower()
    if provider == "mock":
        return _mock_chat(system_prompt, messages)
    if provider == "openai":
        return _openai_chat(system_prompt, messages, temperature, max_tokens)
    if provider == "anthropic":
        return _anthropic_chat(system_prompt, messages, temperature, max_tokens)
    raise LLMError(f"Unknown LLM_PROVIDER: {provider!r}")


def _openai_chat(system_prompt, messages, temperature, max_tokens):
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    api_key = os.environ.get("OPENAI_API_KEY", "")
    model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
    resp = requests.post(
        f"{base_url}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": model,
            "messages": [{"role": "system", "content": system_prompt}] + messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        },
        timeout=60,
    )
    if resp.status_code != 200:
        raise LLMError(f"OpenAI-compatible endpoint returned HTTP {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def _anthropic_chat(system_prompt, messages, temperature, max_tokens):
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    model = os.environ.get("LLM_MODEL", "claude-haiku-5-5")
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "system": system_prompt,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        },
        timeout=60,
    )
    if resp.status_code != 200:
        raise LLMError(f"Anthropic API returned HTTP {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    return "".join(block.get("text", "") for block in data.get("content", []))


def _mock_chat(system_prompt, messages):
    """No network, no key. Deterministic reply so the plumbing can be tested offline.

    This is NOT a stand-in for red-team testing: it does not simulate how a real model
    would react to an injected instruction. Point LLM_PROVIDER at a real model before
    running the Project 3 attacks.
    """
    last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
    return (
        "[mock-llm] This is a placeholder reply from the offline mock provider. "
        "Set LLM_PROVIDER=openai or anthropic in .env to talk to a real model.\n"
        f"You said: {last_user[:300]}\n"
        f"(system prompt length seen: {len(system_prompt)} chars)"
    )