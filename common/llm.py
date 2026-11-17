"""Thin wrapper around the LLM API SDK (model-agnostic).

The API key is read only from the ANTHROPIC_API_KEY environment variable by the
SDK itself, and the model from AGENTSOC_MODEL. Neither is stored, printed or
logged here. Without a key the project runs fully in template mode.
"""
from __future__ import annotations

import json
import os
from typing import Any

_client = None


def has_key() -> bool:
    """True when an API key is configured. Without it AgentSOC uses templates."""
    return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())


def model_name() -> str:
    """The model to use, taken from AGENTSOC_MODEL (empty in template mode)."""
    return os.environ.get("AGENTSOC_MODEL", "").strip()


def get_client():
    global _client
    if _client is None:
        import anthropic  # imported lazily so no-key mode never needs network setup

        _client = anthropic.Anthropic(max_retries=2, timeout=120.0)
    return _client


def create_message(**kwargs: Any):
    """Call the Messages API. Model comes from AGENTSOC_MODEL."""
    client = get_client()
    model = kwargs.pop("model", None) or model_name()
    return client.messages.create(model=model, **kwargs)


def response_text(response) -> str:
    """Join the text blocks of a response."""
    return "".join(getattr(b, "text", "") for b in response.content if getattr(b, "type", "") == "text")


def ask_json(system: str, user: str, schema: dict, max_tokens: int = 2000) -> dict | None:
    """Ask the model for JSON that matches `schema`. Returns None on any failure."""
    if not has_key():
        return None
    try:
        resp = create_message(
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"format": {"type": "json_schema", "schema": schema}},
        )
        if resp.stop_reason == "refusal":
            return None
        return json.loads(response_text(resp))
    except Exception:  # network, auth, refusal, bad JSON: the caller falls back
        return None


def ask_text(system: str, user: str, max_tokens: int = 1500) -> str | None:
    if not has_key():
        return None
    try:
        resp = create_message(
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        if resp.stop_reason == "refusal":
            return None
        return response_text(resp).strip() or None
    except Exception:
        return None
