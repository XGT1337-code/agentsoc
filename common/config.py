"""Shared paths and configuration for all AgentSOC components.

Every path can be overridden with an environment variable, which lets the
tests run against a temporary copy of the sandbox and a temporary database.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent

DEFAULTS: dict[str, Any] = {
    "email": {"allowed_domains": ["corp.example", "company.example"]},
    "sensitive_paths": [".ssh", "id_rsa", "id_ed25519", ".env", "credentials", ".aws", "secrets"],
    "policy": {
        "tool_poisoning_action": "quarantine",
        "injection_action": "redact",
        "judge_enabled": True,
    },
    "syslog": {"enabled": False, "host": "127.0.0.1", "port": 514},
    "api": {"base_url": "http://127.0.0.1:8000"},
}


def sandbox_dir() -> Path:
    """Folder with the fake files, inbox and outbox."""
    return Path(os.environ.get("AGENTSOC_SANDBOX", ROOT / "sandbox")).resolve()


def outbox_path() -> Path:
    return sandbox_dir() / "outbox.jsonl"


def db_path() -> Path:
    """SQLite database shared by the proxy and the API."""
    p = Path(os.environ.get("AGENTSOC_DB", ROOT / "data" / "agentsoc.db"))
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _merge(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> dict[str, Any]:
    """Read config.yaml (or AGENTSOC_CONFIG) on top of the built-in defaults."""
    path = Path(os.environ.get("AGENTSOC_CONFIG", ROOT / "config.yaml"))
    data: dict = {}
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cfg = _merge(DEFAULTS, data)
    # Environment overrides that the tests and the demo use.
    if os.environ.get("AGENTSOC_POISONING_ACTION"):
        cfg["policy"]["tool_poisoning_action"] = os.environ["AGENTSOC_POISONING_ACTION"]
    return cfg
