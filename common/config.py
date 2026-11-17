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
    "auth": {
        "enabled": True,
        # The ONLY address allowed to receive an OTP / log in as admin.
        "admin_email": "hamza.gurbanov07@gmail.com",
        "ssh_password": "agentsoc",      # password for the SSH gateway (demo)
        "ssh_user": "soc",
        "ssh_port": 2222,
        "gate_ttl": 120,                 # seconds a SSH-minted web token is valid
        "otp_ttl": 300,                  # seconds an OTP is valid
        "session_ttl": 28800,            # 8h logged-in session
        # SMTP is optional. If host/user/password are set (via env), the OTP is
        # emailed for real; otherwise it is shown in the gateway terminal + a file.
        "smtp": {"host": "", "port": 587, "user": "", "password": "", "from": ""},
    },
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
    a = cfg.setdefault("auth", {})
    if os.environ.get("AGENTSOC_AUTH_DISABLED") == "1":
        a["enabled"] = False
    for env, key in (("AGENTSOC_ADMIN_EMAIL", "admin_email"),
                     ("AGENTSOC_SSH_PASSWORD", "ssh_password"),
                     ("AGENTSOC_SSH_USER", "ssh_user")):
        if os.environ.get(env):
            a[key] = os.environ[env]
    if os.environ.get("AGENTSOC_SSH_PORT"):
        a["ssh_port"] = int(os.environ["AGENTSOC_SSH_PORT"])
    smtp = a.setdefault("smtp", {})
    for env, key in (("AGENTSOC_SMTP_HOST", "host"), ("AGENTSOC_SMTP_USER", "user"),
                     ("AGENTSOC_SMTP_PASSWORD", "password"), ("AGENTSOC_SMTP_FROM", "from")):
        if os.environ.get(env):
            smtp[key] = os.environ[env]
    if os.environ.get("AGENTSOC_SMTP_PORT"):
        smtp["port"] = int(os.environ["AGENTSOC_SMTP_PORT"])
    return cfg
