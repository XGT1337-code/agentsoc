"""Test fixtures: isolated sandbox + database per test session.

Every test runs with its own copy of the sandbox and a temporary SQLite file,
and with no API key, so the whole suite is deterministic and offline.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def pytest_configure(config):
    config.addinivalue_line("markers", "live: needs a real ANTHROPIC_API_KEY (keeps the key set)")


@pytest.fixture(autouse=True)
def isolated_env(request, tmp_path, monkeypatch):
    # Offline tests force template / heuristic mode by removing the key.
    # Tests marked @pytest.mark.live keep the real key so they hit the model.
    if request.node.get_closest_marker("live") is None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    sb = tmp_path / "sandbox"
    shutil.copytree(ROOT / "sandbox", sb)
    (sb / "outbox.jsonl").unlink(missing_ok=True)
    monkeypatch.setenv("AGENTSOC_SANDBOX", str(sb))
    monkeypatch.setenv("AGENTSOC_DB", str(tmp_path / "agentsoc.db"))
    monkeypatch.setenv("AGENTSOC_CONFIG", str(ROOT / "config.yaml"))
    yield


@pytest.fixture
def store():
    from siem.store import Store
    return Store()
