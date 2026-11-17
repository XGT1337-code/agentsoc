"""End-to-end: attacks leak unprotected and are blocked protected; normal is quiet."""
from __future__ import annotations

import json

import pytest

from common.config import outbox_path
from demo.replay import run_protected, run_unprotected

ATTACKS = ["tool_poisoning", "prompt_injection", "rug_pull"]


def _attacker_msgs() -> int:
    p = outbox_path()
    if not p.exists():
        return 0
    return sum(1 for ln in p.read_text(encoding="utf-8").splitlines() if "evil.example" in ln)


@pytest.mark.parametrize("scenario", ATTACKS)
def test_unprotected_leaks(scenario, store):
    before = _attacker_msgs()
    r = run_unprotected(scenario, store=store)
    assert r.leaked is True
    assert _attacker_msgs() > before, "fake key should reach outbox.jsonl without protection"


@pytest.mark.parametrize("scenario", ATTACKS)
def test_protected_blocks(scenario, store):
    before = _attacker_msgs()
    r = run_protected(scenario, store=store)
    assert r.leaked is False
    assert _attacker_msgs() == before, "nothing should reach the attacker through the firewall"
    assert len(r.alerts) >= 1
    assert any(a["action"] in ("blocked", "quarantined", "redacted") for a in r.alerts)


def test_normal_has_no_alerts(store):
    r = run_protected("normal", store=store)
    assert r.leaked is False
    assert r.alerts == [], "the honest scenario must not raise alerts (no false positives)"
    assert all(s.status in ("ok",) for s in r.steps)


def test_tool_poisoning_quarantines_tool(store):
    r = run_protected("tool_poisoning", store=store)
    assert any(a["rule_id"] == "R1_TOOL_POISONING" for a in r.alerts)
    assert any(s.status == "quarantined" for s in r.steps)


def test_rug_pull_detected(store):
    r = run_protected("rug_pull", store=store)
    assert any(a["rule_id"] == "R4_RUG_PULL" for a in r.alerts)
