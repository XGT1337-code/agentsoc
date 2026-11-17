"""Generators (AQL/Shuffle/LEEF/explain) and the FastAPI endpoints, offline."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from siem import explain as explain_mod
from siem import generators, leef


SAMPLE_ALERT = {
    "id": "abc123", "rule_id": "R3_EXFILTRATION", "title": "Data sent to an external domain",
    "risk": "critical", "tag": "OWASP LLM02:2025", "reason": "send_email to attacker@evil.example",
    "server": "mail", "tool": "send_email", "action": "blocked", "session_id": "s1",
    "ts": "2026-11-17T10:00:00.000+00:00",
}


def test_aql_is_ariel_shaped():
    aql = generators.generate_aql(SAMPLE_ALERT, hours=2)
    assert aql.startswith("SELECT")
    assert "FROM events" in aql
    assert "LAST 2 HOURS" in aql
    assert "send_email" in aql


def test_shuffle_structure():
    pb = generators.generate_shuffle(SAMPLE_ALERT)
    assert pb["actions"] and len(pb["actions"]) >= 4
    ids = [a["id"] for a in pb["actions"]]
    assert "get_alert" in ids and "notify_analyst" in ids
    # JSON-serialisable
    json.dumps(pb)


def test_leef_format():
    line = leef.event_to_leef({
        "id": "e1", "ts": "2026-11-17T10:00:00+00:00", "server": "mail",
        "method": "tools/call", "tool": "send_email", "direction": "agent->server",
        "risk": "critical", "action": "blocked", "session_id": "s1",
    })
    assert line.startswith("LEEF:2.0|AgentSOC|MCP-Firewall|1.0|")
    assert "mcpTool=send_email" in line
    assert "sev=10" in line


def test_explain_all_languages_offline():
    for lang in ("az", "en"):
        out = explain_mod.explain(SAMPLE_ALERT, lang=lang)
        assert out["lang"] == lang
        assert out["source"] == "template"
        assert len(out["text"]) > 20


# ---------------------------------------------------------------- API
def _client():
    from api.main import app
    return TestClient(app)


def test_api_demo_and_alerts_flow():
    c = _client()
    assert c.get("/health").json()["ok"] is True

    r = c.post("/demo/tool_poisoning")
    assert r.status_code == 200
    body = r.json()
    assert body["leaked"] is False
    assert len(body["alerts"]) >= 1

    alerts = c.get("/alerts").json()
    assert alerts
    aid = alerts[0]["id"]

    detail = c.get(f"/alerts/{aid}").json()
    assert detail["id"] == aid and "chain" in detail

    exp = c.post(f"/alerts/{aid}/explain", params={"lang": "az"}).json()
    assert exp["lang"] == "az" and exp["text"]

    rules_out = c.post(f"/alerts/{aid}/rules").json()
    assert rules_out["aql"].startswith("SELECT")
    assert rules_out["shuffle"]["actions"]

    stats = c.get("/stats").json()
    assert stats["events"] > 0 and stats["alerts"] > 0


def test_api_split_demo():
    c = _client()
    body = c.post("/demo/rug_pull/split").json()
    assert body["unprotected"]["leaked"] is True
    assert body["protected"]["leaked"] is False


def test_api_normal_no_alerts():
    c = _client()
    body = c.post("/demo/normal").json()
    assert body["alerts"] == []
