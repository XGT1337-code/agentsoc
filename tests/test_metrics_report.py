"""Metrics aggregation, incident report, and the new detection scenarios."""
from __future__ import annotations

from fastapi.testclient import TestClient

from demo.replay import run_protected
from siem.report import build_report


def _client():
    from api.main import app
    return TestClient(app)


def test_detection_scenarios(store):
    r = run_protected("path_traversal", store=store)
    assert any(a["rule_id"] == "R7_PATH_TRAVERSAL" for a in r.alerts)

    r2 = run_protected("tool_shadowing", store=store)
    rids = {a["rule_id"] for a in r2.alerts}
    assert "R9_TOOL_SHADOWING" in rids
    assert "R1_TOOL_POISONING" in rids


def test_metrics_coverage(store):
    c = _client()
    c.post("/demo/run_all")
    m = c.get("/metrics").json()
    assert m["totals"]["alerts"] > 0
    assert m["by_risk"]
    # MITRE ATLAS + OWASP coverage parsed from tags
    assert any(k.startswith("AML.T") for k in m["mitre_atlas"])
    assert any(k.startswith("LLM") for k in m["owasp_llm"])
    # the new rules show up across a full run
    assert "R7_PATH_TRAVERSAL" in m["by_rule"]
    assert "R9_TOOL_SHADOWING" in m["by_rule"]


def test_incident_report(store):
    r = run_protected("rug_pull", store=store)
    alert = store.get_alert(r.alerts[0]["id"])
    chain = store.list_events(session_id=r.session_id)
    rep = build_report(alert, chain=chain)
    md = rep["markdown"]
    assert "# AgentSOC Incident Report" in md
    assert "QRadar hunt (AQL)" in md
    assert "Recommended actions" in md
    assert rep["source"] == "template"
    assert rep["recommendations"]


def test_report_endpoint(store):
    c = _client()
    c.post("/demo/tool_poisoning")
    aid = c.get("/alerts").json()[0]["id"]
    rep = c.post(f"/alerts/{aid}/report").json()
    assert rep["markdown"].startswith("# AgentSOC Incident Report")


def test_reset_endpoint(store):
    c = _client()
    c.post("/demo/tool_poisoning")
    assert c.get("/stats").json()["alerts"] > 0
    c.post("/reset")
    assert c.get("/stats").json()["alerts"] == 0
