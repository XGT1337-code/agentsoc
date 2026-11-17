"""FastAPI backend for the AgentSOC dashboard.

Endpoints:
  GET  /events
  GET  /alerts
  GET  /alerts/{id}
  POST /alerts/{id}/explain?lang=az|en|ru
  POST /alerts/{id}/rules         -> AQL + Shuffle JSON
  POST /demo/{scenario}           -> run a scenario (protected) and return the transcript
  POST /demo/{scenario}/split     -> run unprotected AND protected (for Split demo)
  POST /soar/block                -> quarantine a tool (used by the Shuffle playbook)
  GET  /stats
  GET  /leef                      -> recent events as LEEF 2.0 (QRadar format)
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from common import llm
from common.config import ROOT
from demo.fixtures import SCENARIOS
from demo.replay import run_protected, run_unprotected
from siem import explain as explain_mod
from siem import generators, leef, report
from siem.store import Store

app = FastAPI(title="AgentSOC", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

store = Store()
DASHBOARD = ROOT / "dashboard" / "index.html"


@app.get("/")
def index():
    if DASHBOARD.exists():
        return FileResponse(DASHBOARD)
    return {"service": "AgentSOC", "llm": "on" if llm.has_key() else "template-mode"}


@app.get("/health")
def health():
    return {"ok": True, "llm": llm.has_key(), "scenarios": list(SCENARIOS)}


@app.get("/stats")
def stats():
    s = store.stats()
    s["llm"] = llm.has_key()
    return s


@app.get("/metrics")
def metrics():
    m = store.metrics()
    m["llm"] = llm.has_key()
    return m


@app.get("/events")
def events(limit: int = 200, session_id: str | None = None):
    return store.list_events(limit=limit, session_id=session_id)


@app.get("/alerts")
def alerts(limit: int = 200, session_id: str | None = None):
    return store.list_alerts(limit=limit, session_id=session_id)


@app.get("/alerts/{alert_id}")
def alert_detail(alert_id: str):
    a = store.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    a["event"] = store.get_event(a["event_id"])
    a["chain"] = store.list_events(limit=50, session_id=a.get("session_id"))
    return a


@app.post("/alerts/{alert_id}/explain")
def alert_explain(alert_id: str, lang: str = Query("en")):
    a = store.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    return explain_mod.explain(a, lang=lang)


@app.post("/alerts/{alert_id}/rules")
def alert_rules(alert_id: str, hours: int = 1):
    a = store.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    return generators.generate_rules(a, hours=hours)


@app.post("/alerts/{alert_id}/report")
def alert_report(alert_id: str):
    a = store.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    chain = store.list_events(limit=50, session_id=a.get("session_id"))
    return report.build_report(a, chain=chain)


class BlockRequest(BaseModel):
    server: str
    tool: str = "*"
    reason: str = "blocked via SOAR"


@app.post("/soar/block")
def soar_block(req: BlockRequest):
    store.block_tool(req.server, req.tool, req.reason)
    return {"blocked": True, "server": req.server, "tool": req.tool}


@app.post("/soar/unblock")
def soar_unblock(req: BlockRequest):
    store.unblock_tool(req.server, req.tool)
    return {"unblocked": True, "server": req.server, "tool": req.tool}


@app.get("/soar/blocklist")
def soar_blocklist():
    return store.list_blocklist()


@app.post("/demo/run_all")
def demo_run_all():
    """Run every scenario (protected) — one-click demo seed."""
    out = {}
    for name in SCENARIOS:
        r = run_protected(name, store=store)
        out[name] = {"alerts": len(r.alerts), "leaked": r.leaked}
    return {"ran": out, "stats": store.stats()}


@app.post("/reset")
def reset():
    store.reset(approvals=True)
    return {"reset": True, "stats": store.stats()}


@app.post("/demo/{scenario}")
def demo(scenario: str):
    if scenario not in SCENARIOS:
        raise HTTPException(404, f"unknown scenario; choose from {list(SCENARIOS)}")
    r = run_protected(scenario, store=store)
    return _replay_json(r)


@app.post("/demo/{scenario}/split")
def demo_split(scenario: str):
    if scenario not in SCENARIOS:
        raise HTTPException(404, f"unknown scenario; choose from {list(SCENARIOS)}")
    unprot = run_unprotected(scenario, store=store)
    prot = run_protected(scenario, store=store)
    return {
        "scenario": scenario,
        "info": SCENARIOS[scenario],
        "unprotected": _replay_json(unprot),
        "protected": _replay_json(prot),
    }


@app.get("/scenarios")
def scenarios():
    return {k: {"title": v["title"], "task": v["task"], "description": v["description"]}
            for k, v in SCENARIOS.items()}


@app.get("/leef", response_class=PlainTextResponse)
def leef_export(limit: int = 50):
    lines = [leef.event_to_leef(e) for e in store.list_events(limit=limit)]
    return "\n".join(lines)


def _replay_json(r) -> dict:
    return {
        "scenario": r.scenario,
        "mode": r.mode,
        "session_id": r.session_id,
        "leaked": r.leaked,
        "alerts": r.alerts,
        "steps": [vars(s) for s in r.steps],
    }
