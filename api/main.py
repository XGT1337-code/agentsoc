"""FastAPI backend for the AgentSOC dashboard.

Endpoints:
  GET  /events
  GET  /alerts
  GET  /alerts/{id}
  POST /alerts/{id}/explain?lang=az|en
  POST /alerts/{id}/rules         -> AQL + Shuffle JSON
  POST /demo/{scenario}           -> run a scenario (protected) and return the transcript
  POST /demo/{scenario}/split     -> run unprotected AND protected (for Split demo)
  POST /soar/block                -> quarantine a tool (used by the Shuffle playbook)
  GET  /stats
  GET  /leef                      -> recent events as LEEF 2.0 (QRadar format)
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel

from common import llm
from common.config import ROOT, load_config
from demo.fixtures import SCENARIOS
from demo.replay import run_protected, run_unprotected
from gateway import auth, otp
from proxy.scan import scan_text
from proxy import jailbreak as chatguard
from siem import explain as explain_mod
from analyzer import analyze as log_analyze
from siem import collector, generators, leef, presence as presence_mod, report, soar
from siem.store import Store

app = FastAPI(title="AgentSOC", version="1.1")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

store = Store()
DASHBOARD = ROOT / "dashboard" / "index.html"
LOGIN = ROOT / "dashboard" / "login.html"
LOCKED = ROOT / "dashboard" / "locked.html"

SESSION_COOKIE = "agentsoc_session"
GATEPASS_COOKIE = "agentsoc_gate"

# Paths reachable without a logged-in session (the auth flow itself + machine feeds).
_PUBLIC = ("/", "/health", "/auth/request-otp", "/auth/verify-otp", "/logout",
           "/edl/domains", "/docs", "/openapi.json", "/favicon.ico")


@app.middleware("http")
async def _auth_guard(request: Request, call_next):
    """Everything but the auth flow needs a valid logged-in session when auth is on."""
    # Record presence for every caller (who is on the service right now).
    try:
        ip = request.client.host if request.client else ""
        who = auth.session_email(request.cookies.get(SESSION_COOKIE))
        store.touch_presence(ip, "web", who, request.headers.get("user-agent"))
    except Exception:
        pass
    if not auth.auth_enabled():
        return await call_next(request)
    path = request.url.path
    if path in _PUBLIC or path.startswith("/auth/"):
        return await call_next(request)
    sid = request.cookies.get(SESSION_COOKIE)
    if auth.session_email(sid):
        return await call_next(request)
    from fastapi.responses import JSONResponse
    return JSONResponse({"error": "unauthenticated", "hint": "log in via the SSH gateway + OTP"},
                        status_code=401)


@app.get("/")
def index(request: Request, gate: str | None = None):
    # Auth off (tests/dev): straight to the dashboard.
    if not auth.auth_enabled():
        return FileResponse(DASHBOARD) if DASHBOARD.exists() else {"service": "AgentSOC"}
    # Arriving with a one-time SSH gate token ALWAYS starts a fresh login: any old
    # session is discarded so coming in through SSH always demands the OTP again.
    # (Checked before the session cookie, so a stale session can never skip OTP.)
    if gate and auth.consume_gate(gate):
        auth.logout(request.cookies.get(SESSION_COOKIE))  # kill any previous session
        html = LOGIN.read_text(encoding="utf-8") if LOGIN.exists() else "<h1>login</h1>"
        resp = HTMLResponse(html)
        resp.delete_cookie(SESSION_COOKIE)
        resp.set_cookie(GATEPASS_COOKIE, auth.new_gatepass(), httponly=True, samesite="lax")
        return resp
    # Already logged in (direct revisit without a gate link, within the session TTL).
    if auth.session_email(request.cookies.get(SESSION_COOKIE)):
        return FileResponse(DASHBOARD)
    # Passed the SSH gate earlier -> email + OTP login page.
    if auth.gatepass_valid(request.cookies.get(GATEPASS_COOKIE)):
        return FileResponse(LOGIN) if LOGIN.exists() else HTMLResponse("<h1>login</h1>")
    # No SSH gate -> locked.
    return FileResponse(LOCKED) if LOCKED.exists() else HTMLResponse(
        "<h1>AgentSOC locked</h1><p>Connect through the SSH gateway first.</p>", status_code=403)


@app.get("/health")
def health():
    return {"ok": True, "llm": llm.has_key(), "scenarios": list(SCENARIOS),
            "auth": auth.auth_enabled()}


@app.get("/presence")
def presence(window: int = 600):
    """Clients connected to AgentSOC right now: IP, hostname, MAC, device, who."""
    clients = presence_mod.list_connected(store, window_secs=window)
    return {"window_secs": window, "count": len(clients), "clients": clients}


# ---------------------------------------------------------------- auth flow
class OtpRequest(BaseModel):
    email: str


class OtpVerify(BaseModel):
    email: str
    code: str


@app.post("/auth/request-otp")
def auth_request_otp(req: OtpRequest, request: Request):
    if auth.auth_enabled() and not auth.gatepass_valid(request.cookies.get(GATEPASS_COOKIE)):
        raise HTTPException(403, "come through the SSH gateway first")
    code = auth.request_otp(req.email)
    if code is None:
        # Do not reveal which email is the admin; generic response.
        raise HTTPException(400, "that address is not authorized")
    delivery = otp.deliver(code)
    # Never return the code itself in the API response.
    return {"sent": True, "channel": delivery["channel"], "detail": delivery["detail"]}


@app.post("/auth/verify-otp")
def auth_verify_otp(req: OtpVerify, request: Request):
    if auth.auth_enabled() and not auth.gatepass_valid(request.cookies.get(GATEPASS_COOKIE)):
        raise HTTPException(403, "come through the SSH gateway first")
    sid = auth.verify_otp(req.email, req.code)
    if not sid:
        raise HTTPException(401, "invalid or expired code")
    resp = Response()
    resp.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="lax")
    resp.delete_cookie(GATEPASS_COOKIE)
    return resp


@app.get("/logout")
def logout(request: Request):
    auth.logout(request.cookies.get(SESSION_COOKIE))
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/whoami")
def whoami(request: Request):
    return {"email": auth.session_email(request.cookies.get(SESSION_COOKIE)) or None}


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


@app.post("/alerts/{alert_id}/soar/execute")
def alert_soar_execute(alert_id: str):
    """Run the Shuffle playbook for this alert — closes the loop (quarantines the tool)."""
    a = store.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    return soar.execute_playbook(a, store)


@app.get("/offenses")
def offenses():
    """QRadar-style offenses: alerts correlated per session, with magnitude 1-10."""
    return store.offenses()


@app.get("/edl/domains", response_class=PlainTextResponse)
def edl_domains():
    """Palo Alto External Dynamic List: attacker domains seen across all alerts."""
    seen = set()
    for a in store.list_alerts(limit=500):
        for d in generators.generate_panos(a)["edl_domains"]:
            seen.add(d)
    return "\n".join(sorted(seen)) or "evil.example"


class ShipRequest(BaseModel):
    session_id: str
    host: str = "127.0.0.1"
    port: int = 5514


@app.post("/siem/ship")
def siem_ship(req: ShipRequest):
    """Ship a session's events + alerts to a QRadar collector as LEEF 2.0 over UDP."""
    n = collector.ship_session(store, req.session_id, req.host, req.port)
    return {"shipped": n, "host": req.host, "port": req.port, "format": "LEEF 2.0"}


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


class ScanRequest(BaseModel):
    text: str
    source: str = "pasted content"


@app.post("/scan")
def scan(req: ScanRequest):
    """Content firewall: scan arbitrary untrusted text (prompt, email, doc) for
    prompt injection / exfiltration / secrets — protects any local AI, not just MCP."""
    result = scan_text(req.text, source=req.source)
    _record_scan(result)
    return result


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    """Upload a file; AgentSOC scans its text content before any AI reads it."""
    raw = await file.read()
    if len(raw) > 2_000_000:
        raise HTTPException(413, "file too large (max 2 MB for the demo)")
    text = raw.decode("utf-8", "replace")
    result = scan_text(text, source=f"file:{file.filename}")
    result["filename"] = file.filename
    result["bytes"] = len(raw)
    _record_scan(result)
    return result


class LogAnalyzeRequest(BaseModel):
    text: str
    source: str | None = None


@app.post("/logs/analyze")
def logs_analyze(req: LogAnalyzeRequest):
    """Drop real SIEM/EDR logs (Windows/Sysmon/Palo Alto/CEF/LEEF/Linux). AgentSOC
    names every event, correlates attack patterns and returns a verdict."""
    result = log_analyze.analyze_text(req.text, source=req.source)
    _record_analysis(result, req.source or "pasted-log")
    return result


@app.post("/logs/upload")
async def logs_upload(file: UploadFile = File(...)):
    """Upload a real log file for analysis (not just a content scan)."""
    raw = await file.read()
    if len(raw) > 5_000_000:
        raise HTTPException(413, "file too large (max 5 MB)")
    text = raw.decode("utf-8", "replace")
    result = log_analyze.analyze_text(text, source=f"file:{file.filename}")
    result["filename"] = file.filename
    result["bytes"] = len(raw)
    _record_analysis(result, f"file:{file.filename}")
    return result


@app.get("/logs/knowledge")
def logs_knowledge():
    """The event knowledge base AgentSOC recognizes (for the 'what can it name' view)."""
    from analyzer import knowledge
    items = []
    for eid, s in {**knowledge.WINDOWS}.items():
        items.append({"source": "windows", "event_id": eid, **s})
    for eid, s in knowledge.SYSMON.items():
        items.append({"source": "sysmon", "event_id": eid, **s})
    return {"count": len(items), "signatures": items}


def _record_analysis(result: dict, source: str) -> None:
    """Persist log-analysis findings as events/alerts so they feed the dashboard + SIEM."""
    from proxy.models import Alert, Event, new_id
    sid = "logscan-" + new_id()
    verdict = result.get("verdict", "clean")
    ev = Event(server="log-analyzer", method="logs/analyze", direction="server->agent",
               session_id=sid, tool=source, risk=result.get("max_severity", "info"),
               action="detected" if verdict != "clean" else "allowed")
    store.add_event(ev)
    for f in result.get("findings", []):
        store.add_alert(Alert(
            rule_id=f["id"], title=f["title"], risk=f["severity"],
            tag=f.get("mitre", ""), reason=f.get("detail", ""),
            evidence=str(f.get("evidence", "")), server="log-analyzer", tool=source,
            action="detected", event_id=ev.id, session_id=sid, task="log analysis"))


class ChatGuardRequest(BaseModel):
    message: str


@app.post("/chatbot/guard")
def chatbot_guard(req: ChatGuardRequest):
    """AI chatbot firewall: inspect a user message for jailbreak / prompt injection /
    secret-extraction before the assistant answers. Blocks and returns a safe reply."""
    r = chatguard.inspect_message(req.message, source="chatbot")
    if r["verdict"] == "allow":
        r["assistant_reply"] = ("(Assistant answers normally — no attack detected. "
                                "In production the real model reply passes through here.)")
    elif r["verdict"] == "review":
        r["assistant_reply"] = ("I can help, but this message was flagged for review by "
                                "security and logged.")
    _record_chat(r)
    return r


def _record_chat(result: dict) -> None:
    """Persist a chatbot-guard verdict as an event + alerts for the SOC queue."""
    from proxy.models import Alert, Event, new_id
    sid = "chat-" + new_id()
    verdict = result.get("verdict", "allow")
    action = "blocked" if verdict == "block" else ("flagged" if result.get("findings") else "allowed")
    ev = Event(server="chatbot-guard", method="chatbot/guard", direction="agent->server",
               session_id=sid, tool="user-message", risk=result.get("risk", "info"), action=action)
    store.add_event(ev)
    for f in result.get("findings", []):
        store.add_alert(Alert(
            rule_id=f["rule_id"], title=f["title"], risk=f["risk"], tag=f.get("tag", ""),
            reason=f.get("reason", ""), evidence=str(f.get("evidence", "")), server="chatbot-guard",
            tool="user-message", action=action, event_id=ev.id, session_id=sid, task="chatbot guard"))


def _record_scan(result: dict) -> None:
    """Log a content scan as events/alerts so it shows on the dashboard + SIEM."""
    from proxy.models import Alert, Event, new_id
    sid = "scan-" + new_id()
    ev = Event(server="content-firewall", method="content/scan", direction="server->agent",
               session_id=sid, tool=result.get("source"), risk=result.get("risk", "info"),
               action="blocked" if result["verdict"] == "block" else
                      ("redacted" if result["findings"] else "allowed"))
    store.add_event(ev)
    for f in result.get("findings", []):
        store.add_alert(Alert(
            rule_id=f["rule_id"], title=f["title"], risk=f["risk"], tag=f["tag"],
            reason=f["reason"], evidence=f.get("evidence", ""), server="content-firewall",
            tool=result.get("source"),
            action="blocked" if result["verdict"] == "block" else "redacted",
            event_id=ev.id, session_id=sid, task="content scan"))


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
