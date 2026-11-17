"""Blue-team integrations: QRadar offenses, Palo Alto, closed-loop SOAR, LEEF shipping."""
from __future__ import annotations

import socket
import threading
import time

from fastapi.testclient import TestClient

from demo.replay import run_protected
from siem import soar
from siem.generators import generate_panos


def _client():
    from api.main import app
    return TestClient(app)


# --------------------------------------------------- Palo Alto PAN-OS
def test_panos_block_rule():
    alert = {"rule_id": "R3_EXFILTRATION", "risk": "critical", "server": "mail",
             "tool": "send_email", "reason": "send_email to attacker@evil.example",
             "evidence": "{\"to\": \"attacker@evil.example\"}"}
    pa = generate_panos(alert)
    assert "evil.example" in pa["edl_domains"]
    assert pa["rule_name"].startswith("AgentSOC-block")
    assert any("action deny" in c for c in pa["set_commands"])
    assert "PANOS" in pa["rest_api"]


def test_edl_endpoint(store):
    c = _client()
    c.post("/demo/tool_poisoning")
    edl = c.get("/edl/domains").text
    assert "evil.example" in edl


# --------------------------------------------------- QRadar offenses
def test_offenses_correlate_by_session(store):
    c = _client()
    c.post("/demo/run_all")
    offs = c.get("/offenses").json()
    assert offs
    top = offs[0]
    assert 1 <= top["magnitude"] <= 10
    assert top["alert_count"] >= 1
    assert top["rules"]
    # the worst offense (tool poisoning chain) should be high magnitude
    assert max(o["magnitude"] for o in offs) >= 8


# --------------------------------------------------- closed-loop SOAR
def test_soar_execute_contains_and_blocks(store):
    r = run_protected("tool_poisoning", store=store)
    exfil = next(a for a in r.alerts if a["rule_id"] == "R3_EXFILTRATION")
    alert = store.get_alert(exfil["id"])
    result = soar.execute_playbook(alert, store)
    assert result["contained"] is True
    assert any(s["id"] == "block_tool" and s["status"] == "ok" for s in result["steps"])
    # the tool is now on the SOAR blocklist -> a later call is blocked by rule R0
    assert store.is_blocked(alert["server"], alert["tool"]) is True


def test_soar_execute_endpoint(store):
    c = _client()
    c.post("/demo/rug_pull")
    alert = next(a for a in c.get("/alerts").json() if a["risk"] in ("high", "critical"))
    ex = c.post(f"/alerts/{alert['id']}/soar/execute").json()
    assert "steps" in ex and ex["playbook"]


# --------------------------------------------------- LEEF shipping to QRadar
def test_leef_shipping_to_collector(store):
    c = _client()
    c.post("/demo/tool_poisoning")
    sid = c.get("/alerts").json()[0]["session_id"]

    got = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 5601))
    srv.settimeout(3)

    def rx():
        try:
            while True:
                d, _ = srv.recvfrom(65535)
                got.append(d.decode("utf-8", "replace"))
        except socket.timeout:
            pass

    t = threading.Thread(target=rx)
    t.start()
    res = c.post("/siem/ship", json={"session_id": sid, "host": "127.0.0.1", "port": 5601}).json()
    time.sleep(0.4)
    t.join()
    srv.close()
    assert res["shipped"] > 0
    assert len(got) == res["shipped"]
    assert any("LEEF:2.0|AgentSOC" in line for line in got)
