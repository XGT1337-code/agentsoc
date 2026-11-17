"""Log analyzer: knowledge base, multi-format parsing, correlation, API."""
from __future__ import annotations

from fastapi.testclient import TestClient

from analyzer import knowledge
from analyzer.analyze import analyze_text
from analyzer.parse import parse


# ------------------------------------------------------------ knowledge base
def test_known_event_names():
    assert knowledge.lookup("windows", "4624")["name"] == "Successful logon"
    assert knowledge.lookup("windows", "4625")["outcome"] == "failure"
    assert knowledge.lookup("windows", "1102")["severity"] == "critical"
    assert knowledge.lookup("sysmon", "1")["source"] == "sysmon"
    assert knowledge.lookup("windows", "99999") is None


def test_worst_severity():
    assert knowledge.worst("low", "critical") == "critical"
    assert knowledge.worst("info", "medium") == "medium"


# ------------------------------------------------------------ parsing
def test_parse_windows_text():
    recs = parse("Event ID: 4625 TargetUserName=admin IpAddress=10.0.0.9")
    assert recs[0]["event_id"] == "4625"
    assert recs[0]["fields"]["user"] == "admin"
    assert recs[0]["fields"]["ip"] == "10.0.0.9"


def test_parse_json_ndjson():
    recs = parse('{"EventID": 4624, "TargetUserName": "bob", "Channel": "Security"}')
    assert recs[0]["event_id"] == "4624"
    assert recs[0]["source"] == "windows"


def test_parse_csv():
    csv_text = "EventID,TargetUserName,IpAddress\n4625,admin,10.0.0.1\n4624,admin,10.0.0.1\n"
    recs = parse(csv_text)
    assert {r["event_id"] for r in recs} == {"4625", "4624"}


def test_parse_cef():
    recs = parse("CEF:0|Vendor|Product|1.0|4625|Failed logon|5|src=10.0.0.1 suser=admin")
    assert recs[0]["event_id"] == "4625"


def test_parse_palo_alto_csv():
    line = "future,2024/01/01 10:00:00,0011,THREAT,vulnerability,10,eth1,eth2,rule,,,web,,,critical"
    recs = parse(line)
    assert recs[0]["source"] == "palo-alto"
    assert recs[0]["event_id"] == "THREAT"


def test_parse_linux_auth():
    recs = parse("Jan 1 10:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2")
    assert recs[0]["source"] == "linux-auth"
    assert recs[0]["fields"]["ip"] == "1.2.3.4"


# ------------------------------------------------------------ analysis / correlation
def _win(eid, **kw):
    extra = " ".join(f"{k}={v}" for k, v in kw.items())
    return f"Event ID: {eid} {extra}"


def test_brute_force_success_is_critical():
    lines = [_win("4625", TargetUserName="admin", IpAddress="10.0.0.9") for _ in range(6)]
    lines.append(_win("4624", TargetUserName="admin", IpAddress="10.0.0.9"))
    r = analyze_text("\n".join(lines))
    assert r["verdict"] == "malicious"
    assert any(f["id"] == "brute_force_success" for f in r["findings"])


def test_log_cleared_is_critical():
    r = analyze_text(_win("1102", Computer="DC01"))
    assert r["max_severity"] == "critical"
    assert any(f["id"] == "log_cleared" for f in r["findings"])


def test_account_added_to_admins():
    r = analyze_text(_win("4720", TargetUserName="bob") + "\n" + _win("4732", TargetUserName="bob"))
    assert any(f["id"] == "account_manipulation" for f in r["findings"])


def test_clean_traffic_has_no_findings():
    r = analyze_text(_win("4624", TargetUserName="alice") + "\n" + _win("4634"))
    assert r["verdict"] == "clean"
    assert r["findings"] == []


def test_every_event_is_named():
    r = analyze_text(_win("4624") + "\n" + _win("4625") + "\n" + _win("1102"))
    assert r["summary"]["recognized"] == 3
    names = {e["name"] for e in r["events"]}
    assert "Successful logon" in names and "Audit log cleared" in names


# ------------------------------------------------------------ API
def _client():
    from api.main import app
    return TestClient(app)


def test_api_logs_analyze():
    c = _client()
    lines = "\n".join("Event ID: 4625 TargetUserName=admin IpAddress=10.0.0.9" for _ in range(6))
    lines += "\nEvent ID: 4624 TargetUserName=admin IpAddress=10.0.0.9"
    r = c.post("/logs/analyze", json={"text": lines})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "malicious"
    assert body["summary"]["recognized"] == 7
    # analysis findings are persisted as alerts
    assert any(a["server"] == "log-analyzer" for a in c.get("/alerts").json())


def test_api_logs_knowledge():
    c = _client()
    kb = c.get("/logs/knowledge").json()
    assert kb["count"] > 20
    assert any(s["event_id"] == "4625" for s in kb["signatures"])
