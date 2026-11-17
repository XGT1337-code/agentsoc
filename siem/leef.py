"""Export events to IBM QRadar LEEF 2.0.

LEEF 2.0 header:
  LEEF:2.0|Vendor|Product|Version|EventID|DelimiterChar|key=value<tab>key=value...

Syslog shipping is OFF by default. When config syslog.enabled is true, events
are sent to QRadar over UDP. Nothing is sent to the internet in the demo.
"""
from __future__ import annotations

import socket
from datetime import datetime, timezone

from common.config import load_config

VENDOR = "AgentSOC"
PRODUCT = "MCP-Firewall"
VERSION = "1.0"
DELIM = "\t"

# Map our risk words to a numeric severity QRadar understands (1..10).
_SEV = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}


def _attr(key: str, value) -> str:
    if value is None:
        value = ""
    text = str(value).replace("\n", " ").replace("\r", " ").replace(DELIM, " ")
    return f"{key}={text}"


def event_to_leef(event: dict) -> str:
    """Render one event dict (from the store) as a LEEF 2.0 line."""
    event_id = f"MCP_{event.get('method', 'unknown').upper().replace('/', '_').replace(':', '_')}"
    ts = event.get("ts") or datetime.now(timezone.utc).isoformat()
    attrs = [
        _attr("devTime", ts),
        _attr("devTimeFormat", "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"),
        _attr("sev", _SEV.get(event.get("risk", "info"), 1)),
        _attr("cat", event.get("action", "allowed")),
        _attr("mcpServer", event.get("server")),
        _attr("mcpMethod", event.get("method")),
        _attr("mcpTool", event.get("tool")),
        _attr("direction", event.get("direction")),
        _attr("sessionId", event.get("session_id")),
        _attr("agentSocEventId", event.get("id")),
        _attr("risk", event.get("risk")),
    ]
    header = f"LEEF:2.0|{VENDOR}|{PRODUCT}|{VERSION}|{event_id}|{DELIM}|"
    return header + DELIM.join(attrs)


def alert_to_leef(alert: dict) -> str:
    """Render an alert dict as a LEEF 2.0 line (richer, carries rule + tag)."""
    attrs = [
        _attr("devTime", alert.get("ts")),
        _attr("devTimeFormat", "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"),
        _attr("sev", _SEV.get(alert.get("risk", "info"), 1)),
        _attr("cat", alert.get("action")),
        _attr("ruleId", alert.get("rule_id")),
        _attr("ruleName", alert.get("title")),
        _attr("frameworkTag", alert.get("tag")),
        _attr("mcpServer", alert.get("server")),
        _attr("mcpTool", alert.get("tool")),
        _attr("sessionId", alert.get("session_id")),
        _attr("reason", alert.get("reason")),
        _attr("risk", alert.get("risk")),
    ]
    header = f"LEEF:2.0|{VENDOR}|{PRODUCT}|{VERSION}|MCP_ALERT|{DELIM}|"
    return header + DELIM.join(attrs)


def send_syslog(line: str, cfg: dict | None = None) -> bool:
    """Send one LEEF line over UDP to QRadar if syslog.enabled. Returns True if sent."""
    cfg = cfg or load_config()
    sy = cfg.get("syslog", {})
    if not sy.get("enabled"):
        return False
    # RFC3164-ish priority prefix: local0.notice = 134.
    payload = f"<134>{line}".encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, (sy.get("host", "127.0.0.1"), int(sy.get("port", 514))))
        return True
    finally:
        sock.close()
