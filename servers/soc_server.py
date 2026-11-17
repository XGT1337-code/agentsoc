"""SOC analyst MCP server: let an AI agent analyze real security logs.

Tools:
  analyze_logs(logs)            -> full analysis (named events, findings, verdict)
  lookup_event(event_id, source)-> what a single event id means
  list_known_events()           -> the event signatures AgentSOC recognizes

This is the "drop a real QRadar/Splunk/Palo Alto/Windows log and get a correct
SOC analysis" capability, exposed over MCP so an agent (behind the AgentSOC
firewall) can call it. Everything runs locally; no data leaves the machine.
"""
from __future__ import annotations

import json

from mcp.server.mcpserver import MCPServer

from analyzer import knowledge
from analyzer.analyze import analyze_text

server = MCPServer("agentsoc-soc-analyst")


@server.tool()
def analyze_logs(logs: str) -> str:
    """Analyze raw security logs (Windows Event, Sysmon, Palo Alto, CEF/LEEF, Linux
    auth). Returns JSON: recognized events with names, correlation findings and an
    overall verdict (clean / suspicious / malicious) with MITRE ATT&CK tags."""
    return json.dumps(analyze_text(logs), ensure_ascii=False, indent=1)


@server.tool()
def lookup_event(event_id: str, source: str = "windows") -> str:
    """Explain a single log event id, e.g. lookup_event('4625') -> failed logon.
    `source` is windows or sysmon."""
    sig = knowledge.lookup(source, event_id)
    if not sig:
        return json.dumps({"event_id": event_id, "known": False,
                           "note": "No signature; review manually."})
    return json.dumps({"known": True, **sig}, ensure_ascii=False)


@server.tool()
def list_known_events() -> str:
    """List the event signatures AgentSOC can recognize by name."""
    items = [{"source": "windows", "event_id": e, "name": s["name"], "outcome": s["outcome"]}
             for e, s in knowledge.WINDOWS.items()]
    items += [{"source": "sysmon", "event_id": e, "name": s["name"], "outcome": s["outcome"]}
              for e, s in knowledge.SYSMON.items()]
    return json.dumps({"count": len(items), "events": items}, ensure_ascii=False)


if __name__ == "__main__":
    server.run("stdio")
