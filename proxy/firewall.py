"""The firewall decision engine: the heart of AgentSOC.

It is independent of transport. The live stdio proxy and the fixture replay
both feed it three kinds of event and act on its verdict:

  inspect_tools_list(server, tools)  -> (safe_tools, alerts)
  inspect_call(server, tool, args)   -> Decision
  inspect_result(server, tool, text) -> (safe_text, alerts)

A Decision with .blocked == True means the call must not reach the server.
Everything is written to the SIEM store as it happens.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from common.config import load_config
from siem.store import Store

from . import rules
from .judge import judge_finding
from .models import Alert, Event, Finding


@dataclass
class Decision:
    allow: bool
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return not self.allow


class Firewall:
    def __init__(self, store: Store | None = None, cfg: dict | None = None,
                 session_id: str = "", task: str = "") -> None:
        self.cfg = cfg or load_config()
        self.store = store or Store()
        self.session_id = session_id
        self.task = task
        self.alerts: list[Alert] = []  # alerts raised in this session (for the replay/demo)

    # ---------------------------------------------------------------- helpers
    def _record(self, event: Event) -> Event:
        self.store.add_event(event)
        return event

    def _raise(self, finding: Finding, event: Event, action: str) -> Alert:
        alert = Alert.from_finding(finding, event, action, task=self.task)
        self.store.add_alert(alert)
        self.alerts.append(alert)
        return alert

    @staticmethod
    def _top_risk(findings: list[Finding]) -> str:
        order = ["info", "low", "medium", "high", "critical"]
        best = "info"
        for f in findings:
            if order.index(f.risk) > order.index(best):
                best = f.risk
        return best

    # ---------------------------------------------------------------- tools/list
    def inspect_tools_list(self, server: str, tools: list[dict]) -> tuple[list[dict], list[Alert]]:
        """Scan each tool definition for poisoning and rug pulls. Returns kept tools + alerts."""
        action_cfg = self.cfg["policy"].get("tool_poisoning_action", "quarantine")
        kept: list[dict] = []
        raised: list[Alert] = []
        seen = self._seen_tool_servers()  # tool name -> first server that offered it
        for tool in tools:
            findings: list[Finding] = []
            f1 = rules.check_tool_poisoning(tool, self.cfg)
            if f1:
                findings.append(f1)
            name = tool.get("name", "")
            f9 = rules.check_tool_shadowing(server, name, seen)
            if f9:
                findings.append(f9)
            seen.setdefault(name, server)
            approval = self.store.get_approval(server, tool.get("name", ""))
            f4 = rules.check_rug_pull(
                tool,
                approval["hash"] if approval else None,
                approval["description"] if approval else None,
            )
            if f4:
                findings.append(f4)

            poisoned = any(f.blocking for f in findings)
            quarantine = poisoned and action_cfg == "quarantine"
            action = "quarantined" if quarantine else ("alerted" if findings else "allowed")

            ev = self._record(Event(
                server=server, method="tools/list", direction="server->agent",
                session_id=self.session_id, tool=tool.get("name"),
                result={"description": tool.get("description")},
                risk=self._top_risk(findings), action=action,
            ))
            for f in findings:
                raised.append(self._raise(f, ev, action))

            if not quarantine:
                kept.append(tool)
            # First clean sighting of a tool becomes the approved baseline (rug-pull anchor).
            if not approval and not poisoned:
                self.store.approve(server, tool.get("name", ""),
                                   rules.tool_fingerprint(tool), tool.get("description") or "")
        return kept, raised

    # ---------------------------------------------------------------- tools/call
    def inspect_call(self, server: str, tool: str, args: dict) -> Decision:
        """Run call-time rules + the judge. Block on any high/critical finding."""
        findings: list[Finding] = []

        if self.store.is_blocked(server, tool):
            findings.append(Finding(
                "R0_SOAR_BLOCKLIST", rules.TITLES["R0_SOAR_BLOCKLIST"], "high",
                rules.TAGS["R0_SOAR_BLOCKLIST"], f"Tool '{tool}' is on the SOAR blocklist."))

        for f in (rules.check_sensitive_file(tool, args, self.cfg),
                  rules.check_path_traversal(tool, args),
                  rules.check_exfiltration(tool, args, self.cfg),
                  rules.check_secret_payload(tool, args, self.cfg)):
            if f:
                findings.append(f)

        if self.cfg["policy"].get("judge_enabled", True) and not any(f.blocking for f in findings):
            all_tools = self._known_tools(server)
            jf = judge_finding(self.task, all_tools, tool, args)
            if jf:
                findings.append(jf)

        blocked = any(f.blocking for f in findings)
        action = "blocked" if blocked else ("alerted" if findings else "allowed")
        ev = self._record(Event(
            server=server, method="tools/call", direction="agent->server",
            session_id=self.session_id, tool=tool, arguments=args,
            risk=self._top_risk(findings), action=action,
        ))
        for f in findings:
            self._raise(f, ev, action)
        reason = "; ".join(f.reason for f in findings if f.blocking)
        return Decision(allow=not blocked, findings=findings, reason=reason)

    def _seen_tool_servers(self) -> dict[str, str]:
        """Map tool name -> first server that offered it in this session (for shadowing)."""
        out: dict[str, str] = {}
        for e in reversed(self.store.list_events(limit=500, session_id=self.session_id)):
            if e["method"] == "tools/list" and e["tool"]:
                out.setdefault(e["tool"], e["server"])
        return out

    def _known_tools(self, server: str) -> list[dict]:
        tools = []
        seen = set()
        for e in self.store.list_events(limit=500, session_id=self.session_id):
            if e["server"] == server and e["method"] == "tools/list" and e["tool"] and e["tool"] not in seen:
                seen.add(e["tool"])
                desc = (e.get("result") or {}).get("description") if isinstance(e.get("result"), dict) else None
                tools.append({"name": e["tool"], "description": desc})
        return tools

    # ---------------------------------------------------------------- results
    def inspect_result(self, server: str, tool: str, text: str) -> tuple[str, list[Alert]]:
        """Scan a tool result for prompt injection; redact or block per policy."""
        finding = rules.check_data_injection(tool, text, self.cfg)
        if not finding:
            return text, []
        mode = self.cfg["policy"].get("injection_action", "redact")
        if mode == "block" or finding.risk == "critical":
            safe, action = "[AGENTSOC blocked this tool result: it contained prompt injection]", "blocked"
        else:
            safe, action = rules.redact_injection(text), "redacted"
        ev = self._record(Event(
            server=server, method="tools/call:result", direction="server->agent",
            session_id=self.session_id, tool=tool, result={"redacted": True},
            risk=finding.risk, action=action,
        ))
        return safe, [self._raise(finding, ev, action)]
