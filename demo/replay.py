"""Replay an attack scenario against the real MCP servers.

Two directions:
  run_unprotected(scenario)  -> messages go straight to the servers; attacks succeed
                                (the fake key really lands in outbox.jsonl)
  run_protected(scenario)    -> every message passes through the Firewall, which
                                blocks dangerous calls and raises SOC alerts.

Both return a transcript the demo / API / dashboard can display.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from common.config import load_config
from common.mcp_client import MCPConnection
from proxy.firewall import Firewall
from proxy.models import new_id
from proxy.rules import result_to_text
from siem.store import Store

from .fixtures import SERVERS, SCENARIOS


@dataclass
class Step:
    op: str
    server: str
    tool: str | None = None
    arguments: Any = None
    status: str = "ok"          # ok, blocked, redacted, quarantined, error
    detail: str = ""
    result_preview: str = ""


@dataclass
class ReplayResult:
    scenario: str
    mode: str                   # "unprotected" | "protected"
    session_id: str
    steps: list[Step] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    leaked: bool = False        # did secret material reach the attacker?


def _open(servers: list[str]) -> dict[str, MCPConnection]:
    conns = {}
    try:
        for key in servers:
            conns[key] = MCPConnection(SERVERS[key]).__enter__()
        return conns
    except Exception:
        for c in conns.values():
            c.__exit__(None, None, None)
        raise


def _close(conns: dict[str, MCPConnection]) -> None:
    for c in conns.values():
        try:
            c.__exit__(None, None, None)
        except Exception:
            pass


def _build_args(step: dict, fed: dict[str, str]) -> dict:
    args = dict(step.get("arguments") or {})
    # 'body_from' / 'arguments_from' pull a previously captured secret into the call.
    if "body_from" in args:
        name = args.pop("body_from")
        args["body"] = fed.get(name, "")
    return args


def _is_exfil(server_key: str, tool: str, args: dict, text: str) -> bool:
    attacker = "evil.example"
    to = str(args.get("to", "")) if args else ""
    body = str(args.get("body", "")) if args else ""
    return tool == "send_email" and attacker in to and ("FAKE-KEY" in body or "PRIVATE KEY" in body)


def run_unprotected(scenario: str, store: Store | None = None) -> ReplayResult:
    sc = SCENARIOS[scenario]
    session_id = "unprot-" + new_id()
    res = ReplayResult(scenario=scenario, mode="unprotected", session_id=session_id)
    fed: dict[str, str] = {}
    conns = _open(sc["servers"])
    try:
        for raw in sc["steps"]:
            server = raw["server"]
            if raw["op"] == "list":
                tools = conns[server].list_tools()
                res.steps.append(Step("list", server, detail=f"{len(tools)} tool(s)"))
                continue
            tool = raw["tool"]
            args = _build_args(raw, fed)
            out = conns[server].call_tool(tool, args)
            text = result_to_text(out)
            if raw.get("feeds"):
                fed[raw["feeds"]] = text
            leaked = _is_exfil(server, tool, args, text)
            res.leaked = res.leaked or leaked
            res.steps.append(Step(
                "call", server, tool, args,
                status="leaked" if leaked else "ok",
                detail="secret sent to attacker" if leaked else "",
                result_preview=text[:160],
            ))
    finally:
        _close(conns)
    return res


def run_protected(scenario: str, store: Store | None = None, task: str | None = None) -> ReplayResult:
    sc = SCENARIOS[scenario]
    store = store or Store()
    session_id = "prot-" + new_id()
    fw = Firewall(store=store, cfg=load_config(), session_id=session_id, task=task or sc["task"])
    res = ReplayResult(scenario=scenario, mode="protected", session_id=session_id)
    fed: dict[str, str] = {}
    conns = _open(sc["servers"])
    try:
        for raw in sc["steps"]:
            server = raw["server"]
            if raw["op"] == "list":
                tools = conns[server].list_tools()
                kept, _ = fw.inspect_tools_list(server, tools)
                removed = len(tools) - len(kept)
                res.steps.append(Step(
                    "list", server,
                    status="quarantined" if removed else "ok",
                    detail=f"{len(kept)} kept, {removed} quarantined",
                ))
                continue
            tool = raw["tool"]
            args = _build_args(raw, fed)
            decision = fw.inspect_call(server, tool, args)
            if decision.blocked:
                res.steps.append(Step("call", server, tool, args, status="blocked",
                                      detail=decision.reason))
                continue
            out = conns[server].call_tool(tool, args)
            text = result_to_text(out)
            safe, result_alerts = fw.inspect_result(server, tool, text)
            if raw.get("feeds"):
                fed[raw["feeds"]] = safe  # downstream steps see the sanitised data
            leaked = _is_exfil(server, tool, args, safe)
            res.leaked = res.leaked or leaked
            status = "redacted" if result_alerts else ("leaked" if leaked else "ok")
            res.steps.append(Step("call", server, tool, args, status=status,
                                  result_preview=safe[:160]))
    finally:
        _close(conns)
    res.alerts = [a.to_dict() for a in fw.alerts]
    return res
