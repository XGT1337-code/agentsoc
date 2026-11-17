"""Data structures shared by the proxy, the SIEM store and the API."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_id() -> str:
    return uuid.uuid4().hex[:12]


@dataclass
class Event:
    """One MCP message seen by the proxy."""

    server: str
    method: str  # tools/list, tools/call, or a "response:" variant
    direction: str  # "agent->server" or "server->agent"
    session_id: str = ""
    tool: str | None = None
    arguments: Any = None
    result: Any = None
    risk: str = "info"
    action: str = "allowed"  # allowed, blocked, redacted, quarantined
    id: str = field(default_factory=new_id)
    ts: str = field(default_factory=now_iso)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    """Result of one detection rule."""

    rule_id: str
    title: str
    risk: str  # low, medium, high, critical
    tag: str  # MITRE ATLAS / OWASP LLM Top 10 tag(s)
    reason: str
    evidence: str = ""

    @property
    def blocking(self) -> bool:
        return RISK_ORDER.get(self.risk, 0) >= RISK_ORDER["high"]


@dataclass
class Alert:
    """A SOC alert produced from a Finding."""

    rule_id: str
    title: str
    risk: str
    tag: str
    reason: str
    server: str
    tool: str | None
    action: str  # blocked, redacted, quarantined, alerted
    event_id: str
    session_id: str = ""
    task: str = ""
    evidence: str = ""
    id: str = field(default_factory=new_id)
    ts: str = field(default_factory=now_iso)

    @classmethod
    def from_finding(cls, f: Finding, event: Event, action: str, task: str = "") -> "Alert":
        return cls(
            rule_id=f.rule_id,
            title=f.title,
            risk=f.risk,
            tag=f.tag,
            reason=f.reason,
            evidence=f.evidence,
            server=event.server,
            tool=event.tool,
            action=action,
            event_id=event.id,
            session_id=event.session_id,
            task=task,
        )

    def to_dict(self) -> dict:
        return asdict(self)
