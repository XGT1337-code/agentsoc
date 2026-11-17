"""SQLite storage for events, alerts, tool approvals and the SOAR blocklist.

Several proxy processes write to the same file at once, so every operation
opens a short connection with a busy timeout and WAL journaling.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from common.config import db_path
from proxy.models import Alert, Event, now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, ts TEXT, session_id TEXT, server TEXT, method TEXT,
    direction TEXT, tool TEXT, arguments TEXT, result TEXT, risk TEXT, action TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, ts TEXT, session_id TEXT, event_id TEXT, server TEXT, tool TEXT,
    rule_id TEXT, title TEXT, risk TEXT, tag TEXT, reason TEXT, evidence TEXT,
    action TEXT, task TEXT
);
CREATE TABLE IF NOT EXISTS approved_tools (
    server TEXT, tool TEXT, hash TEXT, description TEXT, approved_at TEXT,
    PRIMARY KEY (server, tool)
);
CREATE TABLE IF NOT EXISTS blocklist (
    server TEXT, tool TEXT, reason TEXT, created_at TEXT,
    PRIMARY KEY (server, tool)
);
CREATE TABLE IF NOT EXISTS presence (
    ip TEXT, channel TEXT, email TEXT, user_agent TEXT,
    hostname TEXT, mac TEXT, first_seen TEXT, last_seen TEXT,
    last_epoch REAL, hits INTEGER,
    PRIMARY KEY (ip, channel)
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
"""


class Store:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else db_path()
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------ events
    def add_event(self, e: Event) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (e.id, e.ts, e.session_id, e.server, e.method, e.direction, e.tool,
                 _dump(e.arguments), _dump(e.result), e.risk, e.action),
            )

    def update_event(self, event_id: str, risk: str, action: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE events SET risk=?, action=? WHERE id=?", (risk, action, event_id))

    def list_events(self, limit: int = 200, session_id: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM events", []
        if session_id:
            q += " WHERE session_id=?"
            args.append(session_id)
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        with self._conn() as c:
            return [_event_row(r) for r in c.execute(q, args)]

    # ------------------------------------------------------------ alerts
    def add_alert(self, a: Alert) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (a.id, a.ts, a.session_id, a.event_id, a.server, a.tool, a.rule_id, a.title,
                 a.risk, a.tag, a.reason, a.evidence, a.action, a.task),
            )

    def list_alerts(self, limit: int = 200, session_id: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM alerts", []
        if session_id:
            q += " WHERE session_id=?"
            args.append(session_id)
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        with self._conn() as c:
            return [dict(r) for r in c.execute(q, args)]

    def get_alert(self, alert_id: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            return dict(r) if r else None

    def get_event(self, event_id: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            return _event_row(r) if r else None

    def stats(self) -> dict:
        with self._conn() as c:
            ev = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            al = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            bl = c.execute(
                "SELECT COUNT(*) FROM alerts WHERE action IN ('blocked','redacted','quarantined')"
            ).fetchone()[0]
            sessions = c.execute("SELECT COUNT(DISTINCT session_id) FROM events").fetchone()[0]
        return {"events": ev, "alerts": al, "blocked": bl, "sessions": sessions}

    def metrics(self) -> dict:
        """Aggregates for the dashboard: counts by risk, rule, action, and framework."""
        with self._conn() as c:
            def group(col):
                return {r[0] or "?": r[1] for r in
                        c.execute(f"SELECT {col}, COUNT(*) FROM alerts GROUP BY {col} ORDER BY 2 DESC")}
            by_risk = group("risk")
            by_rule = {r[0]: {"title": r[1], "count": r[2], "tag": r[3]} for r in c.execute(
                "SELECT rule_id, title, COUNT(*), MAX(tag) FROM alerts GROUP BY rule_id, title ORDER BY 3 DESC")}
            by_action = group("action")
            recent = [dict(r) for r in c.execute(
                "SELECT id, ts, risk, rule_id, title, server, tool, action FROM alerts ORDER BY ts DESC LIMIT 12")]
        # MITRE ATLAS technique coverage (parsed from the framework tags).
        import re as _re
        atlas = {}
        owasp = {}
        for rid, info in by_rule.items():
            for m in _re.findall(r"AML\.T\d{4}(?:\.\d{3})?", info["tag"]):
                atlas.setdefault(m, 0)
                atlas[m] += info["count"]
            for m in _re.findall(r"LLM\d{2}:\d{4}", info["tag"]):
                owasp.setdefault(m, 0)
                owasp[m] += info["count"]
        return {
            "by_risk": by_risk, "by_rule": by_rule, "by_action": by_action,
            "mitre_atlas": atlas, "owasp_llm": owasp, "recent": recent,
            "totals": self.stats(),
        }

    def offenses(self) -> list[dict]:
        """QRadar-style offenses: alerts correlated per session into one incident.

        Magnitude (1-10) follows QRadar's idea: driven by the highest-severity
        alert in the session and bumped by the number of distinct rules that fired.
        """
        sev = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT session_id, risk, rule_id, title, tag, server, tool, action, ts "
                "FROM alerts ORDER BY ts ASC")]
        groups: dict[str, dict] = {}
        for a in rows:
            sid = a["session_id"] or "unknown"
            g = groups.setdefault(sid, {
                "session_id": sid, "alerts": 0, "rules": set(), "servers": set(),
                "max_sev": 0, "risk": "info", "first_ts": a["ts"], "last_ts": a["ts"],
                "blocked": 0, "titles": [], "tags": set(),
            })
            g["alerts"] += 1
            g["rules"].add(a["rule_id"])
            g["servers"].add(a["server"])
            g["tags"].add(a["tag"])
            if a["title"] not in g["titles"]:
                g["titles"].append(a["title"])
            if a["action"] in ("blocked", "quarantined", "redacted"):
                g["blocked"] += 1
            s = sev.get(a["risk"], 1)
            if s > g["max_sev"]:
                g["max_sev"] = s
                g["risk"] = a["risk"]
            g["last_ts"] = a["ts"]
        out = []
        for g in groups.values():
            magnitude = min(10, g["max_sev"] + max(0, len(g["rules"]) - 1))
            out.append({
                "session_id": g["session_id"],
                "magnitude": magnitude,
                "risk": g["risk"],
                "alert_count": g["alerts"],
                "blocked": g["blocked"],
                "rules": sorted(g["rules"]),
                "servers": sorted(g["servers"]),
                "tags": sorted(g["tags"]),
                "name": g["titles"][0] if g["titles"] else "AgentSOC offense",
                "description": "; ".join(g["titles"][:4]),
                "first_ts": g["first_ts"], "last_ts": g["last_ts"],
                "status": "open",
            })
        out.sort(key=lambda o: (o["magnitude"], o["alert_count"]), reverse=True)
        return out

    # ------------------------------------------------------------ approvals (rug pull)
    def get_approval(self, server: str, tool: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM approved_tools WHERE server=? AND tool=?", (server, tool)).fetchone()
            return dict(r) if r else None

    def approve(self, server: str, tool: str, h: str, description: str) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO approved_tools VALUES (?,?,?,?,?)",
                (server, tool, h, description, now_iso()),
            )

    # ------------------------------------------------------------ SOAR blocklist
    def block_tool(self, server: str, tool: str, reason: str = "") -> None:
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO blocklist VALUES (?,?,?,?)", (server, tool or "*", reason, now_iso()))

    def unblock_tool(self, server: str, tool: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM blocklist WHERE server=? AND tool=?", (server, tool or "*"))

    def is_blocked(self, server: str, tool: str) -> bool:
        with self._conn() as c:
            r = c.execute(
                "SELECT 1 FROM blocklist WHERE server=? AND (tool=? OR tool='*')", (server, tool)
            ).fetchone()
            return r is not None

    def list_blocklist(self) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM blocklist ORDER BY created_at DESC")]

    # ------------------------------------------------------------ presence (who is connected)
    def touch_presence(self, ip: str, channel: str, email: str | None = None,
                       user_agent: str | None = None) -> None:
        """Record that a client (ip, channel) is active right now."""
        import time
        if not ip:
            return
        now, epoch = now_iso(), time.time()
        with self._conn() as c:
            row = c.execute("SELECT first_seen, hits, email, user_agent FROM presence "
                            "WHERE ip=? AND channel=?", (ip, channel)).fetchone()
            if row:
                c.execute(
                    "UPDATE presence SET last_seen=?, last_epoch=?, hits=hits+1, "
                    "email=COALESCE(?, email), user_agent=COALESCE(?, user_agent) "
                    "WHERE ip=? AND channel=?",
                    (now, epoch, email, user_agent, ip, channel))
            else:
                c.execute(
                    "INSERT INTO presence (ip, channel, email, user_agent, hostname, mac, "
                    "first_seen, last_seen, last_epoch, hits) VALUES (?,?,?,?,?,?,?,?,?,1)",
                    (ip, channel, email, user_agent, None, None, now, now, epoch))

    def presence_raw(self, window_secs: int = 600) -> list[dict]:
        """Clients seen within the window, most recent first."""
        import time
        cutoff = time.time() - window_secs
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM presence WHERE last_epoch>=? ORDER BY last_epoch DESC", (cutoff,))]

    def set_presence_meta(self, ip: str, channel: str, hostname: str | None, mac: str | None) -> None:
        with self._conn() as c:
            c.execute("UPDATE presence SET hostname=?, mac=? WHERE ip=? AND channel=?",
                      (hostname, mac, ip, channel))

    def clear_presence(self) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM presence")

    # ------------------------------------------------------------ maintenance
    def reset(self, approvals: bool = True) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM events")
            c.execute("DELETE FROM alerts")
            if approvals:
                c.execute("DELETE FROM approved_tools")


def _dump(v: Any) -> str | None:
    if v is None:
        return None
    return json.dumps(v, ensure_ascii=False)


def _event_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    for k in ("arguments", "result"):
        if d.get(k):
            try:
                d[k] = json.loads(d[k])
            except ValueError:
                pass
    return d
