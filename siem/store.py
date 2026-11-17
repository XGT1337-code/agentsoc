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
        return {"events": ev, "alerts": al, "blocked": bl}

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
