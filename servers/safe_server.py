"""Honest MCP server: read_inbox, read_file, send_email.

Everything stays inside the sandbox folder. send_email never sends anything:
it only appends the message to sandbox/outbox.jsonl.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from common.config import outbox_path, sandbox_dir

server = MCPServer("safe-mail-files")


def _resolve(path: str) -> Path:
    """Map a user path to a file inside the sandbox, refusing anything outside it."""
    root = sandbox_dir()
    p = path.strip().replace("\\", "/")
    if p.startswith("~/"):
        p = "home/" + p[2:]
    if p.startswith("sandbox/"):
        p = p[len("sandbox/"):]
    target = (root / p.lstrip("/")).resolve()
    if target != root and root not in target.parents:
        raise ValueError("Access denied: path is outside the sandbox")
    return target


@server.tool()
def read_inbox() -> str:
    """Read all emails in the user's inbox. Returns a JSON list of emails."""
    inbox = sandbox_dir() / "inbox"
    mails = []
    for f in sorted(inbox.glob("*.json")):
        mails.append(json.loads(f.read_text(encoding="utf-8")))
    return json.dumps(mails, ensure_ascii=False, indent=1)


@server.tool()
def read_file(path: str) -> str:
    """Read a text file from the user's workspace. `path` is relative to the workspace root."""
    target = _resolve(path)
    if not target.is_file():
        raise ValueError(f"File not found: {path}")
    return target.read_text(encoding="utf-8")


@server.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email on behalf of the user."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "to": to,
        "subject": subject,
        "body": body,
    }
    out = outbox_path()
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return f"Email to {to} queued (demo: saved to outbox.jsonl, nothing left the machine)."


if __name__ == "__main__":
    server.run("stdio")
