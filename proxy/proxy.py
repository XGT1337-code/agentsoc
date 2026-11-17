"""AgentSOC stdio MCP proxy — a man-in-the-middle between an agent and one MCP server.

It is itself a stdio MCP server to the agent, and a stdio client to the real
("downstream") server which it launches as a subprocess. Every JSON-RPC frame
is parsed and passed through the AgentSOC Firewall:

  * tools/list responses  -> poisoned tools quarantined, rug pulls detected,
                             descriptions the agent sees are the filtered ones;
  * tools/call requests   -> sensitive-file / exfiltration / judge rules; a
                             blocking verdict is answered with an MCP error and
                             never reaches the downstream server;
  * tools/call responses  -> prompt injection in the result is redacted/blocked.

Usage (the agent spawns this instead of the real server):
  python -m proxy.proxy --server mail --task "Summarize my emails"
  python -m proxy.proxy --cmd "python -m servers.safe_server" --session S1

See DECISIONS.md D2.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import sys
import threading
from typing import Any

from common.config import load_config
from demo.fixtures import SERVERS
from proxy.firewall import Firewall
from proxy.models import new_id
from proxy.rules import result_to_text
from siem.store import Store


class StdioProxy:
    def __init__(self, server_key: str, cmd: list[str], task: str, session_id: str) -> None:
        self.server_key = server_key
        self.cmd = cmd
        self.fw = Firewall(store=Store(), cfg=load_config(), session_id=session_id, task=task)
        self.pending: dict[Any, str] = {}   # request id -> method (to classify responses)
        self.proc: asyncio.subprocess.Process | None = None

    async def run(self) -> None:
        self.proc = await asyncio.create_subprocess_exec(
            *self.cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr, env=dict(os.environ),
        )
        await asyncio.gather(self._agent_to_server(), self._server_to_agent())

    # ---- agent -> downstream (requests) ---------------------------------
    async def _agent_to_server(self) -> None:
        # stdin can't be IOCP-registered on Windows, so read it on a thread
        # and hand each line to the event loop through a queue.
        loop = asyncio.get_event_loop()
        queue: asyncio.Queue = asyncio.Queue()

        def pump() -> None:
            for raw in iter(sys.stdin.buffer.readline, b""):
                loop.call_soon_threadsafe(queue.put_nowait, raw)
            loop.call_soon_threadsafe(queue.put_nowait, None)

        threading.Thread(target=pump, daemon=True).start()
        while True:
            line = await queue.get()
            if line is None:
                break
            msg = _parse(line)
            if msg is None:
                continue
            method = msg.get("method")
            if method is not None and "id" in msg:
                self.pending[msg["id"]] = method
            if method == "tools/call":
                blocked = self._precheck_call(msg)
                if blocked is not None:
                    self._write_agent(blocked)        # answer the agent, don't forward
                    self.pending.pop(msg["id"], None)
                    continue
            self._write_server(msg)
        if self.proc and self.proc.stdin:
            self.proc.stdin.close()

    def _precheck_call(self, msg: dict) -> dict | None:
        params = msg.get("params") or {}
        tool = params.get("name")
        args = params.get("arguments") or {}
        decision = self.fw.inspect_call(self.server_key, tool, args)
        if not decision.blocked:
            return None
        return {
            "jsonrpc": "2.0", "id": msg.get("id"),
            "result": {
                "isError": True,
                "content": [{"type": "text",
                             "text": f"AgentSOC blocked this call. {decision.reason}"}],
            },
        }

    # ---- downstream -> agent (responses) --------------------------------
    async def _server_to_agent(self) -> None:
        assert self.proc and self.proc.stdout
        while True:
            line = await self.proc.stdout.readline()
            if not line:
                break
            msg = _parse(line)
            if msg is None:
                continue
            rid = msg.get("id")
            method = self.pending.pop(rid, None) if rid is not None else None
            if method == "tools/list" and "result" in msg:
                self._rewrite_tools_list(msg)
            elif method == "tools/call" and "result" in msg:
                self._rewrite_call_result(msg)
            self._write_agent(msg)
        # downstream closed; close our stdout so the agent sees EOF
        try:
            sys.stdout.flush()
        except Exception:
            pass

    def _rewrite_tools_list(self, msg: dict) -> None:
        result = msg.get("result") or {}
        tools = result.get("tools") or []
        norm = [{"name": t.get("name"), "description": t.get("description"),
                 "inputSchema": t.get("inputSchema")} for t in tools]
        kept, _ = self.fw.inspect_tools_list(self.server_key, norm)
        kept_names = {t["name"] for t in kept}
        result["tools"] = [t for t in tools if t.get("name") in kept_names]

    def _rewrite_call_result(self, msg: dict) -> None:
        result = msg.get("result") or {}
        text = result_to_text(result)
        if not text:
            return
        safe, alerts = self.fw.inspect_result(self.server_key, "", text)
        if alerts:
            result["content"] = [{"type": "text", "text": safe}]
            result.pop("structuredContent", None)

    # ---- raw writers ----------------------------------------------------
    def _write_server(self, msg: dict) -> None:
        if self.proc and self.proc.stdin:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))

    def _write_agent(self, msg: dict) -> None:
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()


def _parse(line: bytes) -> dict | None:
    s = line.decode("utf-8", "replace").strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except ValueError:
        return None


def main() -> None:
    ap = argparse.ArgumentParser(description="AgentSOC stdio MCP proxy")
    ap.add_argument("--server", help="server key from demo.fixtures.SERVERS (e.g. mail, weather)")
    ap.add_argument("--cmd", help="explicit command to launch the downstream server")
    ap.add_argument("--task", default="", help="the user task, for the LLM judge")
    ap.add_argument("--session", default="", help="session id (default: generated)")
    args = ap.parse_args()

    if args.cmd:
        cmd = shlex.split(args.cmd)
        server_key = args.server or "downstream"
    elif args.server and args.server in SERVERS:
        cmd = [sys.executable, *SERVERS[args.server]]
        server_key = args.server
    else:
        print("give --server <key> or --cmd '<command>'", file=sys.stderr)
        sys.exit(2)

    session_id = args.session or ("proxy-" + new_id())
    proxy = StdioProxy(server_key, cmd, args.task, session_id)
    asyncio.run(proxy.run())


if __name__ == "__main__":
    main()
