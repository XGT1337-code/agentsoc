"""Small synchronous helper to talk to a stdio MCP server.

Wraps the async mcp ClientSession in a blocking API so the rest of the code
(replay, agent, proxy bridge) stays simple. One live connection per `with`
block; state (e.g. a changing tool list for the rug-pull demo) is preserved
across calls on the same connection.
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


class MCPConnection:
    def __init__(self, args: list[str], cwd: str | None = None, env: dict | None = None,
                 command: str | None = None) -> None:
        self._params = StdioServerParameters(
            command=command or sys.executable,
            args=args,
            cwd=cwd or os.getcwd(),
            env={**os.environ, **(env or {})},
        )
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._session: ClientSession | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None
        self._closer: asyncio.Event | None = None

    # -- lifecycle ---------------------------------------------------------
    async def _serve(self) -> None:
        self._closer = asyncio.Event()
        try:
            async with stdio_client(self._params) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    self._session = session
                    self._ready.set()
                    await self._closer.wait()
        except BaseException as exc:  # startup failure: report it to __enter__
            self._error = exc
            self._ready.set()

    def __enter__(self) -> "MCPConnection":
        self._thread.start()
        asyncio.run_coroutine_threadsafe(self._serve(), self._loop)
        if not self._ready.wait(timeout=30):
            raise RuntimeError("MCP server did not initialize in time")
        if self._error is not None:
            raise RuntimeError(f"MCP server failed to start: {self._error!r}")
        return self

    def __exit__(self, *exc) -> None:
        if self._closer is not None:
            self._loop.call_soon_threadsafe(self._closer.set)
        # give _serve a moment to unwind the subprocess, then stop the loop
        self._loop.call_soon_threadsafe(lambda: self._loop.call_later(0.2, self._loop.stop))
        self._thread.join(timeout=10)

    # -- operations --------------------------------------------------------
    def _run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=60)

    def list_tools(self) -> list[dict]:
        res = self._run(self._session.list_tools())
        return [_tool_to_dict(t) for t in res.tools]

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        res = self._run(self._session.call_tool(name, arguments or {}))
        return _result_to_dict(res)


def _tool_to_dict(t: Any) -> dict:
    return {
        "name": t.name,
        "description": t.description or "",
        "inputSchema": getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {},
    }


def _result_to_dict(res: Any) -> dict:
    content = []
    for c in res.content:
        if getattr(c, "type", None) == "text":
            content.append({"type": "text", "text": c.text})
        else:
            content.append({"type": getattr(c, "type", "unknown")})
    return {
        "isError": bool(getattr(res, "is_error", False)),
        "content": content,
        "structuredContent": getattr(res, "structured_content", None),
    }
