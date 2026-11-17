"""AgentSOC client connector — run this from YOUR computer instead of raw ssh.

It opens an SSH session to the AgentSOC gateway, then on YOUR machine it:
  1. opens the one-time gate URL in your default browser automatically, and
  2. prints the OTP code here as soon as you request it on the page.

So from another computer you never copy a link or read a file on the server.

Usage:
    python -m gateway.connect <host> [--port 2222] [--user soc] [--password agentsoc]

Needs asyncssh on the client:  pip install asyncssh
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import re
import sys
import webbrowser

import asyncssh


async def run(host: str, port: int, user: str, password: str) -> None:
    print(f"[AgentSOC] connecting to {host}:{port} ...")
    async with asyncssh.connect(host, port=port, username=user, password=password,
                                known_hosts=None) as conn:
        proc = await conn.create_process(term_type="xterm")
        banner = ""
        while not re.search(r"https?://\S*gate=\S+", banner):
            chunk = await asyncio.wait_for(proc.stdout.read(256), timeout=15)
            if not chunk:
                break
            banner += chunk
        m = re.search(r"(https?://\S*gate=\S+)", banner)
        if not m:
            print("[AgentSOC] gateway did not return a URL:\n" + banner)
            return
        url = m.group(1).strip()
        print(f"[AgentSOC] opening your browser:\n   {url}")
        try:
            webbrowser.open(url)
        except Exception:
            print("[AgentSOC] could not auto-open the browser; open the URL above manually.")

        print("[AgentSOC] On the page enter the admin email and request the one-time code.")
        print("[AgentSOC] The code will appear right here:\n")
        # Relay everything the gateway streams (the OTP line shows up here).
        try:
            while True:
                chunk = await proc.stdout.read(512)
                if not chunk:
                    break
                sys.stdout.write(chunk)
                sys.stdout.flush()
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass


def main() -> None:
    p = argparse.ArgumentParser(description="AgentSOC gateway connector")
    p.add_argument("host", nargs="?", default="127.0.0.1", help="gateway host/IP")
    p.add_argument("--port", type=int, default=2222)
    p.add_argument("--user", default="soc")
    p.add_argument("--password", default=None, help="SSH password (prompted if omitted)")
    a = p.parse_args()
    password = a.password or getpass.getpass(f"Password for {a.user}@{a.host}: ")
    try:
        asyncio.run(run(a.host, a.port, a.user, password))
    except (KeyboardInterrupt, OSError, asyncssh.Error) as exc:
        print(f"[AgentSOC] disconnected: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
