"""SSH access gateway for AgentSOC.

You reach the web console ONLY through this SSH gateway. Connecting:

    ssh soc@<ip> -p 2222        # password: from config (default "agentsoc")

On success the gateway mints a one-time web token and prints the URL to open.
The web app rejects any request without a valid, unused, non-expired token, so
knowing the port alone is not enough. After opening the URL you still must enter
the admin email and the OTP.

Run it:  python -m gateway.ssh_gateway   (needs asyncssh)
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import asyncssh

from common.config import db_path, load_config
from gateway import auth


def _otp_file() -> Path:
    return db_path().parent / "otp.txt"


def _host_key():
    """Load a stable SSH host key from disk, creating it once if missing."""
    p = db_path().parent / "ssh_host_key"
    if p.exists():
        try:
            return asyncssh.read_private_key(str(p))
        except Exception:
            pass
    key = asyncssh.generate_private_key("ssh-ed25519")
    try:
        p.write_bytes(key.export_private_key())
    except Exception:
        pass
    return key


def _open_browser_async(url: str) -> None:
    """Open the default browser on THIS host without blocking the event loop."""
    import threading
    import webbrowser

    def _go():
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=_go, daemon=True).start()


def _read_otp_code() -> str | None:
    """Parse the current OTP code from the local delivery file, if any."""
    try:
        text = _otp_file().read_text(encoding="utf-8").strip()
    except Exception:
        return None
    # Format: "AgentSOC OTP for <email>: <code>"
    return text.rsplit(":", 1)[-1].strip() if ":" in text else None


class GatewayServer(asyncssh.SSHServer):
    def __init__(self, password: str) -> None:
        self._password = password

    def connection_made(self, conn):
        self._conn = conn

    def begin_auth(self, username):
        return True  # require a password

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return password == self._password


async def _handle(process):
    cfg = load_config()
    base = cfg.get("api", {}).get("base_url", "http://127.0.0.1:8000")
    token = auth.mint_gate()
    url = f"{base}/?gate={token}"
    acfg = cfg.get("auth", {})

    # Record this SSH client as "connected" and, if it is on this same machine,
    # open the browser for it automatically (no copy-paste needed locally).
    peer_ip = ""
    try:
        peer = process.get_extra_info("peername")
        peer_ip = peer[0] if peer else ""
    except Exception:
        pass
    try:
        from siem.store import Store
        Store().touch_presence(peer_ip or "127.0.0.1", "ssh", None, "asyncssh gateway")
    except Exception:
        pass
    if peer_ip in ("127.0.0.1", "::1", ""):
        _open_browser_async(url)
    ttl = acfg.get("gate_ttl", 120)
    watch_secs = int(ttl) + int(acfg.get("otp_ttl", 300)) + 60
    process.stdout.write(
        "\r\n== AgentSOC ==============================================\r\n"
        " Access granted. Your browser should open automatically.\r\n"
        " If it does not, open this one-time URL manually:\r\n\r\n"
        f"   {url}\r\n\r\n"
        f" The link is valid once, for {ttl}s. On the page enter the admin\r\n"
        " email and request the one-time code. If the code is delivered\r\n"
        " locally (no SMTP), it will appear HERE in this SSH window.\r\n"
        " Keep this session open; press Ctrl+C to disconnect.\r\n"
        "==========================================================\r\n")

    # Live-watch the local OTP file and print any new code into this SSH
    # session, so a user connecting from another machine never needs to read
    # a file on the host. Only ever shows the admin's own code.
    try:
        baseline_mtime = _otp_file().stat().st_mtime
    except Exception:
        baseline_mtime = 0.0
    last_shown = None
    waited = 0.0
    try:
        while waited < watch_secs:
            await asyncio.sleep(1.0)
            waited += 1.0
            try:
                mtime = _otp_file().stat().st_mtime
            except Exception:
                continue
            if mtime <= baseline_mtime:
                continue
            code = _read_otp_code()
            if code and code != last_shown:
                last_shown = code
                process.stdout.write(
                    "\r\n---------------------------------------------------------\r\n"
                    f"  Your AgentSOC one-time code: {code}\r\n"
                    "  Enter it on the sign-in page to reach the console.\r\n"
                    "---------------------------------------------------------\r\n")
    except asyncio.CancelledError:  # client disconnected
        pass
    process.exit(0)


async def start() -> None:
    cfg = load_config().get("auth", {})
    port = int(cfg.get("ssh_port", 2222))
    host = cfg.get("ssh_host", "127.0.0.1")
    password = cfg.get("ssh_password", "agentsoc")
    # Persistent host key so the client's known_hosts stays valid across restarts
    # (an ephemeral key would trip "HOST KEY CHANGED" on every restart).
    host_key = _host_key()
    await asyncssh.create_server(
        lambda: GatewayServer(password), host, port,
        server_host_keys=[host_key], process_factory=_handle,
    )
    print(f"AgentSOC SSH gateway on {host}:{port} "
          f"(user '{cfg.get('ssh_user','soc')}', password from config). Ctrl+C to stop.")
    await asyncio.Event().wait()


def main() -> None:
    try:
        asyncio.run(start())
    except (KeyboardInterrupt, OSError) as exc:
        print(f"gateway stopped: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
