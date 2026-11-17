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

import asyncssh

from common.config import load_config
from gateway import auth


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
    base = load_config().get("api", {}).get("base_url", "http://127.0.0.1:8000")
    token = auth.mint_gate()
    url = f"{base}/?gate={token}"
    ttl = load_config().get("auth", {}).get("gate_ttl", 120)
    process.stdout.write(
        "\r\n== AgentSOC ==============================================\r\n"
        " Access granted. Open this one-time URL in your browser:\r\n\r\n"
        f"   {url}\r\n\r\n"
        f" The link is valid once, for {ttl}s. On the page, enter the admin\r\n"
        " email, then the OTP that is delivered to it.\r\n"
        "==========================================================\r\n")
    process.exit(0)


async def start() -> None:
    cfg = load_config().get("auth", {})
    port = int(cfg.get("ssh_port", 2222))
    password = cfg.get("ssh_password", "agentsoc")
    # Ephemeral host key so the demo needs no key files on disk.
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    await asyncssh.create_server(
        lambda: GatewayServer(password), "127.0.0.1", port,
        server_host_keys=[host_key], process_factory=_handle,
    )
    print(f"AgentSOC SSH gateway on 127.0.0.1:{port} "
          f"(user '{cfg.get('ssh_user','soc')}', password from config). Ctrl+C to stop.")
    await asyncio.Event().wait()


def main() -> None:
    try:
        asyncio.run(start())
    except (KeyboardInterrupt, OSError) as exc:
        print(f"gateway stopped: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
