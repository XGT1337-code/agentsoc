"""Tiny LEEF/syslog collector — stands in for QRadar while you demo locally.

Run it to watch AgentSOC events arrive as LEEF 2.0 over UDP, exactly the way a
QRadar log source would ingest them:

    python -m siem.collector            # listen on 127.0.0.1:5514

Then enable shipping (config.yaml syslog.enabled: true, port 5514) or call
ship_session()/the /siem/ship API, and the lines show up here.

Also exposes ship_session() used by the API and tests.
"""
from __future__ import annotations

import socket
import sys

from common.config import load_config
from siem import leef
from siem.store import Store


def ship_session(store: Store, session_id: str, host: str, port: int) -> int:
    """Send every event + alert of a session as LEEF 2.0 over UDP. Returns lines sent."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    n = 0
    try:
        for e in reversed(store.list_events(limit=500, session_id=session_id)):
            sock.sendto(f"<134>{leef.event_to_leef(e)}".encode("utf-8"), (host, int(port)))
            n += 1
        for a in reversed(store.list_alerts(limit=500, session_id=session_id)):
            sock.sendto(f"<134>{leef.alert_to_leef(a)}".encode("utf-8"), (host, int(port)))
            n += 1
    finally:
        sock.close()
    return n


def listen(host: str = "127.0.0.1", port: int = 5514) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"AgentSOC LEEF collector (mock QRadar) listening on {host}:{port}\n"
          f"Waiting for LEEF 2.0 events... (Ctrl+C to stop)\n")
    try:
        while True:
            data, addr = sock.recvfrom(65535)
            line = data.decode("utf-8", "replace").lstrip("<0123456789>")
            kind = "ALERT" if "MCP_ALERT" in line else "EVENT"
            print(f"[{kind}] {line}")
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        sock.close()


if __name__ == "__main__":
    cfg = load_config().get("syslog", {})
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(cfg.get("port", 5514))
    listen(cfg.get("host", "127.0.0.1"), port)
