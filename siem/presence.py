"""Who is connected to AgentSOC right now.

Builds a live list of clients touching the service (web dashboard + SSH gateway)
and enriches each with best-effort network identity:
  - hostname  : reverse-DNS / NetBIOS name of the machine
  - mac       : hardware address from the host ARP table (same LAN segment only)
  - device    : OS + browser parsed from the User-Agent

MAC and hostname are only knowable for hosts on the same local network; across
a router they come back blank, which is expected and shown as such.
"""
from __future__ import annotations

import re
import socket
import subprocess
import sys
from functools import lru_cache

# Addresses that are this machine itself.
_LOCAL = {"127.0.0.1", "::1", "localhost", ""}


@lru_cache(maxsize=256)
def resolve_hostname(ip: str) -> str | None:
    """Reverse-DNS the IP to a machine name. Cached; fails quietly."""
    if ip in _LOCAL:
        return socket.gethostname()
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(1.0)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old)


@lru_cache(maxsize=256)
def resolve_mac(ip: str) -> str | None:
    """Read the MAC for an IP from the OS ARP table (same subnet only)."""
    if ip in _LOCAL:
        return _own_mac()
    try:
        # `arp -a <ip>` works on Windows, macOS and Linux (iproute boxes may differ).
        out = subprocess.run(["arp", "-a", ip], capture_output=True, text=True,
                             timeout=3).stdout
    except Exception:
        return None
    # Accept 00-11-22-33-44-55 or 00:11:22:33:44:55.
    m = re.search(r"([0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5})", out)
    return m.group(1).lower().replace("-", ":") if m else None


def _own_mac() -> str | None:
    import uuid
    n = uuid.getnode()
    if (n >> 40) & 0x01:  # multicast bit set => getnode() guessed, unreliable
        return None
    return ":".join(f"{(n >> e) & 0xff:02x}" for e in range(40, -1, -8))


def device_from_ua(ua: str | None) -> str:
    """Human label for the device/browser from a User-Agent string."""
    if not ua:
        return "—"
    u = ua.lower()
    if "asyncssh" in u or "openssh" in u or "ssh" in u:
        return "SSH client"
    os_name = ("Windows" if "windows" in u else "macOS" if ("mac os" in u or "macintosh" in u)
               else "Android" if "android" in u else "iOS" if ("iphone" in u or "ipad" in u)
               else "Linux" if "linux" in u else "Unknown OS")
    browser = ("Edge" if "edg" in u else "Chrome" if "chrome" in u else "Firefox" if "firefox" in u
               else "Safari" if "safari" in u else "curl" if "curl" in u else "client")
    return f"{os_name} · {browser}"


def list_connected(store, window_secs: int = 600) -> list[dict]:
    """Active clients, enriched with hostname/MAC/device. Caches enrichment back
    into the store so ARP/DNS run at most once per client."""
    rows = store.presence_raw(window_secs)
    out = []
    for r in rows:
        ip = r["ip"]
        hostname, mac = r.get("hostname"), r.get("mac")
        if hostname is None and mac is None:
            hostname = resolve_hostname(ip)
            mac = resolve_mac(ip)
            try:
                store.set_presence_meta(ip, r["channel"], hostname, mac)
            except Exception:
                pass
        out.append({
            "ip": ip,
            "channel": r["channel"],
            "email": r.get("email") or None,
            "hostname": hostname or "—",
            "mac": mac or "—",
            "device": device_from_ua(r.get("user_agent")),
            "user_agent": r.get("user_agent") or "",
            "first_seen": r.get("first_seen"),
            "last_seen": r.get("last_seen"),
            "hits": r.get("hits") or 0,
        })
    return out
