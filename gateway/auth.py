"""Access control: SSH gate token -> admin email -> OTP -> logged-in session.

Flow (see README):
  1. The SSH gateway authenticates the operator and calls mint_gate() -> a
     one-time web token. Knowing the port/URL is NOT enough; without a valid
     gate token the web app stays locked.
  2. The browser opens /?gate=<token>; consume_gate() trades it for a short
     "gated" cookie and shows the email page.
  3. The operator enters the admin email (only ADMIN_EMAIL is accepted);
     request_otp() creates a 6-digit code delivered by gateway.otp.
  4. verify_otp() checks the code and creates a logged-in session.

All state lives in the same SQLite DB as events/alerts, in separate tables.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import time
from contextlib import contextmanager

from common.config import db_path, load_config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS auth_gate (token TEXT PRIMARY KEY, created REAL, used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS auth_otp (email TEXT PRIMARY KEY, code_hash TEXT, created REAL, attempts INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS auth_session (sid TEXT PRIMARY KEY, email TEXT, created REAL);
CREATE TABLE IF NOT EXISTS auth_gatepass (sid TEXT PRIMARY KEY, created REAL);
"""


def _cfg() -> dict:
    return load_config().get("auth", {})


def auth_enabled() -> bool:
    return bool(_cfg().get("enabled", True))


def admin_email() -> str:
    return str(_cfg().get("admin_email", "")).strip().lower()


def is_admin(email: str) -> bool:
    return (email or "").strip().lower() == admin_email()


@contextmanager
def _conn():
    c = sqlite3.connect(db_path(), timeout=15)
    try:
        c.executescript(_SCHEMA)
        yield c
        c.commit()
    finally:
        c.close()


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


# ---------------------------------------------------------------- gate (SSH)
def mint_gate() -> str:
    """Create a one-time web token (called by the SSH gateway after auth)."""
    token = secrets.token_urlsafe(24)
    with _conn() as c:
        c.execute("INSERT INTO auth_gate (token, created, used) VALUES (?,?,0)", (token, time.time()))
    return token


def consume_gate(token: str) -> bool:
    """Spend a gate token once, within its TTL. Returns True if it was valid."""
    if not token:
        return False
    ttl = _cfg().get("gate_ttl", 120)
    with _conn() as c:
        row = c.execute("SELECT created, used FROM auth_gate WHERE token=?", (token,)).fetchone()
        if not row or row[1] or (time.time() - row[0]) > ttl:
            return False
        c.execute("UPDATE auth_gate SET used=1 WHERE token=?", (token,))
    return True


def new_gatepass() -> str:
    """A short-lived cookie proving the browser came through the SSH gate."""
    sid = secrets.token_urlsafe(18)
    with _conn() as c:
        c.execute("INSERT INTO auth_gatepass (sid, created) VALUES (?,?)", (sid, time.time()))
    return sid


def gatepass_valid(sid: str) -> bool:
    if not sid:
        return False
    ttl = _cfg().get("otp_ttl", 300) + 600
    with _conn() as c:
        row = c.execute("SELECT created FROM auth_gatepass WHERE sid=?", (sid,)).fetchone()
    return bool(row) and (time.time() - row[0]) < ttl


# ---------------------------------------------------------------- OTP
def request_otp(email: str) -> str | None:
    """Create a 6-digit OTP for the admin email. Returns the code (to deliver), or None."""
    if not is_admin(email):
        return None
    code = f"{secrets.randbelow(1000000):06d}"
    with _conn() as c:
        c.execute("INSERT OR REPLACE INTO auth_otp (email, code_hash, created, attempts) VALUES (?,?,?,0)",
                  (admin_email(), _hash(code), time.time()))
    return code


def verify_otp(email: str, code: str) -> str | None:
    """Check an OTP; on success create and return a logged-in session id."""
    if not is_admin(email):
        return None
    ttl = _cfg().get("otp_ttl", 300)
    with _conn() as c:
        row = c.execute("SELECT code_hash, created, attempts FROM auth_otp WHERE email=?",
                        (admin_email(),)).fetchone()
        if not row:
            return None
        code_hash, created, attempts = row
        if attempts >= 5 or (time.time() - created) > ttl:
            c.execute("DELETE FROM auth_otp WHERE email=?", (admin_email(),))
            return None
        if not hmac.compare_digest(code_hash, _hash((code or "").strip())):
            c.execute("UPDATE auth_otp SET attempts=attempts+1 WHERE email=?", (admin_email(),))
            return None
        c.execute("DELETE FROM auth_otp WHERE email=?", (admin_email(),))
        sid = secrets.token_urlsafe(24)
        c.execute("INSERT INTO auth_session (sid, email, created) VALUES (?,?,?)",
                  (sid, admin_email(), time.time()))
    return sid


# ---------------------------------------------------------------- session
def session_email(sid: str) -> str | None:
    if not sid:
        return None
    ttl = _cfg().get("session_ttl", 28800)
    with _conn() as c:
        row = c.execute("SELECT email, created FROM auth_session WHERE sid=?", (sid,)).fetchone()
    if not row or (time.time() - row[1]) > ttl:
        return None
    return row[0]


def logout(sid: str) -> None:
    with _conn() as c:
        c.execute("DELETE FROM auth_session WHERE sid=?", (sid,))
