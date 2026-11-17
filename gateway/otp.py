"""Deliver the OTP to the admin.

Default (no SMTP configured): write the code to data/otp.txt and return a
message so the SSH gateway / server console can show it. This keeps the
project's "nothing leaves the machine" default.

If SMTP is configured (via AGENTSOC_SMTP_* env vars), the code is emailed to
the admin for real. Credentials are read from the environment only — never
stored in code or logs.
"""
from __future__ import annotations

from pathlib import Path

from common.config import db_path, load_config


def _otp_file() -> Path:
    return db_path().parent / "otp.txt"


def deliver(code: str) -> dict:
    cfg = load_config().get("auth", {})
    email = cfg.get("admin_email", "")
    smtp = cfg.get("smtp", {})
    # Always keep a local copy for the demo / fallback.
    try:
        _otp_file().write_text(f"AgentSOC OTP for {email}: {code}\n", encoding="utf-8")
    except Exception:
        pass

    if smtp.get("host") and smtp.get("user") and smtp.get("password"):
        try:
            _send_smtp(smtp, email, code)
            return {"channel": "email", "to": email, "detail": f"OTP emailed to {email}."}
        except Exception as exc:  # fall back to local on any SMTP error
            return {"channel": "local", "to": email,
                    "detail": f"SMTP failed ({exc}); OTP saved to {_otp_file()}."}
    return {"channel": "local", "to": email,
            "detail": f"No SMTP configured; OTP saved to {_otp_file()} and shown in the gateway terminal."}


def _send_smtp(smtp: dict, to: str, code: str) -> None:
    import smtplib
    from email.mime.text import MIMEText

    msg = MIMEText(f"Your AgentSOC one-time code is: {code}\n\nIt expires shortly. "
                   f"If you did not request this, ignore this message.")
    msg["Subject"] = "AgentSOC one-time code"
    msg["From"] = smtp.get("from") or smtp["user"]
    msg["To"] = to
    with smtplib.SMTP(smtp["host"], int(smtp.get("port", 587)), timeout=15) as s:
        s.starttls()
        s.login(smtp["user"], smtp["password"])
        s.sendmail(msg["From"], [to], msg.as_string())
