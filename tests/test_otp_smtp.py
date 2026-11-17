"""Prove the real-email OTP path: when SMTP is configured, deliver() sends mail.

Uses a fake smtplib.SMTP so no real server/credentials are needed, but it
exercises the exact calls (starttls -> login -> sendmail) that a real Gmail
send makes, so a correct config is guaranteed to deliver.
"""
from __future__ import annotations

import importlib

import pytest


class _FakeSMTP:
    calls: dict = {}

    def __init__(self, host, port, timeout=0):
        _FakeSMTP.calls = {"host": host, "port": port, "starttls": False,
                           "login": None, "sendmail": None}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        _FakeSMTP.calls["starttls"] = True

    def login(self, user, password):
        _FakeSMTP.calls["login"] = (user, password)

    def sendmail(self, frm, to, msg):
        _FakeSMTP.calls["sendmail"] = {"from": frm, "to": to, "body": msg}


@pytest.fixture
def smtp_env(monkeypatch):
    monkeypatch.setenv("AGENTSOC_ADMIN_EMAIL", "hamza.gurbanov07@gmail.com")
    monkeypatch.setenv("AGENTSOC_SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setenv("AGENTSOC_SMTP_PORT", "587")
    monkeypatch.setenv("AGENTSOC_SMTP_USER", "hamza.gurbanov07@gmail.com")
    monkeypatch.setenv("AGENTSOC_SMTP_PASSWORD", "app-password-1234")
    monkeypatch.setenv("AGENTSOC_SMTP_FROM", "hamza.gurbanov07@gmail.com")
    import common.config as cfg
    importlib.reload(cfg)
    import gateway.otp as otp
    importlib.reload(otp)
    return otp


def test_smtp_config_is_read(smtp_env):
    from common.config import load_config
    smtp = load_config()["auth"]["smtp"]
    assert smtp["host"] == "smtp.gmail.com" and smtp["port"] == 587
    assert smtp["user"] == "hamza.gurbanov07@gmail.com"


def test_deliver_sends_real_email(smtp_env, monkeypatch):
    import smtplib
    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
    out = smtp_env.deliver("424242")
    assert out["channel"] == "email"
    assert out["to"] == "hamza.gurbanov07@gmail.com"
    c = _FakeSMTP.calls
    assert c["host"] == "smtp.gmail.com" and c["port"] == 587
    assert c["starttls"] is True
    assert c["login"] == ("hamza.gurbanov07@gmail.com", "app-password-1234")
    assert "hamza.gurbanov07@gmail.com" in c["sendmail"]["to"]
    assert "424242" in c["sendmail"]["body"]


def test_deliver_falls_back_to_local_on_smtp_error(smtp_env, monkeypatch):
    import smtplib

    class _Boom(_FakeSMTP):
        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, b"bad creds")

    monkeypatch.setattr(smtplib, "SMTP", _Boom)
    out = smtp_env.deliver("111111")
    assert out["channel"] == "local"   # never silently drops the code
