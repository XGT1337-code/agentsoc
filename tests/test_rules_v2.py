"""New detection rules (7, 8, 9) and metrics/report: positive + negative cases."""
from __future__ import annotations

from common.config import load_config
from proxy import rules

CFG = load_config()


# ---------------------------------------------- rule 7: path traversal
def test_path_traversal_parent():
    f = rules.check_path_traversal("read_file", {"path": "../../../../etc/passwd"})
    assert f is not None and f.blocking


def test_path_traversal_absolute():
    f = rules.check_path_traversal("read_file", {"path": "/etc/shadow"})
    assert f is not None and f.blocking


def test_path_traversal_windows_absolute():
    f = rules.check_path_traversal("read_file", {"path": "C:\\Windows\\System32\\config\\SAM"})
    assert f is not None and f.blocking


def test_path_traversal_negative():
    assert rules.check_path_traversal("read_file", {"path": "docs/meeting_notes.txt"}) is None


# ---------------------------------------------- rule 8: secret payload (DLP)
def test_secret_payload_positive_internal():
    # even an internal recipient: DLP should flag a secret in the payload
    f = rules.check_secret_payload("send_email",
                                   {"to": "colleague@corp.example",
                                    "body": "-----BEGIN OPENSSH PRIVATE KEY-----"}, CFG)
    assert f is not None and f.risk == "medium"


def test_secret_payload_negative_no_secret():
    assert rules.check_secret_payload("send_email",
                                      {"to": "x@corp.example", "body": "see you at 2pm"}, CFG) is None


def test_secret_payload_negative_non_outbound_tool():
    # read_file is not an outbound tool; reading a secret is rule 2, not rule 8
    assert rules.check_secret_payload("read_file", {"path": "id_rsa"}, CFG) is None


# ---------------------------------------------- rule 9: tool shadowing
def test_tool_shadowing_positive():
    seen = {"read_file": "mail"}
    f = rules.check_tool_shadowing("files-helper", "read_file", seen)
    assert f is not None and f.blocking


def test_tool_shadowing_negative_same_server():
    seen = {"read_file": "mail"}
    assert rules.check_tool_shadowing("mail", "read_file", seen) is None


def test_tool_shadowing_negative_first_time():
    assert rules.check_tool_shadowing("mail", "read_file", {}) is None
