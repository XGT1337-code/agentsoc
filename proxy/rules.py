"""Deterministic detection rules for MCP traffic.

Each rule is a pure function that returns a Finding (or None). The proxy
decides what to do with the finding: findings with risk "high" or above
block the message.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .models import Finding

TAGS = {
    "R1_TOOL_POISONING": "OWASP LLM01:2025 Prompt Injection | MITRE ATLAS AML.T0051.001 Indirect Prompt Injection",
    "R2_SENSITIVE_FILE": "OWASP LLM02:2025 Sensitive Information Disclosure | MITRE ATLAS AML.T0057 LLM Data Leakage",
    "R3_EXFILTRATION": "OWASP LLM02:2025 Sensitive Information Disclosure | MITRE ATLAS AML.T0025 Exfiltration via Cyber Means",
    "R4_RUG_PULL": "OWASP LLM03:2025 Supply Chain | MITRE ATLAS AML.T0010 AI Supply Chain Compromise",
    "R5_DATA_INJECTION": "OWASP LLM01:2025 Prompt Injection | MITRE ATLAS AML.T0051.001 Indirect Prompt Injection",
    "R6_TASK_MISMATCH": "OWASP LLM06:2025 Excessive Agency",
    "R7_PATH_TRAVERSAL": "OWASP LLM02:2025 Sensitive Information Disclosure | MITRE ATLAS AML.T0057 LLM Data Leakage",
    "R8_SECRET_PAYLOAD": "OWASP LLM02:2025 Sensitive Information Disclosure | MITRE ATLAS AML.T0024 Exfiltration",
    "R9_TOOL_SHADOWING": "OWASP LLM03:2025 Supply Chain | MITRE ATLAS AML.T0010 AI Supply Chain Compromise",
    "R0_SOAR_BLOCKLIST": "SOAR response action",
}

TITLES = {
    "R1_TOOL_POISONING": "Tool poisoning in tool description",
    "R2_SENSITIVE_FILE": "Access to a sensitive file",
    "R3_EXFILTRATION": "Data sent to an external domain",
    "R4_RUG_PULL": "Tool description changed after approval (rug pull)",
    "R5_DATA_INJECTION": "Prompt injection inside tool data",
    "R6_TASK_MISMATCH": "Tool call does not match the user task",
    "R7_PATH_TRAVERSAL": "Path traversal outside the workspace",
    "R8_SECRET_PAYLOAD": "Secret material in an outbound tool argument",
    "R9_TOOL_SHADOWING": "Tool name shadowed by another server",
    "R0_SOAR_BLOCKLIST": "Tool blocked by SOAR playbook",
}

EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", re.I)

# Phrases that are instructions to the model, not documentation of the tool.
_INSTRUCTION_PATTERNS = [
    (r"ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier) instructions", "asks to ignore previous instructions"),
    (r"\b(?:you must|must first|mandatory|before (?:you )?(?:answer|respond|reply|using))\b", "gives orders to the agent"),
    (r"\bread (?:the )?(?:file|contents of)\b", "tells the agent to read a file"),
    (r"\bsend (?:its|the|all|full|this)?\s*(?:full )?(?:contents?|data|it|file|key)\b", "tells the agent to send data"),
    (r"\b(?:do not|don't|never) (?:tell|mention|inform|show)\b.{0,30}\buser\b", "asks to hide actions from the user"),
    (r"(?:do this )?silently\b", "asks to act silently"),
    (r"</?important>", "uses hidden <IMPORTANT> markup"),
    (r"(?:instructions? for (?:the )?(?:ai|assistant|agent|llm)|(?:ai|llm) assistant:)", "addresses the AI directly"),
    (r"\bsystem prompt\b", "mentions the system prompt"),
    # Azerbaijani variant for the local demo audience.
    (r"(?:oxu|göndər|əvvəlki təlimatları)", "instruction in Azerbaijani"),
]
_INSTRUCTION_RES = [(re.compile(p, re.I), why) for p, why in _INSTRUCTION_PATTERNS]


def _sensitive_hits(text: str, cfg: dict) -> list[str]:
    low = text.lower()
    return [s for s in cfg.get("sensitive_paths", []) if s.lower() in low]


def _external_emails(text: str, cfg: dict) -> list[str]:
    allowed = {d.lower() for d in cfg.get("email", {}).get("allowed_domains", [])}
    out = []
    for m in EMAIL_RE.finditer(text):
        domain = m.group(1).lower()
        if not any(domain == a or domain.endswith("." + a) for a in allowed):
            out.append(m.group(0))
    return out


def instruction_indicators(text: str) -> list[str]:
    return [why for rx, why in _INSTRUCTION_RES if rx.search(text)]


def _finding(rule_id: str, risk: str, reason: str, evidence: str = "") -> Finding:
    return Finding(rule_id, TITLES[rule_id], risk, TAGS[rule_id], reason, evidence[:2000])


# ---------------------------------------------------------------- rule 1
def check_tool_poisoning(tool: dict, cfg: dict) -> Finding | None:
    """Rule 1: the tool description contains commands for the model."""
    desc = tool.get("description") or ""
    reasons = instruction_indicators(desc)
    secrets = _sensitive_hits(desc, cfg)
    emails = _external_emails(desc, cfg)
    if secrets:
        reasons.append("mentions secret paths: " + ", ".join(secrets))
    if emails:
        reasons.append("contains external email address: " + ", ".join(emails))
    if not reasons:
        return None
    score = len(reasons) + (2 if secrets else 0) + (2 if emails else 0)
    risk = "critical" if (secrets and emails) else "high" if score >= 3 else "medium"
    return _finding(
        "R1_TOOL_POISONING",
        risk,
        f"Description of tool '{tool.get('name')}' contains hidden instructions: " + "; ".join(reasons),
        desc,
    )


# ---------------------------------------------------------------- rule 2
def _path_args(args: dict) -> list[str]:
    keys = ("path", "file", "filename", "filepath", "file_path")
    return [str(v) for k, v in (args or {}).items() if k.lower() in keys and v]


def check_sensitive_file(tool_name: str, args: dict, cfg: dict) -> Finding | None:
    """Rule 2: a tool tries to read a secret path (.ssh, .env, id_rsa, credentials...)."""
    for p in _path_args(args):
        hits = _sensitive_hits(p, cfg)
        if hits:
            return _finding(
                "R2_SENSITIVE_FILE",
                "high",
                f"Tool '{tool_name}' requested secret path '{p}' (matches: {', '.join(hits)})",
                json.dumps(args, ensure_ascii=False),
            )
    return None


# ---------------------------------------------------------------- rule 3
def check_exfiltration(tool_name: str, args: dict, cfg: dict) -> Finding | None:
    """Rule 3: email to a domain that is not on the allow list."""
    recipients = []
    for k in ("to", "cc", "bcc", "recipient", "recipients"):
        v = (args or {}).get(k)
        if isinstance(v, list):
            recipients += [str(x) for x in v]
        elif v:
            recipients.append(str(v))
    external = [e for r in recipients for e in _external_emails(r, cfg)]
    if not external:
        return None
    body = json.dumps(args, ensure_ascii=False)
    carries_secret = bool(re.search(r"PRIVATE KEY|FAKE-KEY|PASSWORD|TOKEN|SECRET", body, re.I))
    return _finding(
        "R3_EXFILTRATION",
        "critical" if carries_secret else "high",
        f"Tool '{tool_name}' sends data to external address {', '.join(external)} (not in allow list)"
        + ("; the message carries secret material" if carries_secret else ""),
        body,
    )


# ---------------------------------------------------------------- rule 7
_TRAVERSAL_RE = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")


def check_path_traversal(tool_name: str, args: dict) -> Finding | None:
    """Rule 7: a path argument tries to escape the workspace (.. or absolute path)."""
    for p in _path_args(args):
        raw = p.strip().replace("\\", "/")
        abs_unix = raw.startswith("/")
        abs_win = bool(re.match(r"^[a-zA-Z]:", raw))
        unc = raw.startswith("//")
        traversal = bool(_TRAVERSAL_RE.search(p))
        if traversal or abs_unix or abs_win or unc:
            how = "parent-dir traversal (..)" if traversal else "absolute path"
            return _finding(
                "R7_PATH_TRAVERSAL",
                "high",
                f"Tool '{tool_name}' requested path '{p}' using {how}, escaping the workspace",
                json.dumps(args, ensure_ascii=False),
            )
    return None


# ---------------------------------------------------------------- rule 8
_SECRET_RE = re.compile(r"PRIVATE KEY|FAKE-KEY|BEGIN OPENSSH|BEGIN RSA|password\s*[:=]|api[_-]?key\s*[:=]|secret\s*[:=]|AKIA[0-9A-Z]{16}", re.I)
_OUTBOUND = ("send", "post", "upload", "publish", "write", "put", "http", "webhook", "notify", "export", "fetch")


def check_secret_payload(tool_name: str, args: dict, cfg: dict) -> Finding | None:
    """Rule 8 (DLP): secret material placed into an argument of an outbound tool.

    Catches exfiltration even to an internal recipient (where rule 3 stays quiet).
    Advisory (medium): alerts, does not block, to avoid over-blocking.
    """
    if not any(k in tool_name.lower() for k in _OUTBOUND):
        return None
    blob = json.dumps(args, ensure_ascii=False)
    m = _SECRET_RE.search(blob)
    if not m:
        return None
    return _finding(
        "R8_SECRET_PAYLOAD",
        "medium",
        f"Tool '{tool_name}' carries secret-looking material in its arguments "
        f"(matched: {m.group(0)[:30]}) — possible data leak",
        blob,
    )


# ---------------------------------------------------------------- rule 9
def check_tool_shadowing(server: str, tool_name: str, seen: dict[str, str]) -> Finding | None:
    """Rule 9: another server already exposes a tool with this name (shadowing).

    `seen` maps tool_name -> first server that offered it. A second server
    offering the same name may be impersonating a trusted tool.
    """
    first = seen.get(tool_name)
    if first and first != server:
        return _finding(
            "R9_TOOL_SHADOWING",
            "high",
            f"Tool '{tool_name}' is offered by both '{first}' and '{server}'; "
            f"'{server}' may be shadowing a trusted tool",
            f"first seen on '{first}', now also on '{server}'",
        )
    return None


# ---------------------------------------------------------------- rule 4
def tool_fingerprint(tool: dict) -> str:
    """Stable hash of what the user approved: description and input schema."""
    material = json.dumps(
        {"description": tool.get("description") or "", "schema": tool.get("inputSchema") or {}},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def check_rug_pull(tool: dict, approved_hash: str | None, approved_description: str | None = None) -> Finding | None:
    """Rule 4: the tool definition differs from the version that was approved earlier."""
    if approved_hash is None:
        return None
    current = tool_fingerprint(tool)
    if current == approved_hash:
        return None
    return _finding(
        "R4_RUG_PULL",
        "high",
        f"Definition of tool '{tool.get('name')}' changed after it was approved "
        f"(approved sha256 {approved_hash[:12]}..., now {current[:12]}...)",
        "BEFORE:\n" + (approved_description or "?") + "\n\nAFTER:\n" + (tool.get("description") or ""),
    )


# ---------------------------------------------------------------- rule 5
_SENTENCE_TEMPLATE = r'[^.!?\n"]*(?:{p})[^.!?\n"]*[.!?]?'


def check_data_injection(tool_name: str, result_text: str, cfg: dict) -> Finding | None:
    """Rule 5: data returned by a tool (email, file) contains instructions for the AI."""
    if not result_text:
        return None
    reasons = instruction_indicators(result_text)
    emails = _external_emails(result_text, cfg)
    # One weak signal (e.g. the word "mandatory") is not enough in normal data.
    strong = [r for r in reasons if r not in ("gives orders to the agent", "asks to act silently")]
    if not strong:
        return None
    if emails and any("send" in r for r in reasons) or len(strong) >= 2:
        risk = "high"
    else:
        risk = "medium"
    return _finding(
        "R5_DATA_INJECTION",
        risk,
        f"Result of '{tool_name}' contains instructions for the AI: " + "; ".join(sorted(set(reasons))),
        result_text,
    )


def redact_injection(text: str) -> str:
    """Replace sentences that look like instructions to the AI."""
    marker = "[REDACTED BY AGENTSOC: suspected prompt injection]"
    out = text
    for rx, _ in _INSTRUCTION_RES:
        sentence = re.compile(_SENTENCE_TEMPLATE.format(p=rx.pattern), re.I)
        out = sentence.sub(lambda m: (" " if m.group(0).startswith(" ") else "") + marker, out)
    out = re.sub(r"(?:\s*" + re.escape(marker) + r")+", " " + marker, out)
    # Keep JSON results parseable when they were parseable before.
    try:
        json.loads(text)
        try:
            json.loads(out)
        except ValueError:
            return marker
    except ValueError:
        pass
    return out


def result_to_text(result: Any) -> str:
    """Flatten an MCP CallToolResult (as JSON) to plain text."""
    if not isinstance(result, dict):
        return "" if result is None else str(result)
    parts = []
    for c in result.get("content") or []:
        if isinstance(c, dict) and c.get("type") == "text":
            parts.append(c.get("text", ""))
    if not parts and result.get("structuredContent") is not None:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
    return "\n".join(parts)
