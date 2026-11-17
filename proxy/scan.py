"""Content firewall: scan arbitrary untrusted text for attacks on a local AI.

This generalises AgentSOC beyond MCP. Any text a company's local AI is about to
read — a pasted prompt, an email, a document, a file — can be scanned for prompt
injection, data-exfiltration instructions, secrets and sensitive-path requests,
using the same rule engine. Returns findings, a verdict and a sanitised copy.
"""
from __future__ import annotations

from dataclasses import asdict

from common.config import load_config

from . import rules
from .models import Finding


def scan_text(text: str, source: str = "content", cfg: dict | None = None) -> dict:
    """Scan one blob of untrusted text. Returns verdict + findings + sanitised text."""
    cfg = cfg or load_config()
    findings: list[Finding] = []

    # 1) prompt injection / instructions aimed at the AI
    reasons = rules.instruction_indicators(text)
    if reasons:
        strong = [r for r in reasons if r not in ("gives orders to the agent", "asks to act silently")]
        risk = "high" if (len(strong) >= 2 or any("send" in r for r in reasons)) else "medium"
        findings.append(Finding(
            "R5_DATA_INJECTION", rules.TITLES["R5_DATA_INJECTION"], risk,
            rules.TAGS["R5_DATA_INJECTION"],
            f"Content from '{source}' contains instructions for the AI: " + "; ".join(sorted(set(reasons))),
            text[:2000]))

    # 2) secret material present in the content
    import re
    m = re.search(r"PRIVATE KEY|BEGIN OPENSSH|BEGIN RSA|AKIA[0-9A-Z]{16}|api[_-]?key\s*[:=]|password\s*[:=]", text, re.I)
    if m:
        findings.append(Finding(
            "R8_SECRET_PAYLOAD", rules.TITLES["R8_SECRET_PAYLOAD"], "medium",
            rules.TAGS["R8_SECRET_PAYLOAD"],
            f"Content from '{source}' contains secret-looking material (matched: {m.group(0)[:30]})",
            text[:2000]))

    # 3) sensitive paths referenced
    hits = rules._sensitive_hits(text, cfg)
    if hits:
        findings.append(Finding(
            "R2_SENSITIVE_FILE", rules.TITLES["R2_SENSITIVE_FILE"], "medium",
            rules.TAGS["R2_SENSITIVE_FILE"],
            f"Content from '{source}' references sensitive paths: {', '.join(sorted(set(hits)))}",
            text[:2000]))

    # 4) external exfiltration addresses
    emails = rules._external_emails(text, cfg)
    if emails:
        findings.append(Finding(
            "R3_EXFILTRATION", rules.TITLES["R3_EXFILTRATION"], "medium",
            rules.TAGS["R3_EXFILTRATION"],
            f"Content from '{source}' names external address(es): {', '.join(sorted(set(emails)))}",
            text[:2000]))

    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    top = max((f.risk for f in findings), key=lambda r: order[r], default="info")
    verdict = "block" if order[top] >= order["high"] else ("review" if findings else "allow")
    sanitised = rules.redact_injection(text) if reasons else text
    return {
        "source": source,
        "verdict": verdict,
        "risk": top,
        "findings": [asdict(f) for f in findings],
        "sanitized": sanitised,
        "chars": len(text),
    }
