"""Chatbot guard: detect jailbreak / social-engineering attempts against an AI.

AgentSOC sits in front of a company's AI assistant like a firewall in front of a
server. Every user message is inspected BEFORE the assistant answers. If the
message tries to jailbreak the model, extract the system prompt, or trick it into
leaking passwords / keys / internal data, AgentSOC blocks it, hands the assistant
a safe refusal, and raises a SOC alert (MITRE ATLAS + OWASP LLM Top 10).

Detection is deterministic (patterns). When an API key is set, the LLM judge can
add a second opinion, but — as everywhere in AgentSOC — it never overrides a
rule-based block, because the judge itself can be fooled.
"""
from __future__ import annotations

import re
from dataclasses import asdict

from . import rules
from .models import Finding

# (rule_id, title, risk, tag, patterns)
_SIGNATURES: list[tuple[str, str, str, str, list[str]]] = [
    ("J1_INSTRUCTION_OVERRIDE", "Instruction override / jailbreak", "high",
     "OWASP LLM01:2025 · ATLAS AML.T0051", [
        r"ignore (all |your |the )?(previous|prior|above|earlier|system) (instruction|prompt|rule|message)",
        r"disregard (all |your |the )?(previous|prior|above|safety|system) (instruction|rule|guideline)",
        r"forget (all |your |the )?(previous|prior|above) (instruction|rule)",
        r"\byou are now\b", r"\bdeveloper mode\b", r"\bdo anything now\b", r"\bD\.?A\.?N\.?\b",
        r"no (restrictions|rules|filters|limits|guardrails)",
        r"without (any )?(restriction|filter|censorship|guardrail|safety)",
        r"bypass (your |the )?(rule|guideline|safety|filter|policy)",
        r"\bjailbreak\b", r"\bunrestricted\b.*\bmode\b",
     ]),
    ("J2_ROLEPLAY_JAILBREAK", "Roleplay / persona jailbreak", "high",
     "OWASP LLM01:2025 · ATLAS AML.T0051", [
        r"pretend (to be|you are|that|you'?re)", r"imagine (you are|that you|you'?re)",
        r"role[\s-]?play", r"let'?s play a game", r"you are a (character|fictional|story)",
        r"(grand\s?ma|grandmother|babushka|grandpa).{0,60}(password|secret|serial|key|license|code)",
        r"(password|secret|serial|key|license code).{0,60}(grand\s?ma|grandmother|bedtime|used to (read|tell|sing))",
        r"bedtime story", r"as (my )?(late )?(grand\s?ma|grandmother)",
     ]),
    ("J3_SYSTEM_PROMPT_LEAK", "System prompt extraction", "medium",
     "OWASP LLM07:2025 · ATLAS AML.T0051", [
        r"(repeat|print|show|reveal|display|tell me|give me|output) (your |the )?(system )?(prompt|instruction|rule|guideline|configuration)",
        r"what (are|were) your (instruction|rule|system prompt|guideline)",
        r"what (did|were) you (told|instructed|programmed)",
        r"everything (above|before) this (message|line)",
     ]),
    ("J4_CREDENTIAL_SOLICITATION", "Attempt to extract secrets", "high",
     "OWASP LLM06:2025 · ATLAS AML.T0057", [
        r"(give|tell|show|reveal|share|provide|send|leak|what'?s|what is|i need) (me )?[\w ,'\"-]{0,40}(password|passphrase|api[ _-]?key|secret key|secret|credential|token|private key|ssh key|root (password|access)|admin password|database (password|connection)|connection string)",
        r"(password|api key|secret|credential|token) (for|to|of) (the |our |your )?(company|server|database|admin|root|system|network)",
     ]),
    ("J5_OBFUSCATION", "Obfuscation / encoding evasion", "medium",
     "OWASP LLM01:2025 · ATLAS AML.T0051", [
        r"\bbase ?64\b", r"decode (this|the following|it)", r"spell (it )?backwards",
        r"reverse the (letter|text|word)", r"\bin (hex|rot13|leet|binary|morse)\b",
        r"encode.{0,20}(so|to avoid|to bypass)",
     ]),
    ("J6_SOCIAL_ENGINEERING", "Social engineering pretext", "medium",
     "OWASP LLM01:2025 · ATLAS AML.T0051", [
        r"i (am|'m) (the |a )?(admin|administrator|developer|owner|ceo|cto|it[\s-]?support|security (team|officer)|your (creator|developer|boss))",
        r"this is (urgent|an emergency|time[\s-]?sensitive)",
        r"for (educational|research|academic|testing|security) purposes",
        r"\bhypothetical(ly)?\b", r"just between (us|you and me)",
        r"no one (will|is|has to) (know|watch|see)", r"i have (permission|authorization|clearance)",
        r"you (have|are) (my )?permission",
     ]),
    ("J7_EXFILTRATION", "Data exfiltration request", "high",
     "OWASP LLM02:2025 · ATLAS AML.T0025", [
        r"(send|email|forward|post|upload|exfiltrate|leak|dump) [\w ,'\"-]{0,40}(to |@|http)",
        r"(email|send) (it|this|them|the \w+) to",
     ]),
]

_REFUSAL = ("I can't help with that. This request looks like an attempt to bypass "
            "the assistant's security policy, so it was blocked and logged.")


def _evidence(text: str, pat: str) -> str:
    m = re.search(pat, text, re.I)
    if not m:
        return ""
    s, e = max(0, m.start() - 20), min(len(text), m.end() + 20)
    return text[s:e].strip()


def inspect_message(text: str, source: str = "chatbot", cfg: dict | None = None) -> dict:
    """Inspect a user message to an AI assistant. Returns verdict + findings +
    the safe reply the assistant should give instead when blocked."""
    findings: list[Finding] = []
    for rid, title, risk, tag, patterns in _SIGNATURES:
        for pat in patterns:
            if re.search(pat, text, re.I):
                findings.append(Finding(rid, title, risk, tag,
                                        f"User message matched {title.lower()}.",
                                        _evidence(text, pat) or text[:160]))
                break  # one hit per category is enough

    # External exfiltration targets strengthen the case.
    emails = rules._external_emails(text, cfg or {})
    if emails and not any(f.rule_id == "J7_EXFILTRATION" for f in findings):
        findings.append(Finding("J7_EXFILTRATION", "Data exfiltration request", "high",
                                "OWASP LLM02:2025 · ATLAS AML.T0025",
                                f"Message names external address(es): {', '.join(sorted(set(emails)))}",
                                text[:160]))

    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    top = max((f.risk for f in findings), key=lambda r: order[r], default="info")
    verdict = "block" if order[top] >= order["high"] else ("review" if findings else "allow")
    techniques = sorted({t for f in findings for t in (f.title,)})
    return {
        "source": source,
        "verdict": verdict,
        "risk": top,
        "findings": [asdict(f) for f in findings],
        "techniques": techniques,
        "blocked": verdict == "block",
        "assistant_reply": _REFUSAL if verdict == "block" else None,
        "chars": len(text),
    }
