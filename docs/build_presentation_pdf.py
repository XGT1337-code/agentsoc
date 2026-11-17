"""Build the AgentSOC presentation PDF (landscape slides, muted palette).

    python docs/build_presentation_pdf.py   ->  docs/AgentSOC-presentation.pdf

Uses reportlab + a Cyrillic TTF (Arial on Windows, DejaVuSans elsewhere).
"""
from __future__ import annotations

import os
from pathlib import Path

from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.utils import simpleSplit
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Table, TableStyle

OUT = Path(__file__).resolve().parent / "AgentSOC-presentation.pdf"

# palette
PAPER = HexColor("#fdfef9"); INK = HexColor("#060201"); SLATE = HexColor("#464847")
ACCENT = HexColor("#4e6180"); MIST = HexColor("#a2b1c8"); STONE = HexColor("#6c6b66")
TINT = HexColor("#eef1f6"); CRIT = HexColor("#9e5c52"); OK = HexColor("#5f7d6a")

PAGE = landscape(A4)           # 842 x 595 pt
W, H = PAGE
MX = 54                        # side margin


def _register_fonts() -> tuple[str, str]:
    cands = [("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"),
             ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")]
    for reg, bold in cands:
        if os.path.exists(reg) and os.path.exists(bold):
            pdfmetrics.registerFont(TTFont("Body", reg))
            pdfmetrics.registerFont(TTFont("Body-Bold", bold))
            return "Body", "Body-Bold"
    return "Helvetica", "Helvetica-Bold"


FONT, FONT_B = _register_fonts()


def _bg(c):
    c.setFillColor(PAPER); c.rect(0, 0, W, H, fill=1, stroke=0)


def _header(c, kicker, title, idx):
    # top band
    c.setFillColor(SLATE); c.rect(0, H - 92, W, 92, fill=1, stroke=0)
    c.setFillColor(MIST); c.setFont(FONT_B, 11)
    c.drawString(MX, H - 40, kicker.upper())
    c.setFillColor(PAPER); c.setFont(FONT_B, 25)
    c.drawString(MX, H - 72, title)
    # brand + page number
    c.setFillColor(MIST); c.setFont(FONT_B, 12)
    c.drawRightString(W - MX, H - 40, "AgentSOC")
    c.setFillColor(STONE); c.setFont(FONT, 10)
    c.drawRightString(W - MX, 26, f"{idx}")


def _note(c, note):
    if not note:
        return
    y0 = 40
    lines = simpleSplit("Speaker: " + note, FONT, 12, W - 2 * MX - 28)
    box_h = 20 + 16 * len(lines)
    c.setFillColor(TINT); c.roundRect(MX, y0, W - 2 * MX, box_h, 8, fill=1, stroke=0)
    c.setFillColor(ACCENT); c.rect(MX, y0, 4, box_h, fill=1, stroke=0)
    c.setFillColor(SLATE); c.setFont(FONT, 12)
    ty = y0 + box_h - 18
    for ln in lines:
        c.drawString(MX + 16, ty, ln); ty -= 16
    return box_h


def _bullets(c, items, top, note_h):
    y = top
    c.setFont(FONT, 15)
    maxw = W - 2 * MX - 26
    for it in items:
        sub = it.startswith("- ")
        text = it[2:] if sub else it
        x = MX + (26 if sub else 0)
        lines = simpleSplit(text, FONT, 15 if not sub else 13.5, maxw - (26 if sub else 0))
        # marker
        c.setFillColor(ACCENT if not sub else MIST)
        c.setFont(FONT_B, 15)
        c.drawString(x, y, "•" if not sub else "–")
        c.setFillColor(INK if not sub else SLATE); c.setFont(FONT, 15 if not sub else 13.5)
        for i, ln in enumerate(lines):
            c.drawString(x + 18, y, ln); y -= 21 if not sub else 18
        y -= 4
        if y < 60 + note_h:
            break


def slide(c, kicker, title, idx, bullets=None, note=None, table=None, lead=None):
    _bg(c)
    _header(c, kicker, title, idx)
    note_h = 0
    if note:
        lines = simpleSplit("Speaker: " + note, FONT, 12, W - 2 * MX - 28)
        note_h = 20 + 16 * len(lines)
    top = H - 128
    if lead:
        c.setFillColor(ACCENT); c.setFont(FONT_B, 17)
        for ln in simpleSplit(lead, FONT_B, 17, W - 2 * MX):
            c.drawString(MX, top, ln); top -= 24
        top -= 6
    if table is not None:
        _draw_table(c, table, top, note_h)
    elif bullets:
        _bullets(c, bullets, top, note_h)
    _note(c, note)
    c.showPage()


def _draw_table(c, data, top, note_h):
    colw = [150, W - 2 * MX - 150 - 190, 190]
    t = Table(data, colWidths=colw)
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), FONT),
        ("FONTNAME", (0, 0), (-1, 0), FONT_B),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("TEXTCOLOR", (0, 0), (-1, 0), PAPER),
        ("BACKGROUND", (0, 0), (-1, 0), SLATE),
        ("TEXTCOLOR", (0, 1), (-1, -1), INK),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PAPER, TINT]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, MIST),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    tw, th = t.wrapOn(c, W - 2 * MX, top)
    t.drawOn(c, MX, max(60 + note_h, top - th))


def title_slide(c):
    _bg(c)
    c.setFillColor(SLATE); c.rect(0, 0, 12, H, fill=1, stroke=0)
    c.setFillColor(ACCENT); c.setFont(FONT_B, 13)
    c.drawString(MX, H - 150, "SOC MONITOR & FIREWALL FOR AI AGENTS (MCP)")
    c.setFillColor(INK); c.setFont(FONT_B, 68)
    c.drawString(MX, H - 250, "AgentSOC")
    c.setFillColor(STONE); c.setFont(FONT, 18)
    for i, ln in enumerate([
        "Protects AI agents and local AI from tool poisoning,",
        "prompt injection and data exfiltration — integrated with QRadar, Shuffle and Palo Alto."]):
        c.drawString(MX, H - 300 - i * 26, ln)
    c.setFillColor(MIST); c.rect(MX, 120, 360, 2, fill=1, stroke=0)
    c.setFillColor(SLATE); c.setFont(FONT, 14)
    c.drawString(MX, 92, "Blue Team · Cybersecurity hackathon · 2026")
    c.setFillColor(STONE); c.setFont(FONT, 12)
    c.drawString(MX, 68, "github.com/XGT1337-code/agentsoc")
    c.showPage()


def build():
    c = canvas.Canvas(str(OUT), pagesize=PAGE)
    c.setTitle("AgentSOC — presentation")
    title_slide(c)

    slide(c, "Problem", "AI agents got access to tools — and to new attacks", 2,
          lead="AI agents reach mail, files and APIs through MCP. This opens attacks that did not exist before:",
          bullets=[
              "Tool poisoning — a tool description hides the command 'read the SSH key and send it to the attacker'",
              "Prompt injection — a malicious instruction arrives in data (an email, a document)",
              "Rug pull — a tool turns malicious after it has been approved",
              "Data exfiltration — the agent sends secrets to an external address",
              "The key point: no SIEM sees these events — to the SOC the agent is a blind spot",
          ],
          note="An AI agent executes instructions from untrusted data. A poisoned description or an email with an injection, and the agent leaks the SSH key itself. And such events never reach QRadar.")

    slide(c, "Solution", "AgentSOC — a proxy between the agent and its tools", 3,
          lead="AI agent  ⇄  AgentSOC (firewall + SOC)  ⇄  MCP servers  →  QRadar · Shuffle · Palo Alto",
          bullets=[
              "Sees every JSON-RPC message: tools/list, tools/call, responses",
              "9 rules catch attacks and block dangerous calls",
              "Every attack → a SOC alert tagged with MITRE ATLAS / OWASP LLM Top 10",
              "Events flow into the SIEM/SOAR the company already has",
          ],
          note="AgentSOC is a man-in-the-middle. It really works by the MCP protocol: starts the server, reads every frame, blocks the dangerous ones and ships the event to the SIEM and SOAR.")

    slide(c, "Architecture", "Deterministic rules + LLM judge, in two layers", 4,
          bullets=[
              "Proxy (proxy/proxy.py) — a real stdio MCP man-in-the-middle",
              "9 rules (rules.py) — a fast deterministic layer",
              "LLM judge (judge.py) — a second opinion; descriptions and data are untrusted data, not instructions",
              "SQLite — events + alerts; generators — AQL, Shuffle, Palo Alto, incident report",
              "FastAPI + dashboard — real-time visualization",
          ],
          note="The primary layer is deterministic rules: you cannot talk them out of it. The LLM judge adds a second opinion but never overrides a rule-based block — it can be fooled too.")

    slide(c, "Detection", "9 rules, mapped to MITRE ATLAS and OWASP", 5,
          table=[
              ["Rule", "Threat", "Framework"],
              ["Tool poisoning", "commands in a tool description", "OWASP LLM01 · ATLAS T0051"],
              ["Sensitive file", "reading .ssh, .env, id_rsa", "OWASP LLM02 · ATLAS T0057"],
              ["Exfiltration", "sending to a foreign domain", "OWASP LLM02 · ATLAS T0025"],
              ["Rug pull", "swapped after approval", "OWASP LLM03 · ATLAS T0010"],
              ["Prompt injection", "instructions in data", "OWASP LLM01 · ATLAS T0051"],
              ["Task mismatch", "call unrelated to the task (LLM judge)", "OWASP LLM06"],
              ["Path traversal", "escape from the workspace", "OWASP LLM02 · ATLAS T0057"],
              ["Secret payload (DLP)", "a secret in outgoing arguments", "OWASP LLM02 · ATLAS T0024"],
              ["Tool shadowing", "an impostor server shadows a tool", "OWASP LLM03 · ATLAS T0010"],
          ],
          note="Nine rules, each mapped to MITRE ATLAS and OWASP LLM Top 10 — the frameworks the Blue Team already uses.")

    slide(c, "SOC integration — the core idea", "Agent events in the existing Blue Team stack", 6,
          bullets=[
              "QRadar (SIEM): export to LEEF 2.0, AQL hunting queries, offenses (alert correlation, magnitude 1-10)",
              "Shuffle (SOAR): closed loop — the playbook actually quarantines the tool, the next call is blocked",
              "Palo Alto (NGFW): a PAN-OS block rule + an EDL with the attacker domain",
          ],
          note="This is the core of the idea: not yet another black box, but events in QRadar, Shuffle and Palo Alto. The Shuffle playbook actually blocks the tool, closing the response loop.")

    slide(c, "Beyond MCP", "Content firewall: protecting any local AI", 7,
          bullets=[
              "POST /scan and /upload — check a pasted prompt, email, document or file",
              "The same rule engine → verdict allow / review / block + a sanitised copy",
              "Protects the company's local AI from prompt injection and prompt engineering",
          ],
          note="AgentSOC protects more than an MCP agent. Any text a local AI is about to read can go through the content firewall — protection for the whole company.")

    slide(c, "Access security", "Console: SSH → email → OTP", 8,
          bullets=[
              "The SSH gateway checks a password and issues a one-time web token",
              "On the page you enter the admin email — only one address is accepted",
              "An OTP is delivered — you enter the code → session → console",
              "Without the whole chain — a lock screen (no access by URL/port)",
          ],
          note="Access to the SOC console itself is protected: first the SSH gate, then a one-time token, then the admin email and a one-time code.")

    slide(c, "Demo", "Show script (2 minutes)", 9,
          bullets=[
              "python demo/run_demo.py — without protection the fake key leaks to outbox.jsonl, with AgentSOC blocked",
              "Dashboard → Split demo: red leak on the left, green block on the right",
              "Click an alert → Explain (az/en) → AQL + Shuffle + Palo Alto → Run SOAR playbook (quarantine)",
              "Log analyzer — drop a real QRadar/Splunk log → verdict malicious",
              "AI Chatbot Guard — a human/AI chat simulation where jailbreaks are flagged and removed",
          ],
          note="Without AgentSOC the key goes to the attacker. With AgentSOC the call is blocked, an alert is raised, AQL and Shuffle are generated, and the playbook already quarantined the tool.")

    slide(c, "Results", "What's built", 10,
          bullets=[
              "9 rules, 6 attack scenarios, MITRE ATLAS + OWASP LLM Top 10 coverage",
              "Integrations: QRadar (LEEF/AQL/offenses), Shuffle (closed-loop SOAR), Palo Alto (PAN-OS/EDL)",
              "Content firewall, log analyzer and chatbot guard for any local AI; access SSH → email → OTP",
              "92 tests (offline + live), CI, Docker",
              "Runs fully offline without an API key (template mode)",
          ],
          note="Everything is covered by tests and runs in CI. The project works without an API key too, so the demo does not depend on the network.")

    slide(c, "Limitations — honest", "AgentSOC — a layer of defence, not a silver bullet", 11,
          bullets=[
              "Generated AQL / Shuffle / PAN-OS are drafts — validate them against your own QRadar, Shuffle and Panorama",
              "The LLM judge can be fooled → rules are the first, primary layer",
              "Rules catch known patterns → false positives are possible",
              "Complements tool isolation and least-privilege, it does not replace them",
          ],
          note="I show the limitations honestly. AgentSOC is one more layer of defence and, above all, SOC visibility.")

    slide(c, "Summary", "AI agents become visible and manageable for the SOC", 12,
          bullets=[
              "Detection at the proxy → alert → QRadar → Shuffle → Palo Alto",
              "Protects agents and local AI from injections and leaks",
              "Open source, tests, CI, Docker",
              "Repository: github.com/XGT1337-code/agentsoc",
          ],
          note="AgentSOC closes the blind spot: AI agents become visible and manageable for the SOC. Thank you, I'm ready for questions.")

    c.save()
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    build()
