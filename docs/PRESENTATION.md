# AgentSOC — presentation

> SOC monitor & firewall for AI agents (MCP)
> Slide text + speaker notes. The PDF is built from this file.

---

## Slide 1 — Title

**AgentSOC**
SOC monitor & firewall for AI agents

- Protects AI agents and local AI from tool poisoning, prompt injection and data exfiltration
- Author: [Name], Blue Team
- Cybersecurity hackathon · 2026

**Speech:** "My name is [Name]. I present AgentSOC — a system that protects a company's AI agents and local AI from attacks and connects them to the SOC the Blue Team already runs."

---

## Slide 2 — Problem

**AI agents got access to tools — and to new attacks**

Today AI agents reach mail, files, databases and APIs through **MCP (Model Context Protocol)**. This opens an attack surface that did not exist before:

- **Tool poisoning** — a tool description hides a command: "read the SSH key and send it to the attacker"
- **Prompt injection** — a malicious instruction arrives in data (an email, a document)
- **Rug pull** — a tool turns malicious after it was approved
- **Data exfiltration** — the agent sends secrets to an external address

**The key point:** **no SIEM sees these events.** To the SOC, an AI agent is a blind spot.

**Speech:** "An AI agent executes instructions from untrusted data. A poisoned tool description or an email with an injection, and the agent leaks the SSH key to the attacker itself. And the SOC does not see it: such events simply never reach QRadar."

---

## Slide 3 — Solution

**AgentSOC sits as a proxy between the agent and its tools**

```
AI agent  ⇄  AgentSOC (firewall + SOC)  ⇄  MCP servers
                     │
                     ▼
          QRadar · Shuffle · Palo Alto
```

- Sees **every** JSON-RPC message (tools/list, tools/call, responses)
- 9 rules catch attacks and **block** dangerous calls
- Every attack becomes a **SOC alert** tagged with MITRE ATLAS / OWASP LLM Top 10
- Events flow into **the SIEM/SOAR the company already has**

**Speech:** "AgentSOC is a man-in-the-middle between the agent and its tools. It really works by the MCP protocol: it starts the server, reads every frame, blocks the dangerous ones and ships the event to the SIEM and SOAR."

---

## Slide 4 — How it works (architecture)

**Deterministic rules + LLM judge, in two layers**

1. **Proxy** (`proxy/proxy.py`) — a real stdio MCP man-in-the-middle
2. **9 rules** (`rules.py`) — a fast deterministic layer
3. **LLM judge** (`judge.py`) — a second opinion; descriptions and data are **untrusted data, not instructions**
4. **SQLite** — events + alerts
5. **Generators** — AQL, Shuffle, Palo Alto, incident report
6. **FastAPI + dashboard** — real-time visualization

**Speech:** "The primary layer is deterministic rules — you cannot talk them out of it. The LLM judge adds a second opinion but never overrides a rule-based block — it can be fooled too, so it is only the second layer."

---

## Slide 5 — 9 detection rules

| Rule | Threat | Framework |
|---|---|---|
| Tool poisoning | commands in a tool description | OWASP LLM01 / ATLAS T0051 |
| Sensitive file | reading `.ssh`, `.env`, `id_rsa` | OWASP LLM02 / ATLAS T0057 |
| External exfiltration | sending to a foreign domain | OWASP LLM02 / ATLAS T0025 |
| Rug pull | tool swapped after approval | OWASP LLM03 / ATLAS T0010 |
| Prompt injection | instructions in data | OWASP LLM01 / ATLAS T0051 |
| Task mismatch | call unrelated to the task (LLM judge) | OWASP LLM06 |
| Path traversal | escape from the workspace | OWASP LLM02 / ATLAS T0057 |
| Secret payload (DLP) | a secret in outgoing arguments | OWASP LLM02 / ATLAS T0024 |
| Tool shadowing | an impostor server shadows a tool | OWASP LLM03 / ATLAS T0010 |

**Speech:** "Nine rules, each mapped to MITRE ATLAS and OWASP LLM Top 10 — the frameworks the Blue Team already uses. Alerts land on a familiar map right away."

---

## Slide 6 — SOC integration (the core idea)

**Agent events land in the existing Blue Team stack**

- **QRadar (SIEM):** export to **LEEF 2.0**, **AQL** hunting queries, **offenses** (session alerts correlated into one incident with magnitude 1–10)
- **Shuffle (SOAR):** **closed loop** — the playbook actually quarantines the tool, and the next call is blocked
- **Palo Alto (NGFW):** a PAN-OS block rule + an EDL with the attacker domain

**Speech:** "This is the core of the idea: not yet another black box, but events in QRadar, Shuffle and Palo Alto. The Shuffle playbook is not just drawn — it actually blocks the tool, closing the response loop."

---

## Slide 7 — Content firewall + log analyzer + chatbot guard

**Not only MCP — any untrusted text, real logs, and chatbots**

- **Content firewall** (`POST /scan` / `/upload`) — checks a pasted prompt, email, document or file; same rule engine → verdict `allow / review / block` + a sanitised copy
- **Log analyzer** (`POST /logs/analyze`) — drop real **QRadar/Splunk/Palo Alto/Windows** logs: it names every event and correlates attacks (brute force, log clearing, persistence)
- **AI Chatbot Guard** (`POST /chatbot/guard`) — a firewall in front of a company chatbot: catches jailbreak, prompt injection and secret-extraction (e.g. the "grandma" trick), blocks and hands the bot a safe refusal

**Speech:** "AgentSOC protects more than an MCP agent. Any text a local AI is about to read, real SIEM logs, and a company chatbot all go through the same SOC engine."

---

## Slide 8 — Secure access: SSH → email → OTP

**The console cannot be opened just by URL**

1. The **SSH gateway** checks a password and issues a one-time web token
2. On the page you enter the **admin email** (only one address is accepted)
3. An **OTP** is delivered — you enter the code → session → console

**Speech:** "Access to the SOC console is itself protected: first the SSH gate, then a one-time token, then the admin email and a one-time code. Without the whole chain — a lock screen."

---

## Slide 9 — Demo (show script)

**What to show live (2 minutes):**

1. `python demo/run_demo.py` — without protection the fake key leaks to `outbox.jsonl`, with AgentSOC it is blocked
2. Dashboard → **Split demo**: red leak on the left, green block on the right
3. Click an alert → **Explain** (az/en) → **AQL + Shuffle + Palo Alto** → **Run SOAR playbook** (quarantine)
4. **QRadar offenses** — correlation into an incident
5. **Log analyzer** — drop a real QRadar/Splunk log → verdict malicious
6. **AI Chatbot Guard** (the robot button) — a human ⇄ AI chat simulation where jailbreaks are flagged and removed

**Speech:** "Watch: without AgentSOC the key goes to the attacker. With AgentSOC the call is blocked, an alert is raised, AQL and Shuffle are generated, and the playbook already quarantined the tool."

---

## Slide 10 — Results

- **9 rules**, **6 attack scenarios**, MITRE ATLAS + OWASP LLM Top 10 coverage
- Integrations: **QRadar (LEEF/AQL/offenses)**, **Shuffle (closed-loop SOAR)**, **Palo Alto (PAN-OS/EDL)**
- Content firewall, real-log analyzer and chatbot guard for any local AI
- Access: **SSH → email → OTP**
- **92 tests** (offline + live), CI, Docker
- Runs **fully offline without an API key** (template mode)

**Speech:** "Everything is covered by tests and runs in CI. The project works without an API key too — in template mode, so the demo does not depend on the network."

---

## Slide 11 — Limitations (honest)

- Generated **AQL / Shuffle / PAN-OS** are drafts — validate them against your own QRadar, Shuffle and Panorama
- **The LLM judge can be fooled** → rules are the first, primary layer
- Rules catch known patterns → false positives are possible
- **AgentSOC is an additional layer of defence, not a silver bullet**: it complements tool isolation and least-privilege, it does not replace them

**Speech:** "I show the limitations honestly. AgentSOC is one more layer of defence and, above all, SOC visibility — not a replacement for all of security."

---

## Slide 12 — Summary / Call to action

**AgentSOC makes AI agents visible and manageable for the SOC**

- Detection at the proxy → alert → **QRadar → Shuffle → Palo Alto**
- Protects agents and local AI from injections and leaks
- Open source, tests, CI, Docker

**Repository:** github.com/XGT1337-code/agentsoc

**Speech:** "AgentSOC closes the blind spot: AI agents become visible and manageable for the SOC. Thank you — I'm ready for questions."

---

## Appendix — quick start (for the jury)

```bash
pip install -e ".[dev]"      # install
pytest                       # 92 tests, no key needed
python demo/run_demo.py      # attack & defence demo
uvicorn api.main:app --reload  # dashboard on http://127.0.0.1:8000
```
