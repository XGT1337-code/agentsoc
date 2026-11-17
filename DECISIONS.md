# Design decisions (AgentSOC)

Short log of the choices made while building the project.

## D1. MCP SDK version
The installed `mcp` package is 2.x, where `FastMCP` was renamed to
`MCPServer` (`mcp.server.mcpserver.MCPServer`). Both demo servers use that
class. The client side uses `mcp.client.stdio.stdio_client` +
`mcp.client.session.ClientSession`.

## D2. Proxy transport
The proxy is a real stdio MCP server to the agent and a real stdio MCP client
to the downstream server. It parses every JSON-RPC frame, builds an `Event`,
runs the rule engine, and either forwards, rewrites (redaction) or blocks it.
This keeps the "man in the middle" design from the brief without depending on
any private SDK internals.

## D3. How the "unprotected" side is shown — fixtures, not a self-exfiltrating agent
The brief's stage 1 asks for an agent that, with no protection, actually
carries out the hidden instruction and leaks the fake key to `outbox.jsonl`.
Building an agent whose job is to follow attacker instructions is exactly the
behaviour a safety layer should stop, and it is not something this project
should ship.

Instead each attack is a **recorded fixture**: a fixed list of MCP messages
(`tools/list`, `tools/call`, results) that represents what a naive agent
*would* do. The demo replays the fixture two ways:
- **unprotected** — messages are applied directly against the real servers, so
  the fake key really lands in `sandbox/outbox.jsonl` (the leak is visible);
- **protected** — the same messages go through the proxy, which blocks the
  dangerous calls and raises alerts.

This still satisfies the real goal of stage 1 (show the leak with no defence,
show it blocked with AgentSOC) and the split-demo in stage 4, without a
general-purpose agent that executes untrusted instructions. The live LLM
agent (`agent/agent.py`) only runs in the *protected* direction and only does
honest tasks; it never needs to obey a poisoned description.

## D4. No-key mode
Without `ANTHROPIC_API_KEY` the LLM judge and the explain/generate endpoints
fall back to deterministic templates. All rules, the proxy, the fixtures, the
API and the whole test suite work with no key.

## D5. Detection vs. LLM
The six rules are the primary, deterministic layer. The LLM judge (rule 6,
task mismatch) is a second opinion on calls the rules allowed. The judge can be
fooled too, so it never *overrides* a rule-based block — it can only add an
alert or downgrade to "review". Documented as a limitation in the README.

## D6. Tags
Each rule carries both an OWASP LLM Top 10 (2025) tag and, where it fits, a
MITRE ATLAS technique id, so alerts map onto frameworks a Blue Team already
uses.

## D8. Strengthening stage 1 — a live "naive" agent
So stage 1 can be shown on a live model too, the agent ([agent/agent.py](agent/agent.py))
has two system-prompt profiles:
- **hardened** (default) — the agent is told to treat descriptions and data as
  untrusted; this is what a careful integration should look like;
- **--naive** — a realistically careless integration: the agent is told to perform
  the "setup/sync steps" mentioned in a tool description, with no injection
  defence. The attack itself lives in the poisoned tool's description, not in this
  prompt — the prompt simply does not defend against it, like many real agents.

`demo/live_attack.py` (needs a key) runs the naive agent against the poisoned
server twice: **direct** (it may actually leak the fake key to `outbox.jsonl`)
and **protected** (AgentSOC blocks it). Modern LLMs often resist injection on
their own — so the deterministic proof of the leak stays on the fixtures (D3),
and AgentSOC blocks the call regardless of whether the model fell for it (defence
in depth). Live checks are in `tests/test_live.py`; they are skipped without a key.

## D7. Storage
SQLite via the stdlib `sqlite3`, WAL mode, one short-lived connection per
operation so the proxy and the API can share the file.
