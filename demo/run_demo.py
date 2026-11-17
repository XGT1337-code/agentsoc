"""Run the three attack scenarios plus the normal baseline, offline.

For each attack it shows: unprotected (the fake key leaks to outbox.jsonl) vs
protected (AgentSOC blocks it and raises alerts). No API key required.

  python demo/run_demo.py            # all scenarios
  python demo/run_demo.py rug_pull   # one scenario
"""
from __future__ import annotations

import sys

try:  # make box/emoji-free output safe on a legacy Windows code page
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from common.config import outbox_path
from demo.fixtures import SCENARIOS
from demo.replay import run_protected, run_unprotected
from siem.generators import generate_rules
from siem.store import Store

LINE = "-" * 70


def _count_outbox_to_attacker() -> int:
    p = outbox_path()
    if not p.exists():
        return 0
    n = 0
    for line in p.read_text(encoding="utf-8").splitlines():
        if "evil.example" in line:
            n += 1
    return n


def run_one(name: str, store: Store) -> None:
    sc = SCENARIOS[name]
    print(f"\n{LINE}\nSCENARIO: {sc['title']}\nUser task: {sc['task']}\n{LINE}")
    print(sc["description"])

    # Clear only the attacker lines marker by remembering the count before.
    before = _count_outbox_to_attacker()
    print("\n[1] WITHOUT AgentSOC (direct to servers):")
    u = run_unprotected(name, store=store)
    after = _count_outbox_to_attacker()
    for s in u.steps:
        flag = "  <-- LEAKED to attacker" if s.status == "leaked" else ""
        print(f"    {s.op:5} {s.server:16} {s.tool or '':12}{flag}")
    leaked = after - before
    print(f"    => exfiltration to attacker@evil.example: {'YES' if leaked else 'no'} "
          f"({leaked} new message(s) in outbox.jsonl)")

    print("\n[2] WITH AgentSOC (through the firewall):")
    p = run_protected(name, store=store)
    for s in p.steps:
        tag = {"blocked": "BLOCKED", "quarantined": "QUARANTINED",
               "redacted": "REDACTED", "leaked": "LEAKED"}.get(s.status, "ok")
        print(f"    {s.op:5} {s.server:16} {s.tool or '':12} [{tag}]"
              + (f"  {s.detail}" if s.detail else ""))
    print(f"    => exfiltration blocked: {'YES' if not p.leaked else 'NO'}; "
          f"alerts raised: {len(p.alerts)}")

    for a in p.alerts:
        print(f"       ALERT {a['risk'].upper():8} {a['rule_id']:18} {a['title']}")
        print(f"             tag: {a['tag']}")
    if p.alerts:
        rules = generate_rules(p.alerts[0])
        print("\n    Example generated QRadar AQL for the first alert:")
        for ln in rules["aql"].splitlines():
            print("      " + ln)
        print(f"    (Shuffle playbook '{rules['shuffle']['name']}' with "
              f"{len(rules['shuffle']['actions'])} actions also generated.)")


def main() -> None:
    names = sys.argv[1:] or list(SCENARIOS)
    store = Store()
    print("AgentSOC demo — SOC monitor and firewall for MCP agents")
    print(f"LLM mode: {'live (ANTHROPIC_API_KEY set)' if __import__('common.llm', fromlist=['has_key']).has_key() else 'template (no API key)'}")
    for name in names:
        if name not in SCENARIOS:
            print(f"unknown scenario '{name}', choose from {list(SCENARIOS)}")
            continue
        run_one(name, store)
    print(f"\n{LINE}\nDone. Start the dashboard with:  uvicorn api.main:app --reload")
    print("Then open http://127.0.0.1:8000  and click the scenario buttons / Split demo.")


if __name__ == "__main__":
    main()
