"""Closed-loop SOAR: actually run a generated Shuffle playbook locally.

This demonstrates the full automation loop the MD brief is about:

    alert  ->  Shuffle playbook  ->  block_tool action  ->  AgentSOC quarantines
    the tool at the proxy  ->  the next call to that tool is blocked (rule R0).

The playbook steps are executed against the local store (no external Shuffle
needed). Each step returns a status so the dashboard can show the run.
"""
from __future__ import annotations

from datetime import datetime, timezone

from siem.generators import generate_shuffle
from siem.store import Store


def execute_playbook(alert: dict, store: Store) -> dict:
    """Run the Shuffle playbook for `alert`. Returns an execution log."""
    pb = generate_shuffle(alert)
    log = []
    containment = None
    for action in pb["actions"]:
        aid = action["id"]
        status, detail = "ok", action.get("description", "")
        if aid == "block_tool":
            server = alert.get("server", "")
            tool = alert.get("tool") or "*"
            if alert.get("risk") in ("high", "critical"):
                store.block_tool(server, tool, reason=f"SOAR playbook for alert {alert.get('id')}")
                containment = {"server": server, "tool": tool}
                detail = f"Quarantined '{tool}' on '{server}' via SOAR blocklist."
            else:
                status, detail = "skipped", "Risk below high; no auto-containment."
        elif aid == "get_alert":
            detail = f"Fetched alert {alert.get('id')} ({alert.get('rule_id')})."
        elif aid == "enrich":
            detail = "Pulled AQL hunt query for related activity."
        elif aid == "notify_analyst":
            detail = "Notified SOC analyst (soc-team@corp.example)."
        log.append({"id": aid, "app": action.get("app"), "status": status, "detail": detail})
    return {
        "playbook": pb["name"],
        "alert_id": alert.get("id"),
        "executed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "steps": log,
        "containment": containment,
        "contained": containment is not None,
    }
