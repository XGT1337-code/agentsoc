"""Analyze parsed logs: name every event, correlate attack patterns, verdict.

This is the SOC brain over the knowledge base. It turns a dropped real log into:
  - a recognized-events table (event -> human name, outcome, severity, count),
  - correlation findings (brute force, log clearing, persistence, priv-esc, ...),
  - an overall verdict (clean / suspicious / malicious) with MITRE ATT&CK tags,
  - counts a SOC cares about (by outcome, severity, category).
"""
from __future__ import annotations

from collections import defaultdict

from analyzer import knowledge
from analyzer.parse import parse

_BRUTE_THRESHOLD = 5  # failed auths from one identity before it is "brute force"


def _signature(rec: dict) -> dict:
    src, eid, f = rec.get("source"), rec.get("event_id"), rec.get("fields", {})
    if src == "linux-auth" and f.get("_linux_sig"):
        return dict(f["_linux_sig"])
    if src == "palo-alto" and eid:
        return knowledge.palo_signature(eid, f.get("action", ""), f.get("severity", ""))
    if eid:
        sig = knowledge.lookup(src, eid)
        if sig:
            return sig
    return {"name": "Unrecognized event", "outcome": "info", "severity": "info",
            "category": "unknown", "mitre": "", "source": src or "unknown",
            "event_id": eid, "desc": "No signature matched; review manually."}


def _ident(rec: dict) -> str:
    f = rec.get("fields", {})
    return f.get("user") or f.get("ip") or "?"


def analyze_text(text: str, source: str | None = None) -> dict:
    recs = parse(text)
    enriched = []
    for r in recs:
        sig = _signature(r)
        enriched.append({**r, "sig": sig})

    # ---- recognized-events table (aggregated) -------------------------------
    agg: dict[tuple, dict] = {}
    by_outcome = defaultdict(int)
    by_severity = defaultdict(int)
    by_category = defaultdict(int)
    mitre = defaultdict(int)
    for e in enriched:
        s = e["sig"]
        key = (s.get("source"), s.get("event_id"), s["name"])
        row = agg.setdefault(key, {"source": s.get("source"), "event_id": s.get("event_id"),
                                   "name": s["name"], "outcome": s["outcome"],
                                   "severity": s["severity"], "category": s.get("category"),
                                   "mitre": s.get("mitre"), "desc": s.get("desc"),
                                   "count": 0, "identities": set()})
        row["count"] += 1
        ident = _ident(e)
        if ident != "?":
            row["identities"].add(ident)
        by_outcome[s["outcome"]] += 1
        by_severity[s["severity"]] += 1
        by_category[s.get("category", "unknown")] += 1
        if s.get("mitre"):
            mitre[s["mitre"]] += 1

    events = sorted(agg.values(),
                    key=lambda r: (knowledge.SEVERITY_ORDER.index(r["severity"]), r["count"]),
                    reverse=True)
    for r in events:
        r["identities"] = sorted(r["identities"])[:8]

    # ---- correlation findings ----------------------------------------------
    findings = _correlate(enriched)

    recognized = sum(1 for e in enriched if e["sig"]["name"] != "Unrecognized event")
    unknown = len(enriched) - recognized
    max_sev = "info"
    for fnd in findings:
        max_sev = knowledge.worst(max_sev, fnd["severity"])
    verdict = ("malicious" if max_sev in ("high", "critical")
               else "suspicious" if max_sev in ("medium", "low") and findings
               else "clean")

    return {
        "verdict": verdict,
        "max_severity": max_sev,
        "summary": {
            "total_records": len(enriched),
            "recognized": recognized,
            "unknown": unknown,
            "by_outcome": dict(by_outcome),
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
        },
        "events": events,
        "findings": findings,
        "mitre_attack": dict(sorted(mitre.items(), key=lambda kv: kv[1], reverse=True)),
    }


def _correlate(enriched: list[dict]) -> list[dict]:
    findings: list[dict] = []

    def ids_with(pred):
        return [e for e in enriched if pred(e)]

    is_fail = lambda e: e["sig"]["outcome"] == "failure"
    is_success = lambda e: e["sig"]["outcome"] == "success"

    # Brute force (and whether it then succeeded) per identity.
    fails_by = defaultdict(int)
    for e in ids_with(is_fail):
        fails_by[_ident(e)] += 1
    success_idents = {_ident(e) for e in ids_with(is_success)}
    for ident, n in sorted(fails_by.items(), key=lambda kv: kv[1], reverse=True):
        if ident == "?" or n < _BRUTE_THRESHOLD:
            continue
        if ident in success_idents:
            findings.append({"id": "brute_force_success", "title": "Brute force likely SUCCEEDED",
                             "severity": "critical", "mitre": "T1110",
                             "detail": f"{n} failed logons for '{ident}' followed by a success.",
                             "evidence": ident})
        else:
            findings.append({"id": "brute_force", "title": "Brute force attempt",
                             "severity": "high", "mitre": "T1110",
                             "detail": f"{n} failed authentications for '{ident}'.",
                             "evidence": ident})

    def has_eid(*eids):
        return [e for e in enriched if str(e.get("event_id")) in eids]

    if has_eid("1102"):
        findings.append({"id": "log_cleared", "title": "Security audit log cleared",
                         "severity": "critical", "mitre": "T1070.001",
                         "detail": "Event 1102 present — anti-forensics / cover tracks.",
                         "evidence": "1102"})
    if has_eid("4719"):
        findings.append({"id": "audit_tampering", "title": "Audit policy changed",
                         "severity": "high", "mitre": "T1562.002",
                         "detail": "Event 4719 — logging configuration was altered.",
                         "evidence": "4719"})
    created = has_eid("4720")
    to_admin = has_eid("4728", "4732", "4756")
    if created and to_admin:
        findings.append({"id": "account_manipulation", "title": "New account added to privileged group",
                         "severity": "high", "mitre": "T1136.001",
                         "detail": "A user account was created (4720) and added to an admin group (4732/4728).",
                         "evidence": "4720+4732"})
    elif to_admin:
        findings.append({"id": "privileged_group_change", "title": "Privileged group membership change",
                         "severity": "medium", "mitre": "T1098",
                         "detail": "A member was added to a security-enabled admin group.",
                         "evidence": "4732/4728"})
    if has_eid("4697", "7045", "4698"):
        findings.append({"id": "persistence", "title": "Service / scheduled task installed",
                         "severity": "high", "mitre": "T1543.003",
                         "detail": "A new service or scheduled task was created (persistence).",
                         "evidence": "4697/7045/4698"})
    # Sysmon remote thread => injection.
    if [e for e in enriched if e.get("source") == "sysmon" and str(e.get("event_id")) == "8"]:
        findings.append({"id": "process_injection", "title": "Possible process injection",
                         "severity": "high", "mitre": "T1055",
                         "detail": "Sysmon event 8 (CreateRemoteThread).", "evidence": "sysmon:8"})
    # Palo Alto threats.
    threats = [e for e in enriched if e.get("source") == "palo-alto"
               and str(e.get("event_id")).upper() == "THREAT"]
    if threats:
        sev = "high"
        for e in threats:
            sev = knowledge.worst(sev, e["sig"]["severity"])
        findings.append({"id": "firewall_threat", "title": "Firewall detected threat(s)",
                         "severity": sev, "mitre": "T1190",
                         "detail": f"{len(threats)} Palo Alto THREAT log(s).", "evidence": "THREAT"})
    return findings
