"""Knowledge base of security log events.

Each signature tells AgentSOC what a raw log event *means*: a human name, the
outcome (success / failure / info), a severity, the MITRE ATT&CK technique and a
short description. This is what lets the analyzer say "4625 = failed logon" and
decide whether a dropped real log is normal or an attack.

Sources covered: Windows Security & System event logs, Sysmon, Palo Alto
NGFW (THREAT/TRAFFIC), and Linux auth (sshd/sudo) text lines.
"""
from __future__ import annotations

# outcome: "success" | "failure" | "info"
# severity: "info" | "low" | "medium" | "high" | "critical"
# key format: "<source>:<event_id>"
WINDOWS: dict[str, dict] = {
    "4624": {"name": "Successful logon", "outcome": "success", "severity": "info",
             "category": "authentication", "mitre": "T1078",
             "desc": "An account was successfully logged on."},
    "4625": {"name": "Failed logon", "outcome": "failure", "severity": "low",
             "category": "authentication", "mitre": "T1110",
             "desc": "An account failed to log on (wrong password / bad user)."},
    "4634": {"name": "Logoff", "outcome": "info", "severity": "info",
             "category": "authentication", "mitre": "", "desc": "An account was logged off."},
    "4647": {"name": "User-initiated logoff", "outcome": "info", "severity": "info",
             "category": "authentication", "mitre": "", "desc": "User initiated logoff."},
    "4648": {"name": "Logon with explicit credentials", "outcome": "info", "severity": "medium",
             "category": "lateral-movement", "mitre": "T1550",
             "desc": "A logon was attempted using explicit credentials (runas / pass-the-hash)."},
    "4672": {"name": "Special privileges assigned", "outcome": "info", "severity": "medium",
             "category": "privilege-escalation", "mitre": "T1078.002",
             "desc": "Admin-equivalent privileges assigned to a new logon."},
    "4688": {"name": "Process created", "outcome": "info", "severity": "info",
             "category": "execution", "mitre": "T1059",
             "desc": "A new process was created."},
    "4697": {"name": "Service installed", "outcome": "info", "severity": "high",
             "category": "persistence", "mitre": "T1543.003",
             "desc": "A service was installed on the system (common persistence)."},
    "4698": {"name": "Scheduled task created", "outcome": "info", "severity": "high",
             "category": "persistence", "mitre": "T1053.005",
             "desc": "A scheduled task was created (common persistence)."},
    "4719": {"name": "Audit policy changed", "outcome": "info", "severity": "high",
             "category": "defense-evasion", "mitre": "T1562.002",
             "desc": "System audit policy was changed."},
    "4720": {"name": "User account created", "outcome": "info", "severity": "medium",
             "category": "account-management", "mitre": "T1136.001",
             "desc": "A new user account was created."},
    "4722": {"name": "User account enabled", "outcome": "info", "severity": "low",
             "category": "account-management", "mitre": "T1098", "desc": "A user account was enabled."},
    "4724": {"name": "Password reset attempt", "outcome": "info", "severity": "medium",
             "category": "account-management", "mitre": "T1098", "desc": "An attempt to reset an account password."},
    "4725": {"name": "User account disabled", "outcome": "info", "severity": "low",
             "category": "account-management", "mitre": "", "desc": "A user account was disabled."},
    "4726": {"name": "User account deleted", "outcome": "info", "severity": "medium",
             "category": "account-management", "mitre": "T1531", "desc": "A user account was deleted."},
    "4728": {"name": "Member added to global group", "outcome": "info", "severity": "high",
             "category": "privilege-escalation", "mitre": "T1098",
             "desc": "A member was added to a security-enabled global group (e.g. Domain Admins)."},
    "4732": {"name": "Member added to local group", "outcome": "info", "severity": "high",
             "category": "privilege-escalation", "mitre": "T1098",
             "desc": "A member was added to a security-enabled local group (e.g. Administrators)."},
    "4740": {"name": "Account locked out", "outcome": "failure", "severity": "medium",
             "category": "authentication", "mitre": "T1110",
             "desc": "A user account was locked out (often brute force)."},
    "4756": {"name": "Member added to universal group", "outcome": "info", "severity": "high",
             "category": "privilege-escalation", "mitre": "T1098",
             "desc": "A member was added to a security-enabled universal group."},
    "4768": {"name": "Kerberos TGT requested", "outcome": "info", "severity": "info",
             "category": "authentication", "mitre": "", "desc": "A Kerberos authentication ticket (TGT) was requested."},
    "4769": {"name": "Kerberos service ticket requested", "outcome": "info", "severity": "low",
             "category": "authentication", "mitre": "T1558.003",
             "desc": "A Kerberos service ticket was requested (watch for Kerberoasting)."},
    "4771": {"name": "Kerberos pre-authentication failed", "outcome": "failure", "severity": "low",
             "category": "authentication", "mitre": "T1110",
             "desc": "Kerberos pre-authentication failed (bad password / AS-REP roasting)."},
    "4776": {"name": "NTLM credential validation", "outcome": "info", "severity": "low",
             "category": "authentication", "mitre": "", "desc": "The domain controller attempted to validate credentials (NTLM)."},
    "5140": {"name": "Network share accessed", "outcome": "info", "severity": "low",
             "category": "lateral-movement", "mitre": "T1021.002", "desc": "A network share object was accessed."},
    "5145": {"name": "Network share object checked", "outcome": "info", "severity": "low",
             "category": "lateral-movement", "mitre": "T1021.002", "desc": "A network share object was checked for access."},
    "1102": {"name": "Audit log cleared", "outcome": "info", "severity": "critical",
             "category": "defense-evasion", "mitre": "T1070.001",
             "desc": "The security audit log was cleared (strong anti-forensics signal)."},
    "7045": {"name": "Service installed (System)", "outcome": "info", "severity": "high",
             "category": "persistence", "mitre": "T1543.003",
             "desc": "A new service was installed in the system (System log)."},
}

SYSMON: dict[str, dict] = {
    "1": {"name": "Sysmon: process create", "outcome": "info", "severity": "info",
          "category": "execution", "mitre": "T1059", "desc": "Sysmon recorded a process creation."},
    "3": {"name": "Sysmon: network connection", "outcome": "info", "severity": "low",
          "category": "command-and-control", "mitre": "T1071", "desc": "Sysmon recorded a network connection."},
    "7": {"name": "Sysmon: image loaded", "outcome": "info", "severity": "low",
          "category": "defense-evasion", "mitre": "T1574", "desc": "A module/DLL was loaded."},
    "8": {"name": "Sysmon: remote thread created", "outcome": "info", "severity": "high",
          "category": "defense-evasion", "mitre": "T1055", "desc": "CreateRemoteThread (process injection)."},
    "11": {"name": "Sysmon: file created", "outcome": "info", "severity": "info",
           "category": "execution", "mitre": "T1105", "desc": "A file was created."},
    "13": {"name": "Sysmon: registry value set", "outcome": "info", "severity": "low",
           "category": "persistence", "mitre": "T1547", "desc": "A registry value was set."},
}

# Palo Alto / firewall log TYPES (sub-type/action give severity).
PALO_TYPES = {"THREAT", "TRAFFIC", "SYSTEM", "CONFIG", "WILDFIRE"}

# Linux auth text patterns (regex -> signature).
LINUX_PATTERNS = [
    (r"Failed password", {"name": "SSH failed password", "outcome": "failure", "severity": "low",
                          "category": "authentication", "mitre": "T1110", "source": "linux-auth",
                          "desc": "An SSH password authentication attempt failed."}),
    (r"Accepted password|Accepted publickey", {"name": "SSH successful login", "outcome": "success",
                          "severity": "info", "category": "authentication", "mitre": "T1078",
                          "source": "linux-auth", "desc": "An SSH login succeeded."}),
    (r"sudo:.*COMMAND=", {"name": "sudo command", "outcome": "info", "severity": "low",
                          "category": "privilege-escalation", "mitre": "T1548.003",
                          "source": "linux-auth", "desc": "A command was run via sudo."}),
    (r"authentication failure", {"name": "PAM authentication failure", "outcome": "failure",
                          "severity": "low", "category": "authentication", "mitre": "T1110",
                          "source": "linux-auth", "desc": "A PAM authentication attempt failed."}),
    (r"Invalid user", {"name": "SSH invalid user", "outcome": "failure", "severity": "low",
                          "category": "authentication", "mitre": "T1110", "source": "linux-auth",
                          "desc": "An SSH login used a non-existent user (scanning / brute force)."}),
]

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def lookup(source: str | None, event_id: str) -> dict | None:
    """Return the signature for an event id within a source family."""
    eid = str(event_id).strip()
    src = (source or "").lower()
    if src in ("sysmon",) and eid in SYSMON:
        return {**SYSMON[eid], "event_id": eid, "source": "sysmon"}
    if eid in WINDOWS:
        return {**WINDOWS[eid], "event_id": eid, "source": "windows"}
    if eid in SYSMON and src in ("sysmon", "", None):
        return {**SYSMON[eid], "event_id": eid, "source": "sysmon"}
    return None


def palo_signature(subtype: str, action: str, severity_field: str = "") -> dict:
    """Build a signature for a Palo Alto log line from its sub-type + action."""
    sub = (subtype or "").upper()
    act = (action or "").lower()
    sev = (severity_field or "").lower()
    if sub == "THREAT":
        severity = {"critical": "critical", "high": "high", "medium": "medium",
                    "low": "low", "informational": "info"}.get(sev, "high")
        return {"name": f"Palo Alto threat ({severity_field or 'threat'})", "outcome": "failure",
                "severity": severity, "category": "intrusion", "mitre": "T1190",
                "source": "palo-alto", "event_id": "THREAT",
                "desc": "Palo Alto NGFW detected a threat (IPS/AV/anti-spyware)."}
    if sub == "TRAFFIC":
        blocked = act in ("deny", "drop", "reset-both", "reset-server", "reset-client")
        return {"name": f"Palo Alto traffic {act or 'allow'}", "outcome": "info",
                "severity": "low" if blocked else "info", "category": "network",
                "mitre": "", "source": "palo-alto", "event_id": "TRAFFIC",
                "desc": f"Firewall {'blocked' if blocked else 'allowed'} a session."}
    return {"name": f"Palo Alto {sub or 'log'}", "outcome": "info", "severity": "info",
            "category": "network", "mitre": "", "source": "palo-alto", "event_id": sub or "LOG",
            "desc": "Palo Alto system/config log entry."}


def worst(a: str, b: str) -> str:
    """Return the higher of two severities."""
    ia = SEVERITY_ORDER.index(a) if a in SEVERITY_ORDER else 0
    ib = SEVERITY_ORDER.index(b) if b in SEVERITY_ORDER else 0
    return SEVERITY_ORDER[max(ia, ib)]
