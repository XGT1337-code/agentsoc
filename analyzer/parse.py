"""Parse dropped real logs into normalized records.

Handles the formats a SOC actually receives: Windows event text/CSV, JSON or
NDJSON (Splunk / Shuffle exports), CEF and LEEF (QRadar / ArcSight), Palo Alto
comma-separated logs, and Linux auth (sshd/sudo) syslog lines. Unknown lines are
kept too, so nothing is silently dropped.

A record is: {raw, source, event_id, fields}.
"""
from __future__ import annotations

import csv
import io
import json
import re

from analyzer import knowledge

_EVENT_ID_KEYS = ("eventid", "event_id", "eventcode", "id", "signature_id", "signatureid")
_USER_KEYS = ("targetusername", "user", "username", "account", "subjectusername", "suser")
_IP_KEYS = ("ipaddress", "src_ip", "src", "source_ip", "srcip", "client_ip", "ip")
_HOST_KEYS = ("computer", "host", "hostname", "dvchost", "machine")


def _lc(d: dict) -> dict:
    return {str(k).lower().replace(" ", "_"): v for k, v in d.items()}


def _pick(d: dict, keys) -> str | None:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return str(d[k])
    return None


def _event_from_obj(obj: dict) -> dict:
    low = _lc(obj)
    eid = _pick(low, _EVENT_ID_KEYS)
    src = "unknown"
    chan = str(low.get("channel", "") or low.get("source", "") or low.get("product", "")).lower()
    if "sysmon" in chan:
        src = "sysmon"
    elif "security" in chan or "windows" in chan or (eid and eid in knowledge.WINDOWS):
        src = "windows"
    elif "pan" in chan or "palo" in chan:
        src = "palo-alto"
    fields = {
        "user": _pick(low, _USER_KEYS),
        "ip": _pick(low, _IP_KEYS),
        "host": _pick(low, _HOST_KEYS),
        "action": low.get("action"),
        "subtype": low.get("subtype") or low.get("type"),
        "severity": low.get("severity"),
        "process": low.get("newprocessname") or low.get("image") or low.get("process"),
    }
    return {"raw": json.dumps(obj, ensure_ascii=False)[:500], "source": src,
            "event_id": eid, "fields": {k: v for k, v in fields.items() if v}}


def _try_json(text: str) -> list[dict] | None:
    t = text.strip()
    if not t:
        return None
    # Whole-document JSON (object or array).
    if t[0] in "[{":
        try:
            data = json.loads(t)
            if isinstance(data, dict):
                data = data.get("events") or data.get("results") or data.get("data") or [data]
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return [_event_from_obj(o) for o in data if isinstance(o, dict)]
        except ValueError:
            pass
    # NDJSON (one JSON object per line).
    lines = [ln for ln in t.splitlines() if ln.strip().startswith("{")]
    if lines and len(lines) >= max(1, t.count("\n") // 2):
        out = []
        for ln in lines:
            try:
                out.append(_event_from_obj(json.loads(ln)))
            except ValueError:
                continue
        if out:
            return out
    return None


_KV_RE = re.compile(r'([A-Za-z][\w.-]*)=("?)([^"]*?)\2(?:\s|$)')


def _kv(line: str) -> dict:
    return {m.group(1).strip().lower().replace(" ", "_"): m.group(3)
            for m in _KV_RE.finditer(line)}


def _parse_cef_leef(line: str) -> dict | None:
    if line.startswith("CEF:"):
        parts = line.split("|")
        if len(parts) >= 7:
            ext = _kv(parts[7]) if len(parts) > 7 else {}
            return {"raw": line[:500], "source": "cef", "event_id": parts[4].strip(),
                    "fields": {"name": parts[5], "severity": parts[6],
                               "ip": _pick(ext, _IP_KEYS), "user": _pick(ext, _USER_KEYS)}}
    if line.startswith("LEEF:"):
        parts = line.split("|")
        if len(parts) >= 5:
            tail = "|".join(parts[5:])
            ext = _kv(tail.replace("\t", " "))
            return {"raw": line[:500], "source": "leef", "event_id": parts[4].strip(),
                    "fields": {"ip": _pick(ext, _IP_KEYS), "user": _pick(ext, _USER_KEYS),
                               "action": ext.get("action")}}
    return None


def _parse_palo_csv(line: str) -> dict | None:
    cols = next(csv.reader([line]), [])
    types = [c for c in cols if c.strip().upper() in knowledge.PALO_TYPES]
    if not types:
        return None
    try:
        i = next(j for j, c in enumerate(cols) if c.strip().upper() in knowledge.PALO_TYPES)
    except StopIteration:
        return None
    subtype = cols[i + 1].strip() if i + 1 < len(cols) else ""
    # Action/severity vary by PAN-OS version; scan remaining cols heuristically.
    action = next((c for c in cols if c.strip().lower() in
                   ("allow", "deny", "drop", "reset-both", "alert", "block")), "")
    severity = next((c for c in cols if c.strip().lower() in
                     ("critical", "high", "medium", "low", "informational")), "")
    return {"raw": line[:500], "source": "palo-alto", "event_id": types[0].strip().upper(),
            "fields": {"subtype": subtype, "action": action, "severity": severity}}


_WIN_ID_RE = re.compile(r"(?:event\s*id|eventid|eventcode)\s*[:=]\s*(\d{3,5})", re.I)


def _parse_text_line(line: str) -> dict | None:
    s = line.strip()
    if not s:
        return None
    cef = _parse_cef_leef(s)
    if cef:
        return cef
    palo = _parse_palo_csv(s)
    if palo:
        return palo
    m = _WIN_ID_RE.search(s)
    if m:
        kv = _kv(s)
        return {"raw": s[:500], "source": "windows", "event_id": m.group(1),
                "fields": {"user": _pick(kv, _USER_KEYS), "ip": _pick(kv, _IP_KEYS),
                           "host": _pick(kv, _HOST_KEYS)}}
    for pat, sig in knowledge.LINUX_PATTERNS:
        if re.search(pat, s):
            ipm = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", s)
            um = re.search(r"(?:user|for)\s+(\w+)", s)
            return {"raw": s[:500], "source": "linux-auth", "event_id": None,
                    "fields": {"ip": ipm.group(1) if ipm else None,
                               "user": um.group(1) if um else None, "_linux_sig": sig}}
    return {"raw": s[:500], "source": "unknown", "event_id": None, "fields": {}}


def _try_csv(text: str) -> list[dict] | None:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2 or "," not in lines[0]:
        return None
    header = [h.strip().lower().replace(" ", "_") for h in next(csv.reader([lines[0]]), [])]
    if not any(h in _EVENT_ID_KEYS for h in header):
        return None
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        out.append(_event_from_obj({k: v for k, v in row.items() if k}))
    return out or None


def parse(text: str) -> list[dict]:
    """Parse arbitrary log text into normalized records."""
    if not text or not text.strip():
        return []
    for parser in (_try_json, _try_csv):
        recs = parser(text)
        if recs:
            return recs
    out = []
    for line in text.splitlines():
        rec = _parse_text_line(line)
        if rec:
            out.append(rec)
    return out
