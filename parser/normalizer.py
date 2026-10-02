"""Normalize parsed records from every format into the common Event schema.

Timestamps are normalized to UTC ISO-8601. Missing fields stay absent (NULL).
Status values for authentication events are standardized to success/failure.
"""
from __future__ import annotations

import hashlib
from typing import Any

from config.settings import get_settings
from utils.time import parse_timestamp

AUTH_SUCCESS_IDS = {"4624", "4624", "528", "540"}
AUTH_FAILURE_IDS = {"4625", "529", "530", "531", "532", "533", "534", "535", "536", "537", "539"}

_EVENT_TYPE_BY_ID = {
    "4624": "authentication", "4625": "authentication",
    "4688": "process", "4720": "account_creation",
    "4698": "scheduled_task", "1102": "log_clearing",
    "1": "process", "3": "network",
    "4103": "powershell", "4104": "powershell",
    "104": "log_clearing",
}


def _first(record: dict[str, Any], *names: str) -> Any:
    low = {str(k).lower(): v for k, v in record.items()}
    for n in names:
        v = low.get(n.lower())
        if v not in (None, "", "-"):
            return v
    return None


def _event_hash(raw: str, file_hash: str, line: int) -> str:
    return hashlib.sha256(f"{file_hash}:{line}:{raw}".encode("utf-8", "replace")).hexdigest()


def normalize_record(record: dict[str, Any], fmt: str, file_hash: str,
                     line_number: int, raw: str) -> dict[str, Any]:
    """Map one parsed record to the normalized schema."""
    s = get_settings()
    ts = None
    if fmt == "linux_syslog":
        from datetime import datetime, timezone
        # e.g. "Oct  2 10:49:01" -> no year/timezone; take analyst-configured year, assume UTC
        raw_ts = str(_first(record, "timestamp") or "")
        try:
            dt = datetime.strptime(f"{s.syslog_year} {raw_ts}", "%Y %b %d %H:%M:%S")
            ts = dt.replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            ts = parse_timestamp(raw_ts)
    else:
        ts = parse_timestamp(str(_first(record, "timestamp", "time", "timecreated",
                                        "eventtime", "date", "@timestamp", "datetime") or ""))

    event_id = str(_first(record, "eventid", "event_id", "id") or "") or None
    username = _first(record, "targetusername", "username", "user", "account", "acct")
    source_ip = _first(record, "ipaddress", "source_ip", "src", "srcip", "clientip", "host")
    hostname = _first(record, "workstationname", "hostname", "computer", "host", "workstation")
    command = _first(record, "commandline", "command", "scriptblocktext", "message_text")
    process = _first(record, "image", "process", "processname", "newprocessname", "application")
    parent = _first(record, "parentimage", "parent_process", "parentprocessname", "creatorprocessname")
    message = _first(record, "message", "msg")

    status = _first(record, "status", "substatus", "result")
    event_type = _EVENT_TYPE_BY_ID.get(event_id or "", None)

    if fmt == "linux_syslog":
        msg = str(message or raw)
        if "sshd" in msg:
            event_type = "authentication"
            if "Accepted" in msg:
                status = "success"
            elif "Failed" in msg or "failure" in msg.lower():
                status = "failure"
            user = username or _syslog_user(msg)
            if user:
                username = user
            ip = _syslog_ip(msg)
            if ip:
                source_ip = ip
        elif "sudo" in msg:
            event_type = "privilege"
        elif "COMMAND" in msg:
            event_type = "process"

    if event_id in AUTH_SUCCESS_IDS:
        status = "success"
    elif event_id in AUTH_FAILURE_IDS:
        status = "failure"

    if event_type is None:
        event_type = str(_first(record, "event_type", "category") or "").lower() or None

    event = {
        "timestamp": ts,
        "source_ip": source_ip,
        "destination_ip": _first(record, "destinationip", "dest_ip", "dst", "dstip", "destination"),
        "source_port": _first(record, "sourceport", "src_port", "sport"),
        "destination_port": _first(record, "destinationport", "dest_port", "dst_port", "dstport", "dport"),
        "username": username,
        "domain": _first(record, "domain", "targetdomainname", "workstation"),
        "hostname": hostname,
        "event_id": event_id,
        "event_type": event_type,
        "logon_type": _first(record, "logontype"),
        "status": status,
        "process": _basename(process),
        "process_id": _first(record, "processid", "pid", "newprocessid"),
        "parent_process": _basename(parent),
        "command": command,
        "message": message if message != command else None,
        "file_hash": _first(record, "filehash", "hash", "sha256", "md5"),
        "url": _first(record, "url", "uri", "request"),
        "log_source": fmt,
        "raw_event": raw,
        "source_file_id": file_hash,
        "line_number": line_number,
        "event_hash": _event_hash(raw, file_hash, line_number),
    }
    return {k: v for k, v in event.items() if v not in (None, "")}


def _basename(path: Any) -> Any:
    if not path:
        return path
    return str(path).replace("\\", "/").split("/")[-1]


def _syslog_ip(msg: str) -> str | None:
    import re
    m = re.search(r"from (?:invalid user \S+ )?(\d{1,3}(?:\.\d{1,3}){3})", msg)
    return m.group(1) if m else None


def _syslog_user(msg: str) -> str | None:
    import re
    m = re.search(r"(?:for|user(?:name)?)[: ]+(?:invalid user )?([A-Za-z0-9._-]+)", msg)
    return m.group(1) if m else None
