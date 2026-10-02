"""Line-based parsers for Linux auth.log (syslog) and Apache access logs."""
from __future__ import annotations

import re

from parser.normalizer import normalize_record

_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
_APACHE_RE = re.compile(
    r'^(?P<source_ip>\S+)\s+\S+\s+(?P<username>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+\S+'
)


def parse_syslog(content: bytes, file_hash: str, max_rows: int) -> tuple[list[dict], int]:
    text = content.decode("utf-8", "replace")
    events, malformed = [], 0
    for i, line in enumerate(text.splitlines()[:max_rows], start=1):
        line = line.rstrip("\n")
        if not line.strip():
            continue
        m = _SYSLOG_RE.match(line)
        if not m:
            malformed += 1
            continue
        rec = m.groupdict()
        rec["message"] = rec.pop("message")
        try:
            events.append(normalize_record(rec, "linux_syslog", file_hash, i, line))
        except Exception:
            malformed += 1
    return events, malformed


def parse_apache(content: bytes, file_hash: str, max_rows: int) -> tuple[list[dict], int]:
    text = content.decode("utf-8", "replace")
    events, malformed = [], 0
    for i, line in enumerate(text.splitlines()[:max_rows], start=1):
        if not line.strip():
            continue
        m = _APACHE_RE.match(line)
        if not m:
            malformed += 1
            continue
        g = m.groupdict()
        parts = g["request"].split()
        rec = {
            "timestamp": g["ts"], "source_ip": g["source_ip"],
            "username": None if g["username"] == "-" else g["username"],
            "url": parts[1] if len(parts) > 1 else g["request"],
            "process": parts[0] if parts else None,
            "status": g["status"], "message": g["request"],
            "event_type": "web",
        }
        try:
            events.append(normalize_record(rec, "apache", file_hash, i, line))
        except Exception:
            malformed += 1
    return events, malformed


PARSERS = {
    "linux_syslog": parse_syslog,
    "apache": parse_apache,
}
