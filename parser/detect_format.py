"""Automatic log format detection.

Returns a format name from SUPPORTED_FORMATS or "unsupported", never raises.
"""
from __future__ import annotations

import re

SUPPORTED_FORMATS = [
    "windows_csv", "sysmon_csv", "powershell_csv", "firewall_csv",
    "sysmon_json", "linux_syslog", "apache",
]

_APACHE_RE = re.compile(r'^\S+\s+\S+\s+\S+\s+\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}\]')
_SYSLOG_RE = re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+")


def _header_map(header: str) -> set[str]:
    return {h.strip().lower() for h in header.split(",")}


def detect_format(filename: str, sample_text: str) -> str:
    name = filename.lower()
    first = sample_text.lstrip()
    first_line = first.splitlines()[0] if first else ""

    # JSON payloads
    if first.startswith("{") or first.startswith("["):
        if '"eventid"' in first.lower() or '"commandline"' in first.lower() or '"image"' in first.lower():
            return "sysmon_json"
        return "unsupported"

    # Syslog / apache are line-structured, not CSV
    if _SYSLOG_RE.match(first_line):
        if "sshd" in first or "sudo" in first or "CRON" in first:
            return "linux_syslog"
        return "unsupported"
    if _APACHE_RE.match(first_line):
        return "apache"

    # CSV: classify by header columns
    if "," in first_line:
        cols = _header_map(first_line)
        if {"eventid", "targetusername", "ipaddress"} <= cols or {"eventid", "logontype"} <= cols:
            return "windows_csv"
        if "commandline" in cols and ("image" in cols or "parentimage" in cols):
            return "sysmon_csv"
        if "message" in cols and ("eventid" in cols or "id" in cols):
            return "powershell_csv"
        src_like = bool(cols & {"src", "src_ip", "source", "source_ip", "srcip"})
        dst_like = bool(cols & {"dst", "dst_ip", "destination", "destination_ip", "dstip"})
        if src_like and dst_like and (cols & {"action", "dst_port", "destination_port", "dstport"}):
            return "firewall_csv"

    if name.endswith(".log"):
        return "linux_syslog" if "sshd" in sample_text else "unsupported"
    return "unsupported"
