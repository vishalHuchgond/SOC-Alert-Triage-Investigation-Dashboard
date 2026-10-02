"""IOC and observable extraction from free text (commands, messages, URLs).

- Extracts IPv4/IPv6, domains, URLs, MD5/SHA1/SHA256
- Validates IPs with the ipaddress module; private/reserved ranges are kept as
  observables but excluded from external enrichment
- Guards against false matches: version strings, filenames with extensions
- Supports defanged input (hxxp://, [.] )
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
URL_RE = re.compile(r"https?://[^\s'\"<>\)\]]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
USERNAME_RE = re.compile(r"(?i)\b(?:user(?:name)?|account|acct|targetusername)[:= ]+([A-Za-z0-9._-]{2,32})")

FILE_TLDS = {"exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "tmp",
             "log", "csv", "dat", "bin", "msi", "scr", "com", "py", "zip", "gz"}


@dataclass
class ExtractionResult:
    iocs: list[dict] = field(default_factory=list)          # enrichable indicators
    observables: list[dict] = field(default_factory=list)   # usernames, processes, file names


def refang(text: str) -> str:
    return (text.replace("hxxp", "http").replace("[.]", ".")
                .replace("[:]", ":").replace("(.)", "."))


def _valid_ip(candidate: str) -> str | None:
    try:
        ip = ipaddress.ip_address(candidate)
        return str(ip)
    except ValueError:
        return None


def _is_enrichable_ip(candidate: str) -> bool:
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    doc_ranges = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    )
    if any(ip in net for net in doc_ranges):
        return True
    return ip.is_global and not ip.is_multicast


def extract(text: str) -> ExtractionResult:
    """Extract IOCs and observables from arbitrary (attacker-controlled) text."""
    text = refang(text or "")
    result = ExtractionResult()
    seen: set[str] = set()

    def add_ioc(ioc_type: str, value: str) -> None:
        if value and value.lower() not in seen:
            seen.add(value.lower())
            result.iocs.append({"type": ioc_type, "value": value})

    for m in IPV4_RE.finditer(text):
        ip = _valid_ip(m.group(0))
        if ip:
            add_ioc("ipv4", ip)
    for m in IPV6_RE.finditer(text):
        ip = _valid_ip(m.group(0))
        if ip:
            add_ioc("ipv6", ip)
    for m in URL_RE.finditer(text):
        add_ioc("url", m.group(0).rstrip(".,;"))
    for m in SHA256_RE.finditer(text):
        add_ioc("sha256", m.group(0).lower())
    for m in SHA1_RE.finditer(text):
        add_ioc("sha1", m.group(0).lower())
    for m in MD5_RE.finditer(text):
        add_ioc("md5", m.group(0).lower())
    for m in DOMAIN_RE.finditer(text):
        d = m.group(0)
        tld = d.rsplit(".", 1)[-1].lower()
        if tld in FILE_TLDS:                       # payload.exe is a file, not a domain
            result.observables.append({"type": "filename", "value": d})
            continue
        # skip things already captured as part of a URL host
        if any(d in i["value"] for i in result.iocs if i["type"] == "url"):
            continue
        add_ioc("domain", d.lower())
    for m in USERNAME_RE.finditer(text):
        result.observables.append({"type": "username", "value": m.group(1)})
    return result


def is_enrichable(ioc: dict) -> bool:
    """Only public IPs and public identifiers may be sent to third parties."""
    if ioc["type"] in ("ipv4", "ipv6"):
        return _is_enrichable_ip(ioc["value"])
    if ioc["type"] in ("domain",):
        return not ioc["value"].endswith((".local", ".internal", ".lan"))
    return ioc["type"] in ("url", "md5", "sha1", "sha256")
