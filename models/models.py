"""Shared data contracts (dataclasses) used across every module."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Event:
    """Normalized log event (loosely follows Elastic Common Schema naming)."""
    timestamp: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: str | None = None
    destination_port: str | None = None
    username: str | None = None
    domain: str | None = None
    hostname: str | None = None
    event_id: str | None = None
    event_type: str | None = None
    logon_type: str | None = None
    status: str | None = None
    process: str | None = None
    process_id: str | None = None
    parent_process: str | None = None
    command: str | None = None
    message: str | None = None
    file_hash: str | None = None
    url: str | None = None
    log_source: str | None = None
    raw_event: str | None = None
    source_file_id: str | None = None
    line_number: int | None = None
    event_hash: str | None = None

    def to_mongo(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class DetectionResult:
    """Structured output of a detection rule (one alert per group)."""
    rule: str
    severity: str
    description: str
    mitre_id: str
    event_ids: list[str]
    group_key: str
    source_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    repeat_count: int = 1
    decoded_command: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_alert(self) -> dict[str, Any]:
        d = asdict(self)
        d["detection_name"] = d.pop("rule")
        return d


@dataclass
class EnrichmentResult:
    """Threat-intelligence result for one IOC."""
    ioc_value: str
    ioc_type: str
    source: str = "Not enriched"     # VirusTotal | Local watchlist | Not enriched
    reputation: str = "unknown"      # malicious | suspicious | clean | unknown
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    total: int = 0
    reason: str = ""


@dataclass
class IOC:
    type: str           # ipv4 | ipv6 | domain | url | md5 | sha1 | sha256
    value: str
    first_seen: str | None = None
    last_seen: str | None = None
    alert_ids: list[str] = field(default_factory=list)
