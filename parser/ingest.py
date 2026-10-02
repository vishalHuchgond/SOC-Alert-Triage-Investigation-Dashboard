"""End-to-end ingestion pipeline: bytes -> idempotent MongoDB events."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from config.settings import get_settings
from database.mongodb import MongoStore
from parser import csv_parser, json_parser, log_parser
from parser.detect_format import detect_format


@dataclass
class IngestResult:
    ok: bool
    message: str
    file_hash: str | None = None
    format: str | None = None
    events_inserted: int = 0
    events_duplicated: int = 0
    malformed_rows: int = 0


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def ingest_bytes(store: MongoStore, filename: str, content: bytes) -> IngestResult:
    s = get_settings()
    if len(content) > s.max_file_size_bytes:
        return IngestResult(False, f"File exceeds the {s.max_file_size_mb} MB upload limit.")
    if len(content) == 0:
        return IngestResult(False, "File is empty.")

    file_hash = sha256_bytes(content)
    existing = store.get_source_file_by_hash(file_hash)
    if existing:
        return IngestResult(True, f"File already ingested as '{existing.get('name')}'. "
                                  "No duplicate events created (idempotent ingestion).",
                            file_hash=file_hash, format=existing.get("format"))

    sample = content[:8192].decode("utf-8", "replace")
    fmt = detect_format(filename, sample)
    if fmt == "unsupported":
        return IngestResult(False, "Unsupported file format. Supported: Windows event CSV, "
                                   "Sysmon CSV/JSON, PowerShell log, Linux auth.log, "
                                   "Apache access log, firewall/connection CSV.")

    if fmt in ("windows_csv", "sysmon_csv", "powershell_csv", "firewall_csv"):
        events, malformed = csv_parser.parse_csv(content, fmt, file_hash, s.max_rows)
    elif fmt == "sysmon_json":
        events, malformed = json_parser.parse_json(content, fmt, file_hash, s.max_rows)
    else:
        events, malformed = log_parser.PARSERS[fmt](content, file_hash, s.max_rows)

    inserted, duplicates = store.insert_events(events)
    store.insert_source_file({
        "file_hash": file_hash,
        "name": filename,
        "size_bytes": len(content),
        "format": fmt,
        "row_count": len(events),
        "inserted": inserted,
        "duplicates": duplicates,
        "malformed_rows": malformed,
    })
    return IngestResult(True, f"Ingested {inserted} new events "
                              f"({duplicates} duplicates skipped, {malformed} malformed rows skipped).",
                        file_hash=file_hash, format=fmt,
                        events_inserted=inserted, events_duplicated=duplicates,
                        malformed_rows=malformed)
