"""JSON parsing for Sysmon JSON exports (single object, array, or NDJSON)."""
from __future__ import annotations

import json

from parser.normalizer import normalize_record


def parse_json(content: bytes, fmt: str, file_hash: str, max_rows: int) -> tuple[list[dict], int]:
    text = content.decode("utf-8", "replace")
    records: list[dict] = []
    stripped = text.strip()
    try:
        if stripped.startswith("["):
            data = json.loads(stripped)
            records = data if isinstance(data, list) else [data]
        elif "\n" in stripped:
            for line in stripped.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    records.append(json.loads(line))
        else:
            records = [json.loads(stripped)]
    except json.JSONDecodeError:
        return [], 0

    events, malformed = [], 0
    for i, rec in enumerate(records[:max_rows], start=1):
        try:
            events.append(normalize_record(rec, fmt, file_hash, i, json.dumps(rec)[:4000]))
        except Exception:
            malformed += 1
    return events, malformed
