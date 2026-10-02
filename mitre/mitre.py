"""MITRE ATT&CK mapping helpers."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

MAPPING_PATH = Path(__file__).resolve().parent / "mapping.json"


@lru_cache(maxsize=1)
def load_mapping() -> dict:
    with open(MAPPING_PATH, encoding="utf-8") as f:
        return json.load(f)


def technique(tid: str) -> dict | None:
    return load_mapping().get(tid)


def technique_label(tid: str) -> str:
    t = technique(tid)
    return f"{tid} / {t['name']}" if t else (tid or "Unmapped")


def coverage() -> dict:
    """Group techniques by tactic for the coverage page."""
    by_tactic: dict[str, list[dict]] = {}
    for tid, t in load_mapping().items():
        for tactic in t["tactics"]:
            by_tactic.setdefault(tactic, []).append({"id": tid, **t})
    for tid_list in by_tactic.values():
        tid_list.sort(key=lambda x: x["id"])
    return dict(sorted(by_tactic.items()))
