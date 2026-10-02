"""Local watchlist loader (SAMPLE/OFFLINE data - no API key required)."""
from __future__ import annotations

import csv
from functools import lru_cache
from pathlib import Path

WATCHLIST_PATH = Path(__file__).resolve().parent / "watchlist.csv"


@lru_cache(maxsize=1)
def load_watchlist() -> list[dict]:
    if not WATCHLIST_PATH.exists():
        return []
    with open(WATCHLIST_PATH, newline="", encoding="utf-8") as f:
        return [dict(r) for r in csv.DictReader(f)]


def lookup(value: str) -> dict | None:
    v = (value or "").lower()
    for entry in load_watchlist():
        if entry["value"].lower() == v:
            return entry
    return None
