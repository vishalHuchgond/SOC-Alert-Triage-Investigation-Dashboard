"""Shared detection plumbing: rule decorator and sliding-window helpers.

Windowing logic: events are sorted chronologically; two pointers (lo/hi) slide
over the list maintaining a window of at most `window_s` seconds. The first
window reaching the threshold is returned as evidence.
"""
from __future__ import annotations

from typing import Any, Callable

import pandas as pd

from utils.time import epoch_seconds


def rule(fn: Callable) -> Callable:
    """Mark a function as a detection rule: (df, cfg) -> list[alert dict]."""
    fn._is_rule = True  # type: ignore[attr-defined]
    return fn


def first_window(times: list[tuple[Any, float]], window_s: int, threshold: int) -> list[Any]:
    """Return ids from the first chronological window reaching threshold, else []."""
    ordered = sorted(times, key=lambda t: t[1])
    lo = 0
    for hi in range(len(ordered)):
        while ordered[hi][1] - ordered[lo][1] > window_s:
            lo += 1
        if hi - lo + 1 >= threshold:
            return [eid for eid, _ in ordered[lo:hi + 1]]
    return []


def first_window_distinct(times_users: list[tuple[Any, float, str]],
                          window_s: int, distinct: int) -> list[Any]:
    """Window variant keyed on distinct usernames (password spray)."""
    ordered = sorted(times_users, key=lambda t: t[1])
    lo = 0
    counts: dict[str, int] = {}
    for hi in range(len(ordered)):
        eid, ts, user = ordered[hi]
        counts[user] = counts.get(user, 0) + 1
        while ordered[hi][1] - ordered[lo][1] > window_s:
            old_user = ordered[lo][2]
            counts[old_user] -= 1
            if counts[old_user] <= 0:
                del counts[old_user]
            lo += 1
        if len(counts) >= distinct:
            return [e[0] for e in ordered[lo:hi + 1]]
    return []


def col(df: pd.DataFrame, name: str) -> pd.Series:
    return df[name] if name in df.columns else pd.Series([None] * len(df))


def timed(df: pd.DataFrame) -> pd.DataFrame:
    """Attach epoch seconds column for windowing; drops unparseable timestamps."""
    out = df.copy()
    out["_ts"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    out = out.dropna(subset=["_ts"])
    out["_epoch"] = out["_ts"].astype("int64") // 10**9
    return out


def make_result(rule_name: str, severity: str, description: str, mitre_id: str,
                rows: pd.DataFrame, group_key: str, extra: dict | None = None) -> dict:
    source_ip_s = col(rows, "source_ip").dropna()
    dest_ip_s = col(rows, "destination_ip").dropna()
    username_s = col(rows, "username").dropna()
    hostname_s = col(rows, "hostname").dropna()

    earliest = str(rows["_ts"].min()) if "_ts" in rows.columns and not rows["_ts"].empty else None
    latest = str(rows["_ts"].max()) if "_ts" in rows.columns and not rows["_ts"].empty else None

    r = {
        "detection_name": rule_name,
        "severity": severity,
        "description": description,
        "mitre_id": mitre_id,
        "event_ids": [str(i) for i in rows["_id"].tolist()] if "_id" in rows.columns else [],
        "group_key": group_key,
        "source_ip": source_ip_s.iloc[0] if len(source_ip_s) > 0 else None,
        "destination_ip": dest_ip_s.iloc[0] if len(dest_ip_s) > 0 else None,
        "username": username_s.iloc[0] if len(username_s) > 0 else None,
        "hostname": hostname_s.iloc[0] if len(hostname_s) > 0 else None,
        "repeat_count": len(rows),
        "earliest": earliest,
        "latest": latest,
        "extra": extra or {},
    }
    return r


def auths(df: pd.DataFrame, status: str) -> pd.DataFrame:
    """Authentication events with normalized status."""
    d = timed(df)
    d = d[(col(d, "event_type") == "authentication") & (col(d, "status") == status)]
    return d[col(d, "source_ip").notna() | col(d, "username").notna()]
