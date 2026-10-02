"""Windows-specific detections: account creation, scheduled tasks, log clearing."""
from __future__ import annotations

import pandas as pd

from detection.helpers import col, make_result, rule, timed


@rule
def account_creation(df: pd.DataFrame, cfg: dict) -> list[dict]:
    d = timed(df)
    d = d[col(d, "event_id") == "4720"]
    out = []
    for _, row in d.iterrows():
        rows = d[d["_id"] == row["_id"]]
        out.append(make_result(
            "account_creation", cfg.get("severity", "medium"),
            f"New local account created: {row.get('username') or 'unknown'}.",
            cfg.get("mitre_id", "T1136.001"), rows,
            f"user:{row.get('username')}", extra={"new_account": row.get("username")}))
    return out


@rule
def scheduled_task_creation(df: pd.DataFrame, cfg: dict) -> list[dict]:
    d = timed(df)
    by_id = d[col(d, "event_id") == "4698"]
    cmd = col(d, "command").str.lower()
    by_cmd = d[cmd.str.contains("schtasks", na=False) & cmd.str.contains("/create", na=False)]
    hits = pd.concat([by_id, by_cmd]).drop_duplicates(subset="_id")
    out = []
    for host, g in hits.groupby("hostname"):
        out.append(make_result(
            "scheduled_task_creation", cfg.get("severity", "medium"),
            f"Scheduled task created on {host} (persistence mechanism).",
            cfg.get("mitre_id", "T1053.005"), g, f"host:{host}"))
    return out


@rule
def security_log_clearing(df: pd.DataFrame, cfg: dict) -> list[dict]:
    d = timed(df)
    hits = d[col(d, "event_id").isin(["1102", "104"])]
    out = []
    for host, g in hits.groupby("hostname"):
        out.append(make_result(
            "security_log_clearing", cfg.get("severity", "high"),
            f"Security event log cleared on {host} (anti-forensics).",
            cfg.get("mitre_id", "T1070.001"), g, f"host:{host}"))
    return out
