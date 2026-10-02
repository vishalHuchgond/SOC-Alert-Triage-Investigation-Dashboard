"""Authentication detections: brute force, password spray, success after failures."""
from __future__ import annotations

import pandas as pd

from detection.helpers import (auths, first_window, first_window_distinct,
                               make_result, rule)


@rule
def brute_force(df: pd.DataFrame, cfg: dict) -> list[dict]:
    window = int(cfg.get("window_minutes", 10)) * 60
    threshold = int(cfg.get("threshold", 5))
    out = []
    for src, g in auths(df, "failure").groupby("source_ip"):
        ids = first_window([(i, t) for i, t in zip(g["_id"], g["_epoch"])], window, threshold)
        if ids:
            rows = g[g["_id"].astype(str).isin([str(x) for x in ids])]
            out.append(make_result(
                "brute_force", cfg.get("severity", "high"),
                f"{len(ids)} failed logins from {src} within {window // 60} minutes.",
                cfg.get("mitre_id", "T1110.001"), rows, f"src:{src}"))
    return out


@rule
def password_spray(df: pd.DataFrame, cfg: dict) -> list[dict]:
    window = int(cfg.get("window_minutes", 10)) * 60
    distinct = int(cfg.get("distinct_accounts", 5))
    out = []
    for src, g in auths(df, "failure").groupby("source_ip"):
        triples = [(i, t, str(u)) for i, t, u in zip(g["_id"], g["_epoch"], g["username"].fillna("?"))]
        ids = first_window_distinct(triples, window, distinct)
        if ids:
            rows = g[g["_id"].astype(str).isin([str(x) for x in ids])]
            n_users = rows["username"].nunique()
            out.append(make_result(
                "password_spray", cfg.get("severity", "high"),
                f"One source failing against {n_users} distinct accounts within {window // 60} minutes.",
                cfg.get("mitre_id", "T1110.003"), rows, f"src:{src}",
                extra={"targeted_accounts": sorted(rows["username"].dropna().unique().tolist())}))
    return out


@rule
def multiple_failed_logins(df: pd.DataFrame, cfg: dict) -> list[dict]:
    window = int(cfg.get("window_minutes", 10)) * 60
    threshold = int(cfg.get("threshold", 5))
    out = []
    for user, g in auths(df, "failure").groupby("username"):
        ids = first_window([(i, t) for i, t in zip(g["_id"], g["_epoch"])], window, threshold)
        if ids:
            rows = g[g["_id"].astype(str).isin([str(x) for x in ids])]
            out.append(make_result(
                "multiple_failed_logins", cfg.get("severity", "medium"),
                f"Account {user} had {len(ids)} failed logins within {window // 60} minutes.",
                cfg.get("mitre_id", "T1110"), rows, f"user:{user}", extra={"username": user}))
    return out


@rule
def success_after_failures(df: pd.DataFrame, cfg: dict) -> list[dict]:
    """A successful login (4624/Accepted) shortly after N failures from the same source."""
    window = int(cfg.get("window_minutes", 15)) * 60
    need = int(cfg.get("failure_threshold", 3))
    out = []
    for src, g in auths(df, "success").groupby("source_ip"):
        f = auths(df, "failure")
        f = f[f["source_ip"] == src]
        if len(f) < need:
            continue
        merged = first_window([(i, t) for i, t in zip(f["_id"], f["_epoch"])], window, need)
        if not merged:
            continue
        succ = g.sort_values("_epoch").iloc[[0]]
        evidence = f[f["_id"].astype(str).isin([str(x) for x in merged])]
        rows = pd.concat([evidence, succ])
        out.append(make_result(
            "success_after_failures", cfg.get("severity", "critical"),
            f"Successful login from {src} after {len(merged)} failed attempts - possible compromise.",
            cfg.get("mitre_id", "T1110"), rows, f"src:{src}",
            extra={"successful_user": succ["username"].iloc[0] if succ["username"].notna().any() else None}))
    return out
