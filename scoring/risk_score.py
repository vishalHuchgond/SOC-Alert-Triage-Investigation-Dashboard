"""Explainable, pluggable risk scoring (0-100).

Severity is set by the rule; risk score is computed here from independent
factors; confidence reflects evidence quality. Factors are a plain list so new
factors (IOC reputation, correlation) plug in without rewriting the module.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import yaml

from config.settings import CONFIG_DIR

FactorFn = Callable[[dict, dict, dict], tuple[int, str] | None]


def load_weights(path: Path | None = None) -> dict:
    with open(path or CONFIG_DIR / "scoring_weights.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _severity_factor(alert: dict, ctx: dict, w: dict) -> tuple[int, str] | None:
    sev = alert.get("severity", "low")
    pts = w["severity"].get(sev, 0)
    return (pts, f"+{pts} {sev.capitalize()} severity detection") if pts else None


def _repeat_factor(alert: dict, ctx: dict, w: dict) -> tuple[int, str] | None:
    n = min(max(int(alert.get("repeat_count", 1)) - 1, 0), w["repeat"]["max_extra_events"])
    if n <= 0:
        return None
    pts = n * w["repeat"]["points_per_event"]
    return pts, f"+{pts} Repeated activity ({alert.get('repeat_count', 1)} events)"


def _watchlist_factor(alert: dict, ctx: dict, w: dict) -> tuple[int, str] | None:
    if ctx.get("source_flagged"):
        pts = w["watchlist_hit"]
        return pts, f"+{pts} Source/IOC flagged in watchlist"
    return None


def _ioc_factor(alert: dict, ctx: dict, w: dict) -> tuple[int, str] | None:
    rep = ctx.get("ioc_reputation")
    if rep is None:
        return 0, "IOC reputation: not enriched"
    pts = w["ioc_reputation"].get(rep, 0)
    return (pts, f"+{pts} IOC reputation: {rep}") if pts else None


def _asset_factor(alert: dict, ctx: dict, w: dict) -> tuple[int, str] | None:
    if ctx.get("asset_critical"):
        pts = w["asset_criticality"]
        return pts, f"+{pts} Critical asset/account involved"
    return None


def _mitre_factor(alert: dict, ctx: dict, w: dict) -> tuple[int, str] | None:
    tid = alert.get("mitre_id")
    if tid:
        pts = w["mitre_mapped"]
        return pts, f"+{pts} MITRE {tid} mapped"
    return None


def _correlation_factor(alert: dict, ctx: dict, w: dict) -> tuple[int, str] | None:
    if alert.get("correlation_group"):
        pts = w["correlated"]
        return pts, f"+{pts} Part of correlated activity"
    return None


FACTORS: list[FactorFn] = [
    _severity_factor, _repeat_factor, _watchlist_factor, _ioc_factor,
    _asset_factor, _mitre_factor, _correlation_factor,
]


def score_alert(alert: dict, context: dict | None = None,
                weights: dict | None = None) -> tuple[int, list[str], str]:
    """Return (score 0-100, human-readable breakdown, confidence)."""
    w = weights or load_weights()
    ctx = context or {}
    breakdown: list[str] = []
    score = 0
    for factor in FACTORS:
        res = factor(alert, ctx, w)
        if res is None:
            continue
        pts, reason = res
        score += pts
        if reason:
            breakdown.append(reason)
    score = min(score, 100)

    if ctx.get("ioc_reputation") == "malicious" or int(alert.get("repeat_count", 1)) >= 5:
        confidence = "high"
    elif int(alert.get("repeat_count", 1)) >= 2 or ctx.get("source_flagged"):
        confidence = "medium"
    else:
        confidence = "low"
    return score, breakdown, confidence


def score_band(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"
