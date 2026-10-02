"""Detection engine: runs enabled rules over an event batch and creates alerts.

- Rules operate on a DataFrame batch (windowed/grouped detections)
- Thresholds come from config/rules_config.yaml, never from code
- One alert per group, linked to contributing events
- Allowlist is applied before alert creation; suppressed counts are reported
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from config.settings import CONFIG_DIR
from database.mongodb import MongoStore
from detection import authentication, network, powershell, process, windows
from scoring.risk_score import score_alert
from threat_intel.watchlist import load_watchlist

RULE_MODULES = [authentication, powershell, process, network, windows]


def load_rules_config() -> dict[str, Any]:
    with open(CONFIG_DIR / "rules_config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def available_rules(cfg: dict | None = None) -> list[str]:
    cfg = cfg or load_rules_config()
    return sorted(cfg.get("rules", {}).keys())


def run_detections(store: MongoStore, query: dict | None = None,
                   config: dict | None = None) -> dict[str, int]:
    cfg = config or load_rules_config()
    rules_cfg = cfg.get("rules", {})
    df = store.events_df(query)
    results: list[dict] = []
    for module in RULE_MODULES:
        for name in dir(module):
            fn = getattr(module, name)
            if getattr(fn, "_is_rule", False) and rules_cfg.get(name, {}).get("enabled", True):
                try:
                    results.extend(fn(df, rules_cfg.get(name, {})))
                except Exception:
                    continue  # a broken rule must never crash the engine

    created = suppressed = 0
    watchlist = {w["value"] for w in load_watchlist()}
    critical_hosts = set(cfg.get("critical_assets", {}).get("hosts", []))
    critical_accounts = set(cfg.get("critical_assets", {}).get("accounts", []))

    for r in results:
        if store.is_allowlisted(r.get("source_ip"), r.get("username"), r.get("group_key")):
            suppressed += 1
            continue
        iocs = r.get("extra", {}).get("iocs", [])
        context = {
            "source_flagged": r.get("source_ip") in watchlist
                              or bool(iocs and set(iocs) & watchlist),
            "asset_critical": (r.get("hostname") in critical_hosts)
                              or (r.get("username") in critical_accounts),
            "ioc_reputation": None,
        }
        score, breakdown, confidence = score_alert(r, context)
        r["risk_score"] = score
        r["risk_breakdown"] = breakdown
        r["confidence"] = confidence
        store.create_alert(r)
        created += 1
    return {"alerts_created": created, "alerts_suppressed": suppressed,
            "events_analyzed": len(df)}
