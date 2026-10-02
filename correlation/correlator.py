"""Alert correlation and attack-chain detection.

- Groups alerts sharing an entity (source IP, username, hostname) in a 24h window
- Detects ordered attack chains per entity (e.g. spray -> success -> account
  creation -> scheduled task -> log clearing)
- Deterministic group IDs (CORR-001); correlation adds a risk factor and can
  suggest creating an incident
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from utils.time import epoch_seconds, utcnow

WINDOW_HOURS = 24

CHAINS: list[dict] = [
    {
        "name": "Account takeover & persistence chain",
        "sequence": ["password_spray", "success_after_failures", "account_creation",
                     "scheduled_task_creation", "security_log_clearing"],
    },
    {
        "name": "Intrusion & anti-forensics chain",
        "sequence": ["brute_force", "success_after_failures",
                     "suspicious_process_execution", "security_log_clearing"],
    },
]


def _window_cutoff() -> str:
    from datetime import datetime, timezone
    return (datetime.now(timezone.utc) - timedelta(hours=WINDOW_HOURS)).isoformat(timespec="seconds")


def _is_subsequence(sequence: list[str], events: list[str]) -> bool:
    it = iter(events)
    return all(any(e == s for e in it) for s in sequence)


def correlate(store) -> dict[str, int]:
    alerts = store.list_alerts({"created_at": {"$gte": _window_cutoff()}})
    groups_saved = chains_found = 0

    for field in ("source_ip", "username", "hostname"):
        by_value: dict[str, list[dict]] = {}
        for a in alerts:
            v = a.get(field)
            if v:
                by_value.setdefault(v, []).append(a)

        for value, group in by_value.items():
            if len(group) < 2:
                continue
            group.sort(key=lambda a: a.get("earliest") or a.get("created_at") or "")
            alert_ids = [a["alert_id"] for a in group]

            # attack chain check on this entity
            detection_order = [a["detection_name"] for a in group]
            matched = [c["name"] for c in CHAINS
                       if _is_subsequence(c["sequence"], detection_order)]

            existing = store.db.correlation_groups.find_one(
                {"entity_field": field, "entity_value": value,
                 "alert_ids": {"$all": alert_ids}}
            )
            doc: dict[str, Any] = {
                "entity_field": field,
                "entity_value": value,
                "alert_count": len(group),
                "alert_ids": alert_ids,
                "detections": sorted({a["detection_name"] for a in group}),
                "window_hours": WINDOW_HOURS,
                "first_seen": group[0].get("earliest"),
                "last_seen": group[-1].get("latest"),
                "attack_chains": matched,
            }
            if existing:
                doc["group_id"] = existing["group_id"]
            saved = store.save_correlation_group(doc)
            groups_saved += 0 if existing else 1
            if matched:
                chains_found += 1

            for a in group:
                updates = {"correlation_group": saved["group_id"]}
                if not a.get("correlation_group"):
                    score = min(int(a.get("risk_score", 0)) + 10, 100)
                    bd = list(a.get("risk_breakdown", []))
                    if not any("correlated" in line for line in bd):
                        bd.append("+10 Part of correlated activity")
                    updates.update({"risk_score": score, "risk_breakdown": bd})
                store.db.alerts.update_one({"alert_id": a["alert_id"]}, {"$set": updates})

    return {"groups_created": groups_saved, "attack_chains_found": chains_found,
            "alerts_correlated": len(alerts)}
