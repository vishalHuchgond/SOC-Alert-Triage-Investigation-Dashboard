"""End-to-end SOC triage pipeline: detection -> correlation -> IOC extraction -> incident escalation."""
from __future__ import annotations

from typing import Any

from bson import ObjectId
from config.settings import get_settings
from correlation.correlator import correlate
from database.mongodb import MongoStore
from detection.engine import run_detections
from incidents.incident_manager import create_from_alert
from ioc.extractor import extract, is_enrichable
from threat_intel.watchlist import lookup as watchlist_lookup


def sync_all_iocs(store: MongoStore) -> int:
    """Extract, store, and enrich IOCs from all events and alerts."""
    ttl = get_settings().ioc_cache_ttl_hours
    alerts = store.list_alerts(limit=5000)
    synced = 0

    for alert in alerts:
        event_ids = alert.get("event_ids", [])
        obj_ids = []
        for eid in event_ids:
            try:
                obj_ids.append(ObjectId(eid))
            except Exception:
                pass

        events = list(store.db.events.find({"_id": {"$in": obj_ids}})) if obj_ids else []

        text_parts = [
            str(alert.get("source_ip") or ""),
            str(alert.get("destination_ip") or ""),
            str(alert.get("description") or ""),
        ]
        for e in events:
            text_parts.extend([
                str(e.get("source_ip") or ""),
                str(e.get("destination_ip") or ""),
                str(e.get("command") or ""),
                str(e.get("message") or ""),
                str(e.get("raw_event") or ""),
            ])

        blob = " ".join(part for part in text_parts if part)
        found = extract(blob)

        if found.iocs:
            ioc_vals = []
            for item in found.iocs:
                val = item["value"]
                ioc_vals.append(val)
                cached = store.cache_get(val, ttl)
                wl = watchlist_lookup(val)
                rep, source = "unknown", "Not enriched"
                if cached:
                    rep, source = cached.get("reputation", "unknown"), cached.get("source", "Not enriched")
                elif wl:
                    rep, source = wl.get("severity", "suspicious"), "Local watchlist"
                elif not is_enrichable(item):
                    source, rep = "Not enriched (internal/private)", "unknown"

                store.upsert_iocs([{
                    "type": item["type"],
                    "value": val,
                    "first_seen": alert.get("earliest"),
                    "last_seen": alert.get("latest"),
                }])
                store.update_ioc(val, {"reputation": rep, "intel_source": source})
                synced += 1

            store.link_iocs_to_alert(alert["alert_id"], ioc_vals)

    return synced


def auto_escalate_incidents(store: MongoStore, min_risk: int = 70) -> list[dict]:
    """Automatically create incidents for high-risk, critical, or chain-correlated alerts."""
    created_incidents = []
    alerts = store.list_alerts(limit=5000)

    # 1. Group correlated alerts that share an attack chain or high severity
    for alert in alerts:
        if alert.get("incident_id"):
            continue

        risk = int(alert.get("risk_score", 0))
        severity = str(alert.get("severity", "low")).lower()
        has_group = bool(alert.get("correlation_group"))

        # Escalate if critical, risk >= threshold, or high with correlation
        if severity == "critical" or risk >= min_risk or (severity == "high" and has_group):
            title = f"{alert.get('detection_name', 'Threat').replace('_', ' ').title()} on {alert.get('hostname') or alert.get('source_ip') or 'Asset'}"
            inc = create_from_alert(store, alert["alert_id"], title=title)
            if inc:
                # Add evidence item for original alert
                store.add_evidence({
                    "incident_id": inc["incident_id"],
                    "type": "Alert",
                    "description": f"Initial triggering alert: {alert['alert_id']} ({alert.get('detection_name')})",
                    "source": alert["alert_id"],
                    "timestamp": alert.get("created_at"),
                })
                # If there's a correlation group, link peer alerts to this incident
                if alert.get("correlation_group"):
                    grp = store.get_correlation_group(alert["correlation_group"])
                    if grp:
                        peer_ids = [aid for aid in grp.get("alert_ids", []) if aid != alert["alert_id"]]
                        for peer_id in peer_ids:
                            peer = store.get_alert(peer_id)
                            if peer and not peer.get("incident_id"):
                                store.db.alerts.update_one(
                                    {"alert_id": peer_id},
                                    {"$set": {"incident_id": inc["incident_id"], "status": "Resolved"}},
                                )
                                store.db.incidents.update_one(
                                    {"incident_id": inc["incident_id"]},
                                    {"$addToSet": {"alert_ids": peer_id}},
                                )
                created_incidents.append(inc)

    return created_incidents


def run_full_pipeline(store: MongoStore, auto_incidents: bool = True) -> dict[str, Any]:
    """Run detection -> correlation -> IOC intelligence -> incident triage in sequence."""
    det_stats = run_detections(store)
    corr_stats = correlate(store)
    iocs_count = sync_all_iocs(store)
    incidents = auto_escalate_incidents(store) if auto_incidents else []

    return {
        "alerts_created": det_stats.get("alerts_created", 0),
        "alerts_suppressed": det_stats.get("alerts_suppressed", 0),
        "events_analyzed": det_stats.get("events_analyzed", 0),
        "correlation_groups": corr_stats.get("groups_created", 0),
        "attack_chains": corr_stats.get("attack_chains_found", 0),
        "iocs_extracted": iocs_count,
        "incidents_created": len(incidents),
    }
