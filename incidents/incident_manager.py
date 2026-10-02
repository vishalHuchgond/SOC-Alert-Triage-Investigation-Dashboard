"""Incident lifecycle management."""
from __future__ import annotations

from config.settings import get_settings
from database.mongodb import MongoStore
from utils.time import utcnow

INCIDENT_STATUSES = ["Open", "Investigating", "Contained", "Resolved", "Closed"]
INCIDENT_TRANSITIONS = {
    "Open": {"Investigating", "Closed"},
    "Investigating": {"Contained", "Resolved", "Closed"},
    "Contained": {"Resolved", "Investigating"},
    "Resolved": {"Closed", "Investigating"},
    "Closed": {"Open"},
}

EVIDENCE_TYPES = ["Windows event log", "Network event", "IOC", "Process",
                  "Command", "Screenshot reference", "Other"]


def create_from_alert(store: MongoStore, alert_id: str, title: str,
                      analyst: str | None = None) -> dict | None:
    alert = store.get_alert(alert_id)
    if not alert:
        return None
    analyst = analyst or get_settings().analyst_name
    iocs = store.db.iocs.find({"alert_ids": alert_id})
    ioc_values = [i["value"] for i in iocs]
    inc = store.create_incident({
        "title": title or f"Incident from {alert_id}: {alert['detection_name']}",
        "severity": alert.get("severity", "medium"),
        "risk_score": alert.get("risk_score", 0),
        "analyst": analyst,
        "alert_ids": [alert_id],
        "ioc_values": ioc_values,
        "mitre_ids": [alert.get("mitre_id")] if alert.get("mitre_id") else [],
        "source_alert": alert_id,
    })
    store.add_history({"alert_id": alert_id, "actor": analyst, "action": "incident",
                       "old": None, "new": inc["incident_id"], "reason": "Incident created"})
    store.add_timeline({"entity_type": "incident", "entity_id": inc["incident_id"],
                        "entry_type": "system", "event_time": utcnow(),
                        "description": f"Incident created from {alert_id} by {analyst}"})
    store.add_timeline({"entity_type": "alert", "entity_id": alert_id,
                        "entry_type": "system", "event_time": utcnow(),
                        "description": f"Linked to incident {inc['incident_id']}"})
    return inc


def set_incident_status(store: MongoStore, incident_id: str, new_status: str) -> tuple[bool, str]:
    inc = store.get_incident(incident_id)
    if not inc:
        return False, "Incident not found."
    current = inc.get("status", "Open")
    if new_status not in INCIDENT_STATUSES:
        return False, f"Invalid status '{new_status}'."
    if new_status not in INCIDENT_TRANSITIONS.get(current, set()):
        return False, f"Cannot move from '{current}' to '{new_status}'."
    store.update_incident(incident_id, {"status": new_status})
    store.add_timeline({"entity_type": "incident", "entity_id": incident_id,
                        "entry_type": "analyst_action", "event_time": utcnow(),
                        "description": f"Status changed {current} -> {new_status} "
                                       f"by {get_settings().analyst_name}"})
    return True, f"Status updated: {current} -> {new_status}"


def add_incident_note(store: MongoStore, incident_id: str, text: str) -> tuple[bool, str]:
    if not text or not text.strip():
        return False, "Note cannot be empty."
    store.db.incidents.update_one(
        {"incident_id": incident_id},
        {"$push": {"notes": {"author": get_settings().analyst_name,
                             "text": text.strip(), "at": utcnow()}}})
    store.add_timeline({"entity_type": "incident", "entity_id": incident_id,
                        "entry_type": "analyst_action", "event_time": utcnow(),
                        "description": f"{get_settings().analyst_name} added a note"})
    return True, "Note added."
