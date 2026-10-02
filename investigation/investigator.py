"""Investigation workflow: validated status transitions, verdicts with required
reasoning, and a full audit history."""
from __future__ import annotations

from config.settings import get_settings
from database.mongodb import MongoStore

STATUSES = ["New", "Investigating", "Resolved", "Closed"]
VERDICTS = ["True Positive", "False Positive", "Benign"]

VALID_TRANSITIONS = {
    "New": {"Investigating", "Closed"},
    "Investigating": {"Resolved", "Closed", "New"},
    "Resolved": {"Closed", "Investigating"},
    "Closed": {"New"},
}


def _actor() -> str:
    return get_settings().analyst_name


def set_status(store: MongoStore, alert_id: str, new_status: str,
               reason: str = "") -> tuple[bool, str]:
    alert = store.get_alert(alert_id)
    if not alert:
        return False, "Alert not found."
    current = alert.get("status", "New")
    if new_status not in STATUSES:
        return False, f"Invalid status '{new_status}'."
    if new_status == current:
        return True, "Status unchanged."
    if new_status not in VALID_TRANSITIONS.get(current, set()):
        return False, f"Cannot move from '{current}' to '{new_status}'."
    store.update_alert(alert_id, {"status": new_status})
    store.add_history({"alert_id": alert_id, "actor": _actor(), "action": "status",
                       "old": current, "new": new_status, "reason": reason})
    return True, f"Status updated: {current} -> {new_status}"


def set_verdict(store: MongoStore, alert_id: str, verdict: str,
                reasoning: str) -> tuple[bool, str]:
    if verdict not in VERDICTS:
        return False, f"Invalid verdict '{verdict}'."
    if not reasoning or len(reasoning.strip()) < 5:
        return False, "Verdict reasoning is required (minimum 5 characters)."
    alert = store.get_alert(alert_id)
    if not alert:
        return False, "Alert not found."
    old = alert.get("verdict")
    store.update_alert(alert_id, {"verdict": verdict, "verdict_reason": reasoning.strip()})
    store.add_history({"alert_id": alert_id, "actor": _actor(), "action": "verdict",
                       "old": old, "new": verdict, "reason": reasoning.strip()})
    return True, f"Verdict recorded: {verdict}"


def add_note(store: MongoStore, alert_id: str, text: str) -> tuple[bool, str]:
    if not text or not text.strip():
        return False, "Note cannot be empty."
    actor = _actor()
    store.add_note({"alert_id": alert_id, "author": actor, "text": text.strip()})
    store.add_history({"alert_id": alert_id, "actor": actor, "action": "note",
                       "old": None, "new": "note added", "reason": ""})
    store.add_timeline({"entity_type": "alert", "entity_id": alert_id,
                        "entry_type": "analyst_action", "event_time": None,
                        "description": f"{actor} added a note"})
    return True, "Note added."
