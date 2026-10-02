"""Incident report generation (self-contained HTML and Markdown via Jinja2).

All log-derived content is rendered through Jinja2 with autoescaping enabled,
so HTML output is escaped by construction. CSV exports go through csv_safe().
"""
from __future__ import annotations

import csv
import io
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from database.mongodb import MongoStore
from mitre.mitre import technique_label
from utils.sanitize import csv_safe

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(("html", "xml")),
    )


def gather(store: MongoStore, incident_id: str) -> dict | None:
    inc = store.get_incident(incident_id)
    if not inc:
        return None
    alerts = list(store.db.alerts.find({"alert_id": {"$in": inc.get("alert_ids", [])}}))
    for a in alerts:
        a["mitre_label"] = technique_label(a.get("mitre_id"))
        a["verdict_reason"] = a.get("verdict_reason") or "No verdict recorded."
    timeline = store.timeline_for("incident", incident_id)
    evidence = store.evidence_for(incident_id)
    iocs = list(store.db.iocs.find({"value": {"$in": inc.get("ioc_values", [])}}))
    for i in iocs:
        i["reputation"] = i.get("reputation", "unknown")
        i["intel_source"] = i.get("intel_source", "Not enriched")
    events = []
    from bson import ObjectId
    for a in alerts:
        raw_eids = a.get("event_ids", [])[:20]
        eids = [ObjectId(x) if ObjectId.is_valid(str(x)) else x for x in raw_eids]
        for e in store.db.events.find({"_id": {"$in": eids}}):
            e["_id"] = str(e["_id"])
            events.append(e)
    events.sort(key=lambda e: e.get("timestamp") or "")
    verdicts = [a.get("verdict") for a in alerts if a.get("verdict")]
    final_verdict = verdicts[0] if verdicts else "Pending"
    return {"incident": inc, "alerts": alerts, "timeline": timeline,
            "evidence": evidence, "iocs": iocs, "events": events,
            "final_verdict": final_verdict}


def render_html(data: dict) -> str:
    return _env().get_template("incident_report.html").render(**data)


def render_markdown(data: dict) -> str:
    return _env().get_template("incident_report.md").render(**data)


def build_report(store: MongoStore, incident_id: str) -> tuple[str, str] | None:
    data = gather(store, incident_id)
    if not data:
        return None
    return render_html(data), render_markdown(data)


def export_alerts_csv(store: MongoStore) -> str:
    """Formula-injection-safe CSV export of all alerts."""
    rows = store.list_alerts(limit=10000)
    buf = io.StringIO()
    cols = ["alert_id", "created_at", "detection_name", "severity", "risk_score",
            "status", "verdict", "source_ip", "destination_ip", "username",
            "hostname", "mitre_id", "confidence", "correlation_group"]
    w = csv.writer(buf)
    w.writerow(cols)
    for a in rows:
        w.writerow([csv_safe(a.get(c)) for c in cols])
    return buf.getvalue()
