"""Investigations: alert detail view (opened via ?alert_id=) + list of alerts
currently under investigation."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from config.settings import get_settings
from incidents.incident_manager import create_from_alert
from investigation.checklists import checklist_for
from investigation.investigator import (STATUSES, VERDICTS, add_note, set_status,
                                        set_verdict)
from mitre.mitre import technique_label
from threat_intel.virustotal import VirusTotalClient
from threat_intel.watchlist import lookup as watchlist_lookup
from ui.components import (card, empty_state, error_banner, kv_table, ok_banner,
                           require_db, risk_indicator, severity_badge, status_badge,
                           timeline_html, verdict_badge)
from ui.db import get_store

store = get_store()
if not require_db(store):
    st.stop()

alert_id = st.query_params.get("alert_id") or st.session_state.get("selected_alert")

if not alert_id:
    st.header("Investigations")
    st.caption("Investigate alerts, view enriched IOCs, triage evidence, and escalate to incidents.")

    c_f1, c_f2 = st.columns([1, 2])
    status_filter = c_f1.selectbox("Filter by Status", ["All Alerts", "Needs Triage (New)", "Under Investigation", "Resolved"])
    query: dict = {}
    if status_filter == "Needs Triage (New)":
        query = {"status": "New"}
    elif status_filter == "Under Investigation":
        query = {"status": "Investigating"}
    elif status_filter == "Resolved":
        query = {"status": "Resolved"}

    rows = store.list_alerts(query, limit=500) if query else store.list_alerts(limit=500)
    if not rows:
        empty_state("No alerts found for this filter", "Ingest logs or run the SOC triage pipeline from Log Analysis.")
        st.stop()

    df = pd.DataFrame(rows)
    for col_name in ["alert_id", "created_at", "detection_name", "severity", "risk_score", "status", "verdict", "source_ip", "username"]:
        if col_name not in df.columns:
            df[col_name] = None

    display_cols = ["alert_id", "created_at", "detection_name", "severity", "risk_score", "status", "verdict", "source_ip", "username"]
    st.dataframe(df[display_cols], use_container_width=True, hide_index=True,
                 column_config={"risk_score": st.column_config.NumberColumn("Risk", format="%d")})

    st.subheader("Select Alert to Investigate")
    alert_options = ["-- Select an alert to start investigation --"] + [
        f"{r['alert_id']} — {r.get('detection_name')} ({r.get('severity', '').upper()} / Risk: {r.get('risk_score', 0)})"
        for r in rows
    ]
    picked = st.selectbox("Choose alert", alert_options)
    if picked != "-- Select an alert to start investigation --":
        picked_id = picked.split(" — ")[0].strip()
        if st.button("🚀 Open Investigation View", type="primary"):
            st.query_params["alert_id"] = picked_id
            st.session_state["selected_alert"] = picked_id
            st.rerun()

    st.stop()

alert = store.get_alert(alert_id)
if not alert:
    error_banner(f"Alert {alert_id} not found. It may have been removed.")
    if st.button("⬅ Back to Investigations"):
        st.query_params.clear()
        st.session_state.pop("selected_alert", None)
        st.rerun()
    st.stop()

if st.button("⬅ Back to All Investigations"):
    st.query_params.clear()
    st.session_state.pop("selected_alert", None)
    st.rerun()


st.header(f"Investigation — {alert['alert_id']}")
c1, c2 = st.columns([3, 1])
with c2:
    st.markdown(severity_badge(alert.get("severity")), unsafe_allow_html=True)
    st.markdown(status_badge(alert.get("status")), unsafe_allow_html=True)
    st.markdown(verdict_badge(alert.get("verdict")), unsafe_allow_html=True)

# ---- summary -----------------------------------------------------------------
with c1:
    st.markdown(card("Alert Summary", kv_table([
        ("Detection", alert.get("detection_name")),
        ("Description", alert.get("description")),
        ("Created (UTC)", alert.get("created_at")),
        ("Time window", f"{alert.get('earliest', '?')} -> {alert.get('latest', '?')}"),
        ("MITRE ATT&CK", technique_label(alert.get("mitre_id"))),
        ("Confidence", alert.get("confidence")),
        ("Correlation group", alert.get("correlation_group") or "None"),
        ("Incident", alert.get("incident_id") or "None"),
        ("Group key", alert.get("group_key")),
    ])), unsafe_allow_html=True)

    st.markdown("**Risk score breakdown**  " +
                "<br>".join(f"`{line}`" for line in alert.get("risk_breakdown", [])),
                unsafe_allow_html=True)
    st.markdown(risk_indicator(alert.get("risk_score", 0)), unsafe_allow_html=True)

# ---- decoded command ---------------------------------------------------------
extra = alert.get("extra", {}) or {}
if extra.get("decoded_command"):
    with st.expander("🧬 Decoded PowerShell command (UTF-16LE)", expanded=True):
        st.code(extra["decoded_command"])
if extra.get("matched_sample"):
    st.caption(f"Matched pattern sample: `{extra['matched_sample']}`")

# ---- status / verdict actions -------------------------------------------------
st.subheader("Analyst Actions")
c1, c2 = st.columns(2)
with c1:
    new_status = st.selectbox("Set status", STATUSES, index=STATUSES.index(alert.get("status", "New")))
    reason = st.text_input("Reason (optional)")
    if st.button("Update status"):
        ok, msg = set_status(store, alert_id, new_status, reason)
        (ok_banner if ok else error_banner)(msg)
        st.rerun()
with c2:
    verdict = st.selectbox("Verdict", [""] + VERDICTS)
    reasoning = st.text_area("Verdict reasoning (required)", value=alert.get("verdict_reason") or "")
    if st.button("Record verdict"):
        ok, msg = set_verdict(store, alert_id, verdict, reasoning)
        (ok_banner if ok else error_banner)(msg)
        st.rerun()

# ---- IOCs + enrichment ---------------------------------------------------------
st.subheader("Extracted IOCs & Intelligence")
from bson import ObjectId
raw_eids = alert.get("event_ids", [])
obj_ids = [ObjectId(x) if ObjectId.is_valid(str(x)) else x for x in raw_eids]
events = list(store.db.events.find({"_id": {"$in": obj_ids}})) if obj_ids else []

from ioc.extractor import extract, is_enrichable
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
text_blob = " ".join(p for p in text_parts if p)
found = extract(text_blob)
if found.iocs:
    rows = []
    vt = VirusTotalClient(store)
    for ioc in found.iocs[:20]:
        cached = store.cache_get(ioc["value"], get_settings().ioc_cache_ttl_hours)
        rep, source = "unknown", "Not enriched"
        wl = watchlist_lookup(ioc["value"])
        if cached:
            rep, source = cached.get("reputation", "unknown"), cached.get("source", "Not enriched")
        elif wl:
            rep, source = wl.get("severity", "suspicious"), "Local watchlist"
        elif not is_enrichable(ioc):
            source, rep = "Not enriched (internal/private)", "unknown"
        rows.append({"type": ioc["type"], "value": ioc["value"],
                     "reputation": rep, "source": source})
        store.upsert_iocs([{"type": ioc["type"], "value": ioc["value"],
                            "first_seen": alert.get("earliest"), "last_seen": alert.get("latest")}])
        store.link_iocs_to_alert(alert_id, [ioc["value"]])
        store.update_ioc(ioc["value"], {"reputation": rep, "intel_source": source})
    idf = pd.DataFrame(rows).drop_duplicates("value")
    st.dataframe(idf, use_container_width=True, hide_index=True)
    target = st.selectbox("Enrich via VirusTotal (on demand)", [""] + idf["value"].tolist())
    if target and st.button("Enrich selected IOC"):
        row = idf[idf["value"] == target].iloc[0]
        res = vt.enrich({"type": row["type"], "value": target})
        st.json({k: getattr(res, k) for k in ("ioc_value", "source", "reputation",
                                              "malicious", "suspicious", "undetected", "reason")})
        if res.source != "Not enriched":
            store.update_ioc(target, {"reputation": res.reputation, "intel_source": res.source})
            st.rerun()
else:
    st.caption("No IOCs found in the evidence events.")

# ---- related alerts / correlation ----------------------------------------------
st.subheader("Related Alerts & Correlation")
related = []
for f in ("source_ip", "username", "hostname"):
    v = alert.get(f)
    if v:
        related += [a for a in store.alerts_for_entity(f, v, exclude_id=alert_id)
                    if a["alert_id"] not in {r["alert_id"] for r in related}]
if related:
    rdf = pd.DataFrame(related)[["alert_id", "created_at", "detection_name",
                                 "severity", "risk_score", "status"]].head(10)
    st.dataframe(rdf, use_container_width=True, hide_index=True)
else:
    st.caption("No related alerts sharing source IP, username, or hostname.")
if alert.get("correlation_group"):
    grp = store.get_correlation_group(alert["correlation_group"])
    if grp:
        st.markdown(card(f"Correlation group {grp['group_id']}",
                         kv_table([("Entity", f"{grp['entity_field']} = {grp['entity_value']}"),
                                   ("Alerts", ", ".join(grp["alert_ids"])),
                                   ("Detections", ", ".join(grp["detections"])),
                                   ("Attack chains", "; ".join(grp.get("attack_chains", [])) or "None")])
                         ), unsafe_allow_html=True)

# ---- triage checklist -------------------------------------------------------------
st.subheader("Triage Checklist")
for item in checklist_for(alert.get("detection_name", "")):
    st.checkbox(item, key=f"chk_{alert_id}_{hash(item) & 0xffff}")

# ---- original events --------------------------------------------------------------
st.subheader("Original Events (evidence)")
for e in events[:10]:
    with st.expander(f"{e.get('timestamp', '?')} · {e.get('event_id') or e.get('event_type') or ''} · "
                     f"{e.get('source_ip') or ''} · line {e.get('line_number', '?')}"):
        st.code(e.get("raw_event", ""))

# ---- notes & history ----------------------------------------------------------------
c1, c2 = st.columns(2)
with c1:
    st.subheader("Analyst Notes")
    note = st.text_area("Add note", key="note_box", height=80)
    if st.button("Add note"):
        ok, msg = add_note(store, alert_id, note)
        (ok_banner if ok else error_banner)(msg)
        st.rerun()
    for n in reversed(store.notes_for(alert_id)):
        st.markdown(f"**{n.get('author', '?')}** · {n.get('created_at', '')}\n\n{n.get('text', '')}")
with c2:
    st.subheader("Investigation History")
    hist = store.history_for(alert_id)
    if hist:
        st.markdown(timeline_html([{"entry_type": h["action"],
                                    "event_time": h.get("at"), "recorded_at": h.get("at"),
                                    "description": f"{h.get('actor', '?')}: "
                                                   f"{h.get('old') or '-'} -> {h.get('new') or '-'} "
                                                   f"({h.get('reason', '')})"} for h in hist]),
                    unsafe_allow_html=True)
    else:
        st.caption("No history yet.")

# ---- create incident ------------------------------------------------------------------
st.subheader("Escalate to Incident")
title = st.text_input("Incident title", value=f"{alert['detection_name']} on "
                                              f"{alert.get('hostname') or alert.get('source_ip') or 'unknown'}")
if st.button("Create incident from this alert", type="primary"):
    inc = create_from_alert(store, alert_id, title)
    if inc:
        ok_banner(f"Incident {inc['incident_id']} created. Manage it on the Incidents page.")
        st.rerun()
    else:
        error_banner("Could not create incident.")
