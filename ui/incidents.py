"""Incidents: list, create from alerts/correlation, detail with timeline + evidence."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from incidents.incident_manager import (EVIDENCE_TYPES, add_incident_note,
                                        set_incident_status, INCIDENT_STATUSES)
from ui.components import (card, empty_state, error_banner, kv_table, ok_banner,
                           require_db, severity_badge, status_badge, timeline_html)
from ui.db import get_store

st.header("Incidents")

store = get_store()
if not require_db(store):
    st.stop()

c1, c2 = st.columns([2, 1])
with c1:
    st.caption("Manage security incidents, review correlated threat evidence, update status, and export investigation reports.")
with c2:
    with st.expander("➕ New incident"):
        all_unlinked = [a for a in store.list_alerts(limit=500) if not a.get("incident_id")]
        alert_choices = ["-- Select an alert --"] + [
            f"{a['alert_id']} — {a.get('detection_name')} ({a.get('severity', '').upper()} / Risk: {a.get('risk_score', 0)})"
            for a in all_unlinked
        ]
        chosen = st.selectbox("From alert", alert_choices)
        chosen_id = chosen.split(" — ")[0].strip() if chosen != "-- Select an alert --" else ""
        manual_id = st.text_input("Or enter Alert ID manually", value=chosen_id)
        title = st.text_input("Incident Title (optional)")
        if st.button("Create Incident", type="primary"):
            from incidents.incident_manager import create_from_alert
            target_id = manual_id.strip().upper()
            inc = create_from_alert(store, target_id, title)
            if inc:
                ok_banner(f"Incident {inc['incident_id']} created.")
                st.session_state["selected_incident"] = inc["incident_id"]
                st.rerun()
            else:
                error_banner("Alert not found — please check the alert ID.")

        st.divider()
        if st.button("⚡ Auto-Escalate Critical Threats"):
            from detection.pipeline import auto_escalate_incidents
            new_incs = auto_escalate_incidents(store, min_risk=60)
            if new_incs:
                ok_banner(f"Created {len(new_incs)} new incidents from high-severity alerts.")
                st.rerun()
            else:
                st.info("No unescalated critical/high alerts found.")

incidents = store.list_incidents()
if not incidents:
    empty_state("No incidents yet", "Escalate an alert from its investigation view, or use the form above to create an incident.")
    if st.button("⚡ Auto-Generate Incidents from Existing Alerts"):
        from detection.pipeline import auto_escalate_incidents
        new_incs = auto_escalate_incidents(store, min_risk=50)
        if new_incs:
            ok_banner(f"Created {len(new_incs)} incidents.")
            st.rerun()
        else:
            st.warning("No alerts available to escalate. Please ingest logs first.")
    st.stop()

left, right = st.columns([1, 2])
with left:
    st.subheader("Incident List")
    df = pd.DataFrame([{k: i.get(k) for k in
                        ("incident_id", "title", "severity", "status", "risk_score",
                         "analyst", "created_at")} for i in incidents])
    sel = st.dataframe(df, use_container_width=True, hide_index=True,
                       on_select="rerun", selection_mode="single-row",
                       column_config={"risk_score": st.column_config.NumberColumn("Risk", format="%d")})

    selected_row_id = None
    if hasattr(sel, "selection") and sel.selection:
        rows = getattr(sel.selection, "rows", None)
        if rows is None and isinstance(sel.selection, dict):
            rows = sel.selection.get("rows", [])
        if rows and len(rows) > 0:
            selected_row_id = df.iloc[rows[0]]["incident_id"]

    inc_options = [i["incident_id"] for i in incidents]
    default_inc = selected_row_id or st.session_state.get("selected_incident") or inc_options[0]
    idx = inc_options.index(default_inc) if default_inc in inc_options else 0
    picked_inc = st.selectbox("Select Incident", inc_options, index=idx,
                              format_func=lambda iid: f"{iid} — {store.get_incident(iid).get('title', '')}")
    inc_id = picked_inc
    st.session_state["selected_incident"] = inc_id

inc = store.get_incident(inc_id)
if inc:
    with right:
        st.subheader(f"{inc['incident_id']} — {inc['title']}")
        st.markdown(severity_badge(inc.get("severity")) + " " +
                    status_badge(inc.get("status")), unsafe_allow_html=True)
        st.markdown(card("Details", kv_table([
            ("Analyst", inc.get("analyst")), ("Risk score", inc.get("risk_score")),
            ("Created", inc.get("created_at")), ("Updated", inc.get("updated_at")),
            ("Related alerts", ", ".join(inc.get("alert_ids", []))),
            ("IOCs", ", ".join(inc.get("ioc_values", [])) or "None"),
            ("MITRE", ", ".join(inc.get("mitre_ids", [])) or "None"),
        ])), unsafe_allow_html=True)

        if st.button("📄 View / Export Incident Report", type="primary"):
            st.session_state["selected_incident"] = inc_id
            st.switch_page("ui/reports.py")

        c1, c2 = st.columns(2)
        with c1:
            new_status = st.selectbox("Status", INCIDENT_STATUSES,
                                      index=INCIDENT_STATUSES.index(inc.get("status", "Open")))
            if st.button("Update status"):
                ok, msg = set_incident_status(store, inc_id, new_status)
                (ok_banner if ok else error_banner)(msg)
                st.rerun()
        with c2:
            note = st.text_input("Add note")
            if st.button("Add note"):
                ok, msg = add_incident_note(store, inc_id, note)
                (ok_banner if ok else error_banner)(msg)
                st.rerun()

        alerts = list(store.db.alerts.find({"alert_id": {"$in": inc.get("alert_ids", [])}}))
        if alerts:
            st.markdown("**Linked alerts**")
            adf = pd.DataFrame(alerts)[["alert_id", "detection_name", "severity",
                                        "risk_score", "status", "verdict"]]
            st.dataframe(adf, use_container_width=True, hide_index=True)

        st.markdown("**Timeline**")
        st.markdown(timeline_html(store.timeline_for("incident", inc_id)), unsafe_allow_html=True)

        st.markdown("**Evidence**")
        ev = store.evidence_for(inc_id)
        if ev:
            edf = pd.DataFrame([{k: e.get(k) for k in
                                 ("evidence_id", "type", "description", "timestamp")} for e in ev])
            st.dataframe(edf, use_container_width=True, hide_index=True)
        with st.expander("➕ Add evidence item"):
            e_type = st.selectbox("Type", EVIDENCE_TYPES)
            e_desc = st.text_input("Description")
            e_ts = st.text_input("Timestamp (UTC ISO, optional)")
            e_src = st.text_input("Source (file/alert/URL)")
            if st.button("Add evidence"):
                store.add_evidence({"incident_id": inc_id, "type": e_type,
                                    "description": e_desc, "timestamp": e_ts or None,
                                    "source": e_src})
                ok_banner("Evidence item added.")
                st.rerun()
        if inc.get("notes"):
            st.markdown("**Notes**")
            for n in inc["notes"]:
                st.markdown(f"- **{n.get('author', '?')}** ({n.get('at', '')}): {n.get('text', '')}")
