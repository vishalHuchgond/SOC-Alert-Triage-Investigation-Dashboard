"""Alerts list with filters, severity tinting, and drill-down to investigation."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from ui.components import empty_state, require_db, severity_badge, status_badge
from ui.db import get_store

st.header("Alerts")

store = get_store()
if not require_db(store):
    st.stop()

alerts = store.list_alerts(limit=5000)
if not alerts:
    empty_state("No alerts", "Ingest logs and run the detection engine from Log Analysis.")
    st.stop()

df = pd.DataFrame(alerts)

# Ensure all expected columns exist to avoid KeyError when some alerts lack specific fields
expected_cols = [
    "alert_id", "created_at", "detection_name", "severity", "risk_score",
    "source_ip", "destination_ip", "username", "hostname", "mitre_id",
    "status", "verdict", "description"
]
for col_name in expected_cols:
    if col_name not in df.columns:
        df[col_name] = None

# ---- filters ------------------------------------------------------------------
c1, c2, c3, c4 = st.columns([1, 1, 1, 2])
f_sev = c1.multiselect("Severity", ["critical", "high", "medium", "low"])
statuses = sorted([s for s in df["status"].dropna().unique() if s])
f_status = c2.multiselect("Status", statuses)
detections = sorted([d for d in df["detection_name"].dropna().unique() if d])
f_det = c3.multiselect("Detection", detections)
f_search = c4.text_input("Search (IP, user, hostname, alert id)")

view = df.copy()
if f_sev:
    view = view[view["severity"].isin(f_sev)]
if f_status:
    view = view[view["status"].isin(f_status)]
if f_det:
    view = view[view["detection_name"].isin(f_det)]
if f_search:
    search_cols = [c for c in ["alert_id", "source_ip", "destination_ip", "username", "hostname",
                               "detection_name", "description"] if c in view.columns]
    m = view[search_cols].astype(str).apply(lambda col: col.str.contains(f_search, case=False, na=False))
    view = view[m.any(axis=1)]

st.caption(f"{len(view)} of {len(df)} alerts")
if view.empty:
    empty_state("No matching alerts", "Adjust the filters.")
    st.stop()


def _style_sev(v):
    colors = {"critical": "background-color:#DC2626;color:#fff",
              "high": "background-color:#EF4444;color:#fff",
              "medium": "background-color:#F59E0B;color:#111",
              "low": "background-color:#22C55E;color:#062e13"}
    return [colors.get(str(x).lower(), "") for x in v]


show_cols = ["alert_id", "created_at", "detection_name", "severity", "risk_score",
             "source_ip", "destination_ip", "username", "hostname", "mitre_id",
             "status", "verdict"]
show = view[show_cols].copy()

# Render styled alerts table
event = st.dataframe(
    show.style.apply(_style_sev, subset=["severity"]),
    use_container_width=True, hide_index=True,
    on_select="rerun", selection_mode="single-row",
    column_config={"risk_score": st.column_config.NumberColumn("Risk", format="%d"),
                   "alert_id": "Alert ID"},
)

# Extract selected alert from dataframe row selection or selectbox fallback
selected_alert_id = None
if hasattr(event, "selection") and event.selection:
    rows = getattr(event.selection, "rows", None)
    if rows is None and isinstance(event.selection, dict):
        rows = event.selection.get("rows", [])
    if rows and len(rows) > 0:
        selected_alert_id = show.iloc[rows[0]]["alert_id"]

st.divider()
c_sel, c_act = st.columns([3, 2])
with c_sel:
    options = ["-- Select an alert from table or list --"] + show["alert_id"].tolist()
    default_idx = 0
    if selected_alert_id and selected_alert_id in options:
        default_idx = options.index(selected_alert_id)
    choice = st.selectbox("Quick Alert Selector", options, index=default_idx)
    if choice != "-- Select an alert from table or list --":
        selected_alert_id = choice

if selected_alert_id:
    st.session_state["selected_alert"] = selected_alert_id
    a = store.get_alert(selected_alert_id)
    if a:
        with c_act:
            st.markdown(f"Selected: **{selected_alert_id}** — {a.get('detection_name')} "
                        f"({severity_badge(a.get('severity'))}) risk **{a.get('risk_score', 0)}/100** "
                        f"{status_badge(a.get('status'))}", unsafe_allow_html=True)
            b1, b2 = st.columns(2)
            with b1:
                if st.button("🔍 Open Investigation", type="primary", use_container_width=True):
                    st.query_params["alert_id"] = selected_alert_id
                    st.switch_page("ui/investigations.py")
            with b2:
                if st.button("🚨 Escalate to Incident", use_container_width=True):
                    from incidents.incident_manager import create_from_alert
                    inc = create_from_alert(store, selected_alert_id,
                                            title=f"{a.get('detection_name')} on {a.get('hostname') or a.get('source_ip') or 'Host'}")
                    if inc:
                        st.success(f"Incident {inc['incident_id']} created!")
                        st.session_state["selected_incident"] = inc["incident_id"]
                        st.switch_page("ui/incidents.py")

