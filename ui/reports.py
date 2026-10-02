"""Reports: incident report export (HTML + Markdown) and alerts CSV export."""
from __future__ import annotations

import streamlit as st

from reports.incident_report import build_report, export_alerts_csv
from ui.components import empty_state, error_banner, ok_banner, require_db
from ui.db import get_store

st.header("Reports")
st.caption("Self-contained HTML and Markdown incident reports. All log-derived "
           "content is HTML-escaped; CSV exports are formula-injection safe.")

store = get_store()
if not require_db(store):
    st.stop()

incidents = store.list_incidents()
st.subheader("Incident Report")
if not incidents:
    empty_state("No incidents yet", "Create an incident from an alert investigation, or click the button below to auto-generate from high-risk alerts.")
    if st.button("⚡ Auto-Generate Incident from Highest-Risk Alert", type="primary"):
        from detection.pipeline import auto_escalate_incidents
        new_incs = auto_escalate_incidents(store, min_risk=50)
        if new_incs:
            ok_banner(f"Generated {len(new_incs)} incidents. You can now build and export their reports.")
            st.session_state["selected_incident"] = new_incs[0]["incident_id"]
            st.rerun()
        else:
            st.warning("No alerts available to create an incident. Please ingest logs from Log Analysis first.")
else:
    inc_ids = [i["incident_id"] for i in incidents]
    default_id = st.session_state.get("selected_incident")
    default_idx = inc_ids.index(default_id) if default_id in inc_ids else 0
    choice = st.selectbox("Select Incident to Report", inc_ids, index=default_idx,
                          format_func=lambda iid: f"{iid} — {store.get_incident(iid).get('title', '')}")
    if choice:
        built = build_report(store, choice)
        if not built:
            error_banner("Could not build the report for this incident.")
        else:
            html, md = built
            st.caption(f"Report ready for **{choice}** ({len(html)} bytes HTML, {len(md)} bytes Markdown).")
            c1, c2 = st.columns(2)
            with c1:
                st.download_button("⬇ Download HTML report", html,
                                   file_name=f"{choice}_report.html", mime="text/html",
                                   use_container_width=True)
            with c2:
                st.download_button("⬇ Download Markdown report", md,
                                   file_name=f"{choice}_report.md", mime="text/markdown",
                                   use_container_width=True)

            t1, t2 = st.tabs(["Markdown Preview", "HTML Preview"])
            with t1:
                st.markdown(md[:6000])
            with t2:
                import streamlit.components.v1 as components
                components.html(html, height=500, scrolling=True)

st.divider()
st.subheader("Alerts Export (CSV)")
if st.button("Generate CSV"):
    csv_data = export_alerts_csv(store)
    st.download_button("⬇ Download alerts.csv", csv_data,
                       file_name="alerts_export.csv", mime="text/csv")
    ok_banner(f"Exported {csv_data.count(chr(10)) - 1} alerts with formula-injection protection.")
