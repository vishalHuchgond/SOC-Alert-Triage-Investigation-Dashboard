"""MITRE ATT&CK coverage page."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from mitre.mitre import coverage
from ui.components import empty_state, require_db, badge
from ui.db import get_store

st.header("MITRE ATT&CK Coverage")
st.caption("Detection coverage mapped to ATT&CK techniques. Every alert carries "
           "its technique ID, name, and tactic.")

store = get_store()
if not require_db(store):
    st.stop()

cov = coverage()
all_alerts = store.list_alerts(limit=10000)

# Build technique to alerts mapping
technique_alerts: dict[str, list[dict]] = {}
for a in all_alerts:
    m_id = a.get("mitre_id")
    det = a.get("detection_name")
    mapped = False
    if m_id:
        technique_alerts.setdefault(m_id, []).append(a)
        mapped = True
    for tactic, tech_list in cov.items():
        for t in tech_list:
            if det in t.get("rules", []) and t["id"] != m_id:
                technique_alerts.setdefault(t["id"], []).append(a)
                mapped = True

total_techniques = sum(len(v) for v in cov.values())
triggered_techniques = sum(1 for tids in technique_alerts.values() if len(tids) > 0)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Techniques Covered", total_techniques)
c2.metric("Tactics Covered", len(cov))
c3.metric("Techniques Triggered", triggered_techniques)
c4.metric("Alerts Mapped", len(all_alerts))

for tactic, techniques in cov.items():
    st.subheader(f"{tactic} ({len(techniques)} techniques)")
    rows = []
    for t in techniques:
        matched_alerts = technique_alerts.get(t["id"], [])
        count = len(matched_alerts)
        rows.append({
            "Technique": f"{t['id']} — {t['name']}",
            "Detections": ", ".join(t["rules"]),
            "Alerts": count,
            "Status": "🚨 Triggered" if count > 0 else "🛡️ Covered",
        })
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True,
                 column_config={"Alerts": st.column_config.NumberColumn("Alerts", format="%d")})

st.divider()
st.subheader("Coverage by Tactic")
import plotly.express as px
tactic_counts = {k: len(v) for k, v in cov.items()}
fig = px.bar(x=list(tactic_counts.keys()), y=list(tactic_counts.values()),
             labels={"x": "Tactic", "y": "Techniques"},
             color_discrete_sequence=["#38BDF8"])
fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                  font_color="#94A3B8", margin=dict(l=0, r=0, t=10, b=0))
st.plotly_chart(fig, use_container_width=True)

with st.expander("🔍 Drill Down: View Alerts by MITRE Technique"):
    all_tids = sorted(list({t["id"]: t["name"] for tl in cov.values() for t in tl}.keys()))
    picked_tid = st.selectbox("Select Technique", all_tids,
                              format_func=lambda tid: f"{tid} — {coverage().get(tid, {}).get('name') if False else tid}")
    if picked_tid:
        matching = technique_alerts.get(picked_tid, [])
        if matching:
            st.caption(f"{len(matching)} alerts mapped to {picked_tid}:")
            m_df = pd.DataFrame([{
                "Alert ID": a.get("alert_id"),
                "Detection": a.get("detection_name"),
                "Severity": a.get("severity"),
                "Risk": a.get("risk_score"),
                "Source IP": a.get("source_ip"),
                "Host": a.get("hostname"),
                "Status": a.get("status"),
            } for a in matching])
            st.dataframe(m_df, use_container_width=True, hide_index=True)
        else:
            st.info(f"No alerts currently triggered for technique {picked_tid}.")

if not all_alerts:
    empty_state("No alerts yet", "Coverage shows rule-to-technique mapping; alert counts populate after detections run.")

