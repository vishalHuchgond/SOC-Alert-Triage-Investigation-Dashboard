"""Dashboard: metric cards (clickable drill-down), charts, FP-rate, recent alerts."""
from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from ui.components import empty_state, require_db, severity_badge
from ui.db import get_store

st.header("Dashboard")

store = get_store()
if not require_db(store):
    st.stop()

alerts = store.list_alerts(limit=10000)
df = pd.DataFrame(alerts)

for c in ["alert_id", "created_at", "detection_name", "source_ip",
          "destination_ip", "username", "severity", "risk_score",
          "mitre_id", "status", "verdict"]:
    if c not in df.columns:
        df[c] = None

# ---- metric cards (clickable -> filtered page) ------------------------------
c1, c2, c3, c4, c5, c6 = st.columns(6)
total = len(df)
critical = int((df["severity"] == "critical").sum()) if not df.empty else 0
high_risk = int((df["risk_score"] >= 70).sum()) if not df.empty else 0
open_incidents = store.db.incidents.count_documents({"status": {"$in": ["Open", "Investigating"]}})
tp = int((df["verdict"] == "True Positive").sum()) if not df.empty else 0
fp = int((df["verdict"] == "False Positive").sum()) if not df.empty else 0

cards = [("Total Alerts", total, None), ("Critical", critical, "critical"),
         ("High Risk", high_risk, None), ("Open Incidents", open_incidents, None),
         ("True Positives", tp, None), ("False Positives", fp, None)]
for col, (title, value, sev) in zip((c1, c2, c3, c4, c5, c6), cards):
    with col:
        st.metric(title, value)

st.caption("Drill-down: use the Alerts page filters (severity, status, search) "
           "or click an alert row to open its investigation.")

# ---- charts ------------------------------------------------------------------
left, right = st.columns(2)
with left:
    st.subheader("Alert Severity Distribution")
    if df.empty:
        empty_state("No alerts yet", "Upload logs on the Log Analysis page and run detections.")
    else:
        sev_counts = df["severity"].value_counts().reindex(["critical", "high", "medium", "low"]).fillna(0)
        fig = px.bar(x=sev_counts.index, y=sev_counts.values,
                     color=sev_counts.index, color_discrete_map={
                         "critical": "#DC2626", "high": "#EF4444",
                         "medium": "#F59E0B", "low": "#22C55E"},
                     labels={"x": "Severity", "y": "Alerts"})
        fig.update_layout(showlegend=False, paper_bgcolor="rgba(0,0,0,0)",
                          plot_bgcolor="rgba(0,0,0,0)", font_color="#94A3B8",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Alert Status")
    if df.empty:
        empty_state("No alerts yet", "Statuses will appear here once detections run.")
    else:
        status_counts = df["status"].value_counts()
        fig = px.pie(names=status_counts.index, values=status_counts.values, hole=0.55,
                     color_discrete_sequence=["#38BDF8", "#F59E0B", "#22C55E", "#64748B"])
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#94A3B8",
                          margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)

left, right = st.columns(2)
with left:
    st.subheader("False-Positive Rate per Detection")
    if df.empty or "verdict" not in df:
        empty_state("No verdicts yet", "Record TP/FP verdicts in Investigations.")
    else:
        judged = df[df["verdict"].isin(["True Positive", "False Positive"])]
        if judged.empty:
            empty_state("No verdicts yet", "Record TP/FP verdicts in Investigations.")
        else:
            fp_rate = (judged.groupby("detection_name")["verdict"]
                       .apply(lambda s: (s == "False Positive").mean() * 100)
                       .sort_values())
            fig = px.bar(x=fp_rate.values, y=fp_rate.index, orientation="h",
                         labels={"x": "FP rate %", "y": ""}, color_discrete_sequence=["#38BDF8"])
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              font_color="#94A3B8", margin=dict(l=0, r=0, t=10, b=0))
            st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Top Source IPs")
    ev = store.events_df({})
    if ev.empty or "source_ip" not in ev:
        empty_state("No events yet", "Ingest logs to see source IP activity.")
    else:
        top = ev["source_ip"].dropna().value_counts().head(8)
        fig = px.bar(x=top.values, y=top.index, orientation="h",
                     labels={"x": "Events", "y": ""}, color_discrete_sequence=["#F59E0B"])
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          font_color="#94A3B8", margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)

# ---- recent alerts ------------------------------------------------------------
st.subheader("Recent Alerts")
if df.empty:
    empty_state("No alerts", "Ingest logs, then run detections from Log Analysis.")
else:
    recent = df.head(15)[["alert_id", "created_at", "detection_name", "source_ip",
                          "destination_ip", "username", "severity", "risk_score",
                          "mitre_id", "status"]].copy()


    def _style_sev(v):
        colors = {"critical": "background-color:#DC2626;color:#fff",
                  "high": "background-color:#EF4444;color:#fff",
                  "medium": "background-color:#F59E0B;color:#111",
                  "low": "background-color:#22C55E;color:#062e13"}
        return [colors.get(str(x).lower(), "") for x in v]


    styled = recent.style.apply(_style_sev, subset=["severity"])
    st.dataframe(styled, use_container_width=True, hide_index=True,
                 column_config={"alert_id": "Alert ID", "mitre_id": "MITRE",
                                "risk_score": st.column_config.NumberColumn("Risk", format="%d")})
    st.caption("Open an investigation from the Alerts page (click a row, then 'Open Investigation').")
