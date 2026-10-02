"""SOC Alert Triage & Investigation Platform - entrypoint.

Run:  streamlit run app.py
"""
from __future__ import annotations

import streamlit as st

from ui.theme import inject_css

st.set_page_config(page_title="SOC Alert Triage & Investigation Dashboard", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")
inject_css()

from ui.db import get_store  # noqa: E402
from ui.components import system_status_html  # noqa: E402
from config.settings import get_settings  # noqa: E402

store = get_store()
s = get_settings()
db_ok = store.ping()

with st.sidebar:
    st.markdown("### 🛡️ SOC PLATFORM")
    st.caption("Alert Triage & Investigation Dashboard")
    st.divider()
    st.markdown(system_status_html(db_ok, True, s.vt_configured), unsafe_allow_html=True)
    st.divider()
    st.caption(f"SOC Analyst Platform, Version {s.app_version}")

pages = [
    st.Page("ui/dashboard.py", title="Dashboard", icon=":material/dashboard:"),
    st.Page("ui/logs.py", title="Log Analysis", icon=":material/upload_file:"),
    st.Page("ui/alerts.py", title="Alerts", icon=":material/notification_important:"),
    st.Page("ui/investigations.py", title="Investigations", icon=":material/search:"),
    st.Page("ui/incidents.py", title="Incidents", icon=":material/crisis_alert:"),
    st.Page("ui/iocs.py", title="IOC Intelligence", icon=":material/network_intelligence:"),
    st.Page("ui/mitre.py", title="MITRE ATT&CK", icon=":material/grid_on:"),
    st.Page("ui/reports.py", title="Reports", icon=":material/description:"),
    st.Page("ui/settings.py", title="Settings", icon=":material/settings:"),
]

nav = st.navigation(pages)
nav.run()
