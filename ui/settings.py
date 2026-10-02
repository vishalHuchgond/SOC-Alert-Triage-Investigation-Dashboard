"""Settings: system status, analyst identity, allowlist, thresholds. Never shows secrets."""
from __future__ import annotations

import pandas as pd
import streamlit as st
from config.settings import CONFIG_DIR, get_settings
from detection.engine import available_rules, load_rules_config
from mitre.mitre import load_mapping
from ui.components import card, empty_state, error_banner, kv_table, ok_banner, require_db
from ui.db import get_store

st.header("Settings")

store = get_store()
s = get_settings()
db_ok = store.ping()

st.markdown(card("System Status", kv_table([
    ("Version", s.app_version),
    ("Database", "Connected (MongoDB)" if db_ok else "UNAVAILABLE"),
    ("Database name", s.mongo_db),
    ("Schema version", getattr(store, "version", "unknown") if db_ok else "-"),
    ("Detection engine", "Online"),
    ("Detection rules", len(available_rules())),
    ("MITRE techniques", len(load_mapping())),
    ("VirusTotal", "Configured" if s.vt_configured else "Not configured (local watchlist only)"),
    ("API key", "••••••••" if s.vt_configured else "-"),
    ("Upload limits", f"{s.max_file_size_mb} MB / {s.max_rows:,} rows"),
])), unsafe_allow_html=True)

if not db_ok:
    error_banner("Database unavailable. Start MongoDB: docker compose up -d mongo")
    st.stop()

# ---- analyst identity -----------------------------------------------------------
st.subheader("Analyst")
analyst = st.text_input("Analyst name (recorded on every action)",
                        value=store.get_setting("analyst_name", s.analyst_name))
syslog_year = st.number_input("Syslog year (auth.log lines have no year; assumed UTC)",
                              min_value=2000, max_value=2100, step=1,
                              value=int(store.get_setting("syslog_year", s.syslog_year)))
if st.button("Save settings"):
    store.set_setting("analyst_name", analyst.strip() or "analyst")
    store.set_setting("syslog_year", int(syslog_year))
    ok_banner("Settings saved.")

# ---- detection thresholds summary -------------------------------------------------
st.subheader("Detection Thresholds")
cfg = load_rules_config()
rows = [{"rule": name, **{k: v for k, v in c.items() if k in
        ("enabled", "window_minutes", "threshold", "distinct_accounts",
         "distinct_ports", "failure_threshold", "severity", "mitre_id")}}
        for name, c in cfg.get("rules", {}).items()]
st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
st.caption(f"Edit config/rules_config.yaml to tune thresholds. Critical assets: "
           f"{', '.join(cfg.get('critical_assets', {}).get('hosts', []))} / "
           f"{', '.join(cfg.get('critical_assets', {}).get('accounts', []))}")

# ---- allowlist ---------------------------------------------------------------------
st.subheader("Suppression Allowlist")
st.caption("Allowlisted sources/users/keys are suppressed before alert creation. "
           "Suppressed counts are shown after each detection run.")
with st.expander("➕ Add allowlist entry"):
    c1, c2, c3 = st.columns(3)
    a_type = c1.selectbox("Type", ["source_ip", "username", "group_key"])
    a_value = c2.text_input("Value (e.g. scanner IP 10.10.5.5)")
    a_reason = c3.text_input("Reason")
    if st.button("Add to allowlist"):
        if not a_value.strip():
            error_banner("Value is required.")
        else:
            store.add_allowlist_entry({"type": a_type, "value": a_value.strip(),
                                       "reason": a_reason.strip(),
                                       "added_by": store.get_setting("analyst_name", "analyst")})
            ok_banner("Entry added.")
            st.rerun()

entries = store.list_allowlist()
if entries:
    edf = pd.DataFrame(entries)[["type", "value", "reason", "added_by", "added_at"]]
    sel = st.dataframe(edf, use_container_width=True, hide_index=True,
                       on_select="rerun", selection_mode="single-row")
    if sel.selection.rows:
        v = edf.iloc[sel.selection.rows[0]]["value"]
        if st.button(f"Remove '{v}'"):
            store.remove_allowlist_entry(v)
            ok_banner("Allowlist entry removed.")
            st.rerun()
else:
    empty_state("Allowlist empty", "Add known scanners or service accounts to reduce noise.")

# ---- dangerous zone: clear data ------------------------------------------------------
st.subheader("Data Management")
with st.expander("⚠ Reset platform data (demo only)"):
    st.caption("Drops all events, alerts, incidents and intelligence. Requires MongoDB admin rights.")
    if st.button("Drop all collections"):
        for name in ("events", "alerts", "iocs", "ioc_enrichment_cache", "source_files",
                     "correlation_groups", "investigations", "investigation_history",
                     "analyst_notes", "incidents", "timeline", "evidence",
                     "allowlist", "counters"):
            store.db[name].delete_many({})
        ok_banner("All data cleared.")
        st.rerun()
