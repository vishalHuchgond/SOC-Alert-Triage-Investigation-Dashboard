"""Log Analysis: upload + ingest, ingestion history, event viewer, run detections."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from detection.engine import run_detections
from ioc.extractor import extract
from parser.ingest import ingest_bytes
from ui.components import empty_state, error_banner, ok_banner, require_db
from ui.db import get_store

st.header("Log Analysis")
st.caption("Upload security logs -> normalize -> run detection engine. "
           "Supported: Windows event CSV, Sysmon CSV/JSON, PowerShell log, "
           "Linux auth.log, Apache access log, firewall/connection CSV.")

store = get_store()
if not require_db(store):
    st.stop()

# ---- upload -------------------------------------------------------------------
up = st.file_uploader("Upload log file", type=["csv", "json", "log", "txt"],
                      help="Max size and row count are configurable in Settings/.env.")
auto_triage = st.checkbox("Automatically run Detections, Correlation, and Incident Triage after ingestion", value=True)

if up is not None:
    content = up.getvalue()
    if st.button("Ingest & Process File", type="primary"):
        with st.spinner("Parsing and ingesting events into MongoDB..."):
            res = ingest_bytes(store, up.name, content)
        if res.ok:
            ok_banner(res.message)
            st.session_state["last_file_hash"] = res.file_hash
            if auto_triage:
                with st.spinner("Running detection rules, correlation, and automated incident triage..."):
                    from detection.pipeline import run_full_pipeline
                    stats = run_full_pipeline(store)
                ok_banner(f"🚀 Triage complete: {stats['alerts_created']} alerts, "
                          f"{stats['correlation_groups']} correlation groups, "
                          f"{stats['iocs_extracted']} IOCs extracted, "
                          f"{stats['incidents_created']} incidents created.")
                st.info("Check the **Alerts**, **Investigations**, **Incidents**, and **Reports** pages to review the results.")
        else:
            error_banner(res.message)

# ---- sample data ----------------------------------------------------------------
with st.expander("Load synthetic SAMPLE DATA (no real data; documentation IP ranges only)"):
    st.caption("Generates windows.csv, auth.log, apache.log, powershell.log, "
               "firewall.csv, sysmon.csv with attack scenarios, then ingests them.")
    if st.button("Generate and ingest sample data"):
        import subprocess, sys
        from pathlib import Path
        r = subprocess.run([sys.executable, str(Path("sample_logs/generate.py"))],
                           capture_output=True, text=True)
        if r.returncode != 0:
            error_banner(f"Sample generator failed: {r.stderr[:300]}")
        else:
            from config.settings import CONFIG_DIR
            total_new = 0
            gen_dir = Path("sample_logs/generated")
            for f in sorted(gen_dir.iterdir()):
                res = ingest_bytes(store, f.name, f.read_bytes())
                total_new += res.events_inserted
                (ok_banner if res.ok else error_banner)(f"{f.name}: {res.message}")
            ok_banner(f"Sample data loaded. {total_new} new events ingested.")
            with st.spinner("Running full detection and triage pipeline on sample data..."):
                from detection.pipeline import run_full_pipeline
                stats = run_full_pipeline(store)
            ok_banner(f"🚀 Pipeline finished: {stats['alerts_created']} alerts created, "
                      f"{stats['correlation_groups']} correlation groups, "
                      f"{stats['iocs_extracted']} IOCs extracted, "
                      f"{stats['incidents_created']} incidents escalated.")

# ---- run detections --------------------------------------------------------------
st.divider()
st.subheader("SOC Triage Pipeline")
st.caption("Run rule evaluations across all events, group correlated attack chains, sync IOC intelligence, and escalate high-risk incidents.")
c_p1, c_p2 = st.columns([2, 3])
with c_p1:
    if st.button("⚡ Run Full SOC Triage Pipeline", type="primary", use_container_width=True):
        with st.spinner("Executing detection rules, attack-chain correlation, and incident triage..."):
            from detection.pipeline import run_full_pipeline
            stats = run_full_pipeline(store)
        ok_banner(f"Full pipeline complete: {stats['alerts_created']} alerts, "
                  f"{stats['correlation_groups']} correlation groups, "
                  f"{stats['attack_chains']} attack chains, "
                  f"{stats['iocs_extracted']} IOCs, "
                  f"{stats['incidents_created']} incidents.")
        st.info("Updated: **Alerts**, **Investigations**, **Incidents**, **IOC Intelligence**, **MITRE ATT&CK**, and **Reports**.")

# ---- ingestion history -------------------------------------------------------------
st.subheader("Ingestion History")
files_list = store.list_source_files()
if not files_list:
    empty_state("No files ingested", "Upload a log file above to begin.")
else:
    fdf = pd.DataFrame([{k: f.get(k) for k in
                         ("name", "format", "size_bytes", "row_count", "inserted",
                          "duplicates", "malformed_rows", "ingested_at")} for f in files_list])
    st.dataframe(fdf, use_container_width=True, hide_index=True,
                 column_config={"format": "Detected Format",
                                "ingested_at": "Ingested At (UTC)",
                                "malformed_rows": "Malformed Rows"})

# ---- event viewer ------------------------------------------------------------------
st.subheader("Event Viewer")
ev = store.events_df({})
if ev.empty:
    empty_state("No events", "Ingest a log file to browse normalized events.")
else:
    c1, c2, c3 = st.columns(3)
    sources = sorted(ev["log_source"].dropna().unique()) if "log_source" in ev else []
    etypes = sorted(ev["event_type"].dropna().unique()) if "event_type" in ev else []
    f_src = c1.multiselect("Log source", sources)
    f_type = c2.multiselect("Event type", etypes)
    f_search = c3.text_input("Search raw event / IP / user")
    view = ev.copy()
    if f_src:
        view = view[view["log_source"].isin(f_src)]
    if f_type:
        view = view[view["event_type"].isin(f_type)]
    if f_search:
        m = view.astype(str).apply(lambda col: col.str.contains(f_search, case=False, na=False))
        view = view[m.any(axis=1)]
    cols = [c for c in ["timestamp", "log_source", "event_type", "event_id", "source_ip",
                        "destination_ip", "username", "hostname", "process", "status"] if c in view]
    st.caption(f"{len(view)} events")
    st.dataframe(view[cols].head(1000), use_container_width=True, hide_index=True)
    with st.expander("View raw event"):
        sel = st.selectbox("Event", view.head(200)["_id"].tolist() if not view.empty else [])
        if sel:
            doc = store.get_event(sel)
            if doc:
                st.code(doc.get("raw_event", ""), language=None)
                iocs = extract(str(doc.get("command", "")) + " " + str(doc.get("message", "")) + " " + str(doc.get("raw_event", "")))
                if iocs.iocs:
                    st.markdown("**Extracted IOCs**")
                    st.json(iocs.iocs)
