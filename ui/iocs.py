"""IOC Intelligence: on-demand lookup/enrichment + all extracted IOCs."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from ioc.extractor import extract, is_enrichable
from threat_intel.virustotal import VirusTotalClient
from threat_intel.watchlist import lookup as watchlist_lookup
from ui.components import card, empty_state, error_banner, kv_table, ok_banner, require_db
from ui.db import get_store

st.header("IOC Intelligence")
st.caption("Local watchlist works offline. VirusTotal enrichment is on-demand, "
           "rate-limited, cached, and never receives private/internal indicators.")

store = get_store()
if not require_db(store):
    st.stop()
vt = VirusTotalClient(store)

# ---- lookup ------------------------------------------------------------------
c1, c2 = st.columns([3, 1])
with c1:
    query = st.text_input("Look up IP, domain, URL, or hash", placeholder="203.0.113.99 / malware.example / https://... / sha256")
with c2:
    st.write("")
    st.write("")
    run = st.button("Analyze", type="primary")

if run and query.strip():
    res = extract(query.strip())
    if not res.iocs:
        error_banner("No valid IOC recognized. Check the input (defanged hxxp:// and [.] are supported).")
    else:
        ioc = res.iocs[0]
        wl = watchlist_lookup(ioc["value"])
        cached = store.cache_get(ioc["value"], 24)
        body = [("Type", ioc["type"]), ("Value", ioc["value"])]
        if wl:
            body += [("Reputation", wl.get("severity", "suspicious")),
                     ("Intelligence source", "Local watchlist (SAMPLE/OFFLINE data)"),
                     ("Reason", wl.get("reason", ""))]
        elif cached:
            body += [("Reputation", cached.get("reputation", "unknown")),
                     ("Intelligence source", f"{cached.get('source')} (cached)"),
                     ("Detections", f"{cached.get('malicious', 0)} malicious / "
                                    f"{cached.get('suspicious', 0)} suspicious of "
                                    f"{cached.get('total', 0)} engines")]
        elif not is_enrichable(ioc):
            body += [("Reputation", "unknown"),
                     ("Intelligence source", "Not enriched (internal/private indicator)")]
        elif not vt.available:
            body += [("Reputation", "unknown"),
                     ("Intelligence source", "Not enriched (VirusTotal unavailable / no API key)")]
        else:
            with st.spinner("Querying VirusTotal..."):
                r = vt.enrich(ioc)
            body += [("Reputation", r.reputation),
                     ("Intelligence source", r.source),
                     ("Detections", f"{r.malicious} malicious / {r.suspicious} suspicious of {r.total} engines"),
                     ("Note", r.reason)]
            if r.source != "Not enriched":
                store.update_ioc(ioc["value"], {"reputation": r.reputation, "intel_source": r.source})
        st.markdown(card("Lookup result", kv_table(body)), unsafe_allow_html=True)

# ---- all IOCs ------------------------------------------------------------------
st.subheader("Extracted IOCs")
iocs = store.list_iocs()
if not iocs:
    empty_state("No IOCs extracted yet", "IOCs are extracted automatically during the SOC triage pipeline and when alerts are investigated.")
    if st.button("⚡ Sync & Extract IOCs from Alerts Now", type="primary"):
        from detection.pipeline import sync_all_iocs
        count = sync_all_iocs(store)
        if count:
            ok_banner(f"Extracted and synchronized {count} IOCs.")
            st.rerun()
        else:
            st.info("No new IOCs found in existing alert events.")
else:
    rows = []
    for i in iocs:
        rows.append({
            "type": i.get("type"), "value": i.get("value"),
            "reputation": i.get("reputation", "unknown"),
            "intel_source": i.get("intel_source", "Not enriched"),
            "first_seen": i.get("first_seen"), "last_seen": i.get("last_seen"),
            "related_alerts": ", ".join(i.get("alert_ids", [])[:5]),
            "confidence": "high" if i.get("reputation") == "malicious"
                          else ("medium" if i.get("reputation") in ("suspicious", "clean") else "low"),
        })
    df = pd.DataFrame(rows)
    sel = st.dataframe(df, use_container_width=True, hide_index=True,
                       on_select="rerun", selection_mode="single-row")
    rows_sel = getattr(sel.selection, "rows", None) if hasattr(sel, "selection") else None
    if rows_sel is None and isinstance(getattr(sel, "selection", None), dict):
        rows_sel = sel.selection.get("rows", [])
    if rows_sel and len(rows_sel) > 0:
        row = df.iloc[rows_sel[0]]
        st.caption(f"Selected: **{row['value']}** — reputation **{row['reputation']}** "
                   f"(source: {row['intel_source']}). Related alerts: {row['related_alerts'] or 'none'}.")
