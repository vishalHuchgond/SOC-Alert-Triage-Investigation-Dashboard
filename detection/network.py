"""Network detections: port scanning from firewall/connection logs."""
from __future__ import annotations

import pandas as pd

from detection.helpers import col, make_result, rule, timed


@rule
def port_scanning(df: pd.DataFrame, cfg: dict) -> list[dict]:
    window = int(cfg.get("window_minutes", 10)) * 60
    distinct_ports = int(cfg.get("distinct_ports", 20))
    out = []
    d = timed(df)
    d = d[col(d, "destination_port").notna() & col(d, "source_ip").notna()]
    d = d[col(d, "event_type").isin(["network", "firewall", None])]
    for src, g in d.groupby("source_ip"):
        g = g.sort_values("_epoch")
        ports = g["destination_port"].astype(str)
        if ports.nunique() >= distinct_ports:
            window_rows = g[(g["_epoch"] - g["_epoch"].min()) <= window]
            hits = window_rows if window_rows["destination_port"].astype(str).nunique() >= distinct_ports else g
            out.append(make_result(
                "port_scanning", cfg.get("severity", "medium"),
                f"{src} touched {ports.nunique()} distinct destination ports - likely network scanning.",
                cfg.get("mitre_id", "T1046"), hits, f"src:{src}",
                extra={"distinct_ports": int(ports.nunique()),
                       "top_targets": hits["destination_ip"].dropna().value_counts().head(5).to_dict()}))
    return out
