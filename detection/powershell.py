"""PowerShell detections: suspicious commands and encoded command decoding."""
from __future__ import annotations

import base64
import re

import pandas as pd

from detection.helpers import col, make_result, rule, timed

_SUSPICIOUS = re.compile(
    r"(?i)(downloadstring|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|"
    r"-nop\b|-noexit|-w\s+hidden|-windowstyle\s+hidden|-ep\s+bypass|-executionpolicy\s+bypass|"
    r"start-bitstransfer|net\.webclient)"
)
_ENCODED = re.compile(
    r"(?i)(?:-enc(?:odedcommand)?|frombase64string\s*\(\s*[\"'])\s*[\"']?([A-Za-z0-9+/=]{16,})"
)


def decode_utf16(data: str) -> str | None:
    """Decode a base64 blob as UTF-16LE (PowerShell -EncodedCommand)."""
    try:
        raw = base64.b64decode(data + "=" * (-len(data) % 4))
        return raw.decode("utf-16-le", errors="strict")
    except Exception:
        return None


def ps_events(df: pd.DataFrame) -> pd.DataFrame:
    d = timed(df)
    mask = (col(d, "event_type") == "powershell") | col(d, "command").str.contains(
        "powershell|pwsh", case=False, na=False)
    return d[mask & col(d, "command").notna()]


@rule
def suspicious_powershell(df: pd.DataFrame, cfg: dict) -> list[dict]:
    out = []
    for host, g in ps_events(df).groupby("hostname"):
        hits = g[g["command"].str.contains(_SUSPICIOUS, na=False)]
        if not hits.empty:
            sample = hits["command"].iloc[0][:120]
            out.append(make_result(
                "suspicious_powershell", cfg.get("severity", "high"),
                f"Suspicious PowerShell pattern on {host} (e.g. download cradle or hidden window).",
                cfg.get("mitre_id", "T1059.001"), hits, f"host:{host}",
                extra={"matched_sample": sample}))
    return out


@rule
def encoded_powershell(df: pd.DataFrame, cfg: dict) -> list[dict]:
    out = []
    for host, g in ps_events(df).groupby("hostname"):
        decoded = None
        hits_rows = []
        for _, row in g.iterrows():
            m = _ENCODED.search(str(row["command"]))
            if m:
                hits_rows.append(row)
                if decoded is None:
                    decoded = decode_utf16(m.group(1))
        if hits_rows:
            hits = pd.DataFrame(hits_rows)
            desc = f"Encoded PowerShell command on {host}."
            extra = {"decoded_command": decoded or "Unable to decode payload"}
            out.append(make_result(
                "encoded_powershell", cfg.get("severity", "high"), desc,
                cfg.get("mitre_id", "T1059.001"), hits, f"host:{host}", extra=extra))
    return out
