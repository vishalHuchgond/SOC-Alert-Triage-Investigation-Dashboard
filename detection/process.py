"""Process detections: LOLBins, suspicious parent-child pairs, shell spawn context."""
from __future__ import annotations

import pandas as pd

from detection.helpers import col, make_result, rule, timed

LOLBINS = {
    "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe",
    "wmic.exe", "cscript.exe", "wscript.exe", "msbuild.exe", "installutil.exe",
    "regasm.exe", "psexec.exe", "cmstp.exe", "msiexec.exe",
}

# (parent, child) pairs where a command shell is abnormal and high-signal
SUSPICIOUS_PARENT_CHILD = [
    ("winword.exe", "cmd.exe"), ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"), ("excel.exe", "powershell.exe"),
    ("powerpnt.exe", "cmd.exe"), ("outlook.exe", "powershell.exe"),
    ("chrome.exe", "cmd.exe"), ("firefox.exe", "cmd.exe"), ("msedge.exe", "cmd.exe"),
    ("w3wp.exe", "cmd.exe"), ("w3wp.exe", "powershell.exe"), ("nginx.exe", "cmd.exe"),
    ("sqlservr.exe", "cmd.exe"),
]
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe"}


def _base(s: pd.Series) -> pd.Series:
    return s.fillna("").str.replace("\\", "/", regex=False).str.split("/").str[-1].str.lower()


@rule
def suspicious_process_execution(df: pd.DataFrame, cfg: dict) -> list[dict]:
    out = []
    d = timed(df)
    proc, parent = _base(col(d, "process")), _base(col(d, "parent_process"))
    lol = d[proc.isin(LOLBINS)]
    for host, g in lol.groupby("hostname"):
        names = sorted(g["process"].dropna().unique().tolist())
        out.append(make_result(
            "suspicious_process_execution", cfg.get("severity", "high"),
            f"LOLBin execution on {host}: {', '.join(names)}.",
            cfg.get("mitre_id", "T1218"), g, f"host:{host}",
            extra={"processes": names}))
    pairs = pd.Series(list(zip(parent, proc)), index=d.index)
    mask = pairs.isin(SUSPICIOUS_PARENT_CHILD)
    if mask.any():
        g = d[mask]
        parent_masked = parent[mask]
        proc_masked = proc[mask]
        for (p, c), gg in g.groupby([parent_masked, proc_masked]):
            out.append(make_result(
                "suspicious_process_execution", cfg.get("severity", "high"),
                f"Suspicious parent-child pair: {p} -> {c}.",
                cfg.get("mitre_id", "T1218"), gg, f"pair:{p}->{c}",
                extra={"parent": p, "child": c}))
    return out


@rule
def command_shell_execution(df: pd.DataFrame, cfg: dict) -> list[dict]:
    """Contextual: a shell spawned by Office, a browser, or a web server."""
    out = []
    d = timed(df)
    proc, parent = _base(col(d, "process")), _base(col(d, "parent_process"))
    office = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"}
    browsers = {"chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe"}
    webservers = {"w3wp.exe", "nginx.exe", "httpd.exe", "apache2.exe", "tomcat9.exe", "java.exe"}
    mask = proc.isin(SHELLS) & (parent.isin(office | browsers | webservers))
    for (p, c), g in d[mask].groupby([parent[mask], proc[mask]]):
        out.append(make_result(
            "command_shell_execution", cfg.get("severity", "medium"),
            f"Command shell ({c}) spawned by {p} - verify this is expected software behavior.",
            cfg.get("mitre_id", "T1059.003"), g, f"shell:{p}->{c}",
            extra={"parent": p, "child": c}))
    return out
