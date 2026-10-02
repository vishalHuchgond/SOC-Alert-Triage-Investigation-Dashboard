# Port Scanning

- **Purpose:** detect port scanning activity
- **Data source:** Firewall/connection logs
- **Logic:** One source hitting many distinct ports in a window
- **ATT&CK:** T1046
- **Known false positives:** Approved vulnerability scanners
- **Tuning guidance:** Allowlist scanners; tune distinct-ports threshold
