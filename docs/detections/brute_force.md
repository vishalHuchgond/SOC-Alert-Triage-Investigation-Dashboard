# Brute Force

- **Purpose:** detect brute force activity
- **Data source:** 4625 / auth.log failures
- **Logic:** N failures from one source in a window
- **ATT&CK:** T1110.001
- **Known false positives:** Vulnerability scanners; misconfigured services
- **Tuning guidance:** Allowlist scanner IPs; raise threshold for service accounts
