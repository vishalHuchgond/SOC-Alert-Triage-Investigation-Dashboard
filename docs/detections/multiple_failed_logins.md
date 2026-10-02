# Multiple Failed Logins

- **Purpose:** detect multiple failed logins activity
- **Data source:** 4625 failures
- **Logic:** N failures against one account in a window
- **ATT&CK:** T1110
- **Known false positives:** Users forgetting passwords
- **Tuning guidance:** Correlate with helpdesk tickets
