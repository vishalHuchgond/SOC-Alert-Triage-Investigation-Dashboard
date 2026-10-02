# Security Log Clearing

- **Purpose:** detect security log clearing activity
- **Data source:** 1102 / 104
- **Logic:** Audit log cleared (anti-forensics)
- **ATT&CK:** T1070.001
- **Known false positives:** Log rotation scripts with wrong privileges
- **Tuning guidance:** Treat as high severity; preserve remaining logs
