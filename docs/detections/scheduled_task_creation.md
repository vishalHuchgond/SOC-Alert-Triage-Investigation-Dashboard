# Scheduled Task Creation

- **Purpose:** detect scheduled task creation activity
- **Data source:** 4698 / schtasks /create
- **Logic:** Scheduled task created (persistence)
- **ATT&CK:** T1053.005
- **Known false positives:** Software updaters; IT maintenance
- **Tuning guidance:** Review task author and run-as account
