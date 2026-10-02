# Command Shell Execution

- **Purpose:** detect command shell execution activity
- **Data source:** 4688 / Sysmon 1
- **Logic:** cmd.exe spawned by Office, browsers, web servers
- **ATT&CK:** T1059.003
- **Known false positives:** Legacy macros; IT automation
- **Tuning guidance:** Contextual - pair with parent process review
