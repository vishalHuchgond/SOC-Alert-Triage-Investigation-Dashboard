# Suspicious Process Execution

- **Purpose:** detect suspicious process execution activity
- **Data source:** 4688 / Sysmon 1
- **Logic:** LOLBin execution and suspicious parent-child pairs
- **ATT&CK:** T1218
- **Known false positives:** Admin tooling; installers using rundll32
- **Tuning guidance:** Tune LOLBin list; check command-line arguments
