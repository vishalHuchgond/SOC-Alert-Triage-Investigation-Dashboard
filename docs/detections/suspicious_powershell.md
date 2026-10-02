# Suspicious PowerShell

- **Purpose:** detect suspicious powershell activity
- **Data source:** 4104 / process command lines
- **Logic:** Download cradles, hidden windows, bypass flags
- **ATT&CK:** T1059.001
- **Known false positives:** Admin scripts; software deployment
- **Tuning guidance:** Tune pattern list; whitelist deployment tools
