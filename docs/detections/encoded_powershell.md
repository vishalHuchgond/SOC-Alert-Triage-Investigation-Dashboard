# Encoded PowerShell

- **Purpose:** detect encoded powershell activity
- **Data source:** 4104 / 4688
- **Logic:** -enc / -EncodedCommand / FromBase64String; base64 decoded as UTF-16LE
- **ATT&CK:** T1059.001 / T1027
- **Known false positives:** Some vendors encode legitimately
- **Tuning guidance:** Review decoded command content
