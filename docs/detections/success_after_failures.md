# Successful Login After Failures

- **Purpose:** detect successful login after failures activity
- **Data source:** 4624 after 4625
- **Logic:** Success from a source with N recent failures
- **ATT&CK:** T1110
- **Known false positives:** Users who mistyped then succeeded
- **Tuning guidance:** Treat as high value; verify with the user
