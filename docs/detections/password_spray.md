# Password Spray

- **Purpose:** detect password spray activity
- **Data source:** 4625 failures
- **Logic:** One source failing against many distinct accounts in a window
- **ATT&CK:** T1110.003
- **Known false positives:** Password managers misbehaving; helpdesk resets
- **Tuning guidance:** Distinct-account threshold; exclude SSO NAT IPs
