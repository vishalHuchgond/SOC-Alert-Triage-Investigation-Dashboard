# Interview Talking Points

1. **Why one alert per group?** Alert fatigue - 500 failed logins become one
   actionable alert with all evidence linked, not 500 rows.
2. **Explainable risk scoring:** every point has a reason shown to the analyst;
   "not enriched" is explicit so nobody trusts a silent zero.
3. **Idempotent ingestion:** SHA-256 file + event hashes with a unique index -
   re-uploading evidence never duplicates events, which matters for chain of custody.
4. **Encoded PowerShell:** I decode base64 UTF-16LE payloads and store the decoded
   command as evidence - the analyst sees what actually ran.
5. **Attack-chain correlation:** a spray -> success -> account creation ->
   scheduled task -> log clearing sequence becomes one CORR group, which is how
   real intrusions look in SIEMs.
6. **Security of the tool itself:** attacker-controlled log content is escaped on
   render, CSV exports are formula-injection safe, private IPs never go to VT.
7. **MongoDB design:** collections mirror the relational spec 1:1; unique indexes
   enforce idempotency; counters collection generates ALT-0001-style IDs.
