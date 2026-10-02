# SOC Alert Triage & Investigation Platform

An internal-analyst-style security operations platform: upload logs, detect
attacks with stateful rules, score risk with an explainable model, enrich
IOCs, map to MITRE ATT&CK, correlate attack chains, investigate with verdicts
and audit history, manage incidents, and export professional reports.

**Persistence: MongoDB** (pymongo). Start one with `docker compose up -d mongo`
or point `MONGO_URI` at any MongoDB.

## Quick start
```bash
docker compose up -d mongo
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # add VT_API_KEY optionally
streamlit run app.py
```
Then: **Log Analysis > Generate and ingest sample data > Run Detection Engine**,
open alerts, investigate, escalate to incidents, export reports.

## Supported log formats
| Format | Content |
|---|---|
| Windows event CSV | 4624/4625/4688/4720/4698/1102 |
| Sysmon CSV/JSON | Event 1 (process), 3 (network) |
| PowerShell log | 4103/4104 |
| Linux auth.log | SSH success/failure, sudo |
| Apache access log | web requests |
| Firewall CSV | src/dst/port/action (port-scan detection) |

Format is auto-detected; timestamps normalized to UTC ISO-8601; ingestion is
idempotent (SHA-256 file + event hashes); malformed rows are skipped and counted.

## Detection rules (12, all config-driven)
Brute Force T1110.001 · Password Spray T1110.003 · Multiple Failed Logins T1110 ·
Success After Failures T1110 · Suspicious PowerShell T1059.001 · Encoded
PowerShell T1059.001/T1027 (base64 UTF-16LE decoded) · Command Shell Execution
T1059.003 · Port Scanning T1046 · Suspicious Process Execution (LOLBins) T1218 ·
Account Creation T1136.001 · Scheduled Task T1053.005 · Log Clearing T1070.001.
One alert per group; allowlist suppression with visible counts; per-rule docs
in docs/detections/.

## Risk scoring
0-100 (Low <40, Medium 40-69, High 70-89, Critical 90+). Pluggable factors
(weights in config/scoring_weights.yaml): severity, repeat count, watchlist,
IOC reputation, asset criticality, MITRE mapping, correlation. Always shows a
readable breakdown; "IOC reputation: not enriched" is explicit, never a silent
zero. No randomness.

## Threat intelligence
Local watchlist (SAMPLE/OFFLINE data, no key needed) + VirusTotal API v3.
VT is rate-limited (4/min, 500/day free tier), handles 429/timeouts, caches in
MongoDB with TTL, enriches on demand only, and NEVER sends private IPs,
internal hostnames, or usernames. Sources are always labeled (VirusTotal /
Local watchlist / Not enriched) - results are never fabricated.

## Investigation & incidents
Status machine (New/Investigating/Resolved/Closed) with validated transitions;
verdicts (True Positive / False Positive / Benign) require written reasoning;
every action is written to an audit history; per-detection triage checklists;
decoded PowerShell payloads; related alerts and correlation groups inline.
Incidents aggregate alerts, IOCs, MITRE techniques, a generic timeline
(event vs recorded time distinguished), and typed evidence.

## Reports
Self-contained HTML + Markdown incident reports (Jinja2, autoescaped), plus a
formula-injection-safe CSV export of alerts.

## Security
No hard-coded secrets (.env, pre-commit secret scanning), parameterized BSON
queries only, html.escape on all log-derived rendering, upload limits,
safe parsing (no eval, no catastrophic regex), internal data never leaves
the platform.

## Testing
```bash
ruff check . && pytest -q
```
Covers parsers, normalization, all key detections, scoring boundaries
(0/39-40/69-70/89-90/100 cap), IOC extraction (private-IP exclusion, false
matches, defanging), idempotent ingestion, allowlist, cache TTL, correlation
chains, and mocked VirusTotal behavior (never real calls).

## Limitations & future work
No auth/multi-user (v1 scope); VT free-tier quota; syslog year is an analyst
setting; ML scoring and PDF export are future work.
