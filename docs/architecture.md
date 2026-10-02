# Architecture

## Pipeline
LOG FILE -> PARSER -> NORMALIZER -> EVENTS (MongoDB) -> DETECTION ENGINE -> ALERTS
 -> RISK SCORING -> IOC EXTRACTION -> THREAT INTEL (watchlist + VirusTotal)
 -> MITRE MAPPING -> CORRELATION -> INVESTIGATION -> TP/FP/BENIGN
 -> INCIDENT -> TIMELINE + EVIDENCE -> REPORT (HTML/MD)

## MongoDB collections (replace SQLite schema 1:1)
- source_files 1--n events (source_file_id + line_number preserved for evidence)
- events n--n alerts (alert.event_ids; events.alert_ids back-reference)
- alerts 1--n iocs (iocs.alert_ids)
- ioc_enrichment_cache (TTL-checked per query; never query same IOC twice in TTL)
- correlation_groups (deterministic CORR-001 ids; attack_chains[])
- investigation_history (audit trail), analyst_notes
- incidents (embed alert_ids, ioc_values, mitre_ids), timeline (generic
  entity_type/entity_id), evidence
- allowlist (suppression before alert creation), counters (ID sequences),
  schema_version, settings

## Module boundaries
Every stage is an independent module with a small interface; the detection
engine walks rule modules via the `@rule` decorator and config thresholds,
so rules are added without touching engine code. Scoring factors are a list
of callables. UI never contains detection logic.
