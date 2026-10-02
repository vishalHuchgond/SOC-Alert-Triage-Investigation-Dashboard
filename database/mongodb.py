"""MongoDB persistence layer.

Replaces the SQLite design from the original spec 1:1 with collections:
source_files, events, alerts, iocs, ioc_enrichment_cache, correlation_groups,
investigations, investigation_history, analyst_notes, incidents, timeline,
evidence, allowlist, counters (human-readable ID sequences), settings,
schema_version (migrations).

- All queries are parameterized (BSON documents, never string-built).
- Timestamps are UTC ISO-8601 strings.
- Idempotent ingestion via unique event_hash index.
"""
from __future__ import annotations

from typing import Any

import pandas as pd
from pymongo import ASCENDING, MongoClient, ReturnDocument, UpdateOne
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError, PyMongoError

from config.settings import Settings, get_settings
from utils.time import utcnow

SCHEMA_VERSION = 1


class MongoStore:
    """Thin, parameterized data-access wrapper around a MongoDB database."""

    def __init__(self, uri: str | None = None, db_name: str | None = None,
                 settings: Settings | None = None, client: MongoClient | None = None) -> None:
        self._settings = settings or get_settings()
        if client is not None:
            self.client = client
        else:
            self.client: MongoClient = MongoClient(
                uri or self._settings.mongo_uri, serverSelectionTimeoutMS=4000
            )
        self.db: Database = self.client[db_name or self._settings.mongo_db]

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def ping(self) -> bool:
        try:
            self.client.admin.command("ping")
            return True
        except PyMongoError:
            return False

    def init(self) -> "MongoStore":
        ev = self.db.events
        ev.create_index([("event_hash", ASCENDING)], unique=True)
        ev.create_index([("timestamp", ASCENDING)])
        ev.create_index([("source_ip", ASCENDING)])
        ev.create_index([("username", ASCENDING)])
        ev.create_index([("event_type", ASCENDING)])
        ev.create_index([("log_source", ASCENDING)])

        self.db.source_files.create_index([("file_hash", ASCENDING)], unique=True)

        al = self.db.alerts
        al.create_index([("alert_id", ASCENDING)], unique=True)
        al.create_index([("status", ASCENDING)])
        al.create_index([("severity", ASCENDING)])
        al.create_index([("detection_name", ASCENDING)])
        al.create_index([("created_at", ASCENDING)])

        self.db.iocs.create_index([("value", ASCENDING)], unique=True)
        cache = self.db.ioc_enrichment_cache
        cache.create_index([("ioc_value", ASCENDING)], unique=True)
        cache.create_index([("fetched_at", ASCENDING)])

        self.db.correlation_groups.create_index([("group_id", ASCENDING)], unique=True)
        self.db.investigations.create_index([("alert_id", ASCENDING)])
        self.db.investigation_history.create_index([("alert_id", ASCENDING), ("at", ASCENDING)])
        self.db.incidents.create_index([("incident_id", ASCENDING)], unique=True)
        self.db.timeline.create_index(
            [("entity_type", ASCENDING), ("entity_id", ASCENDING), ("event_time", ASCENDING)]
        )
        self.db.evidence.create_index([("incident_id", ASCENDING)])
        self.db.allowlist.create_index([("value", ASCENDING)], unique=True)

        doc = self.db.schema_version.find_one_and_update(
            {"_id": "schema"},
            {"$setOnInsert": {"version": SCHEMA_VERSION, "applied_at": utcnow()}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        self.version: int = doc["version"]
        return self

    # ------------------------------------------------------------------
    # human-readable IDs (ALT-0001, INC-0001, CORR-001, EV-0001)
    # ------------------------------------------------------------------
    def next_id(self, prefix: str) -> str:
        width = 4 if prefix in ("ALT", "INC", "EV") else 3
        doc = self.db.counters.find_one_and_update(
            {"_id": prefix}, {"$inc": {"seq": 1}},
            upsert=True, return_document=ReturnDocument.AFTER,
        )
        return f"{prefix}-{doc['seq']:0{width}d}"

    # ------------------------------------------------------------------
    # source files & events
    # ------------------------------------------------------------------
    def get_source_file_by_hash(self, file_hash: str) -> dict | None:
        return self.db.source_files.find_one({"file_hash": file_hash})

    def insert_source_file(self, meta: dict) -> dict:
        meta.setdefault("ingested_at", utcnow())
        try:
            self.db.source_files.insert_one(meta)
        except DuplicateKeyError:
            pass
        return meta

    def list_source_files(self) -> list[dict]:
        return list(self.db.source_files.find().sort("ingested_at", -1))

    def insert_events(self, events: list[dict]) -> tuple[int, int]:
        """Bulk upsert by unique event_hash. Returns (inserted, duplicates_skipped)."""
        if not events:
            return 0, 0
        ops = [UpdateOne({"event_hash": e["event_hash"]}, {"$setOnInsert": e}, upsert=True)
               for e in events]
        result = self.db.events.bulk_write(ops, ordered=False)
        inserted = len(result.upserted_ids)
        return inserted, len(events) - inserted

    def events_df(self, query: dict | None = None) -> pd.DataFrame:
        cursor = self.db.events.find(query or {})
        df = pd.DataFrame(list(cursor))
        if not df.empty:
            df["_id"] = df["_id"].astype(str)
        return df

    def get_event(self, event_id: str) -> dict | None:
        from bson import ObjectId
        try:
            return self.db.events.find_one({"_id": ObjectId(event_id)})
        except Exception:
            return None

    # ------------------------------------------------------------------
    # alerts
    # ------------------------------------------------------------------
    def create_alert(self, alert: dict) -> dict:
        alert["alert_id"] = self.next_id("ALT")
        alert.setdefault("status", "New")
        alert.setdefault("verdict", None)
        alert.setdefault("verdict_reason", None)
        alert.setdefault("created_at", utcnow())
        alert.setdefault("correlation_group", None)
        self.db.alerts.insert_one(alert)
        ids = alert.get("event_ids") or []
        if ids:
            self.db.events.update_many(
                {"_id": {"$in": ids}},
                {"$addToSet": {"alert_ids": alert["alert_id"]}},
            )
        return alert

    def list_alerts(self, query: dict | None = None, limit: int = 500) -> list[dict]:
        return list(self.db.alerts.find(query or {}).sort("created_at", -1).limit(limit))

    def get_alert(self, alert_id: str) -> dict | None:
        return self.db.alerts.find_one({"alert_id": alert_id})

    def find_alert(self, query: dict) -> dict | None:
        return self.db.alerts.find_one(query)

    def update_alert(self, alert_id: str, changes: dict) -> None:
        changes["updated_at"] = utcnow()
        self.db.alerts.update_one({"alert_id": alert_id}, {"$set": changes})

    def alerts_for_entity(self, field: str, value: str, exclude_id: str | None = None) -> list[dict]:
        q: dict[str, Any] = {field: value, field: {"$ne": None}}
        q = {field: value}
        if exclude_id:
            q["alert_id"] = {"$ne": exclude_id}
        return list(self.db.alerts.find(q).sort("created_at", -1).limit(20))

    # ------------------------------------------------------------------
    # investigations (status / verdict / history / notes)
    # ------------------------------------------------------------------
    def add_history(self, entry: dict) -> None:
        entry.setdefault("at", utcnow())
        self.db.investigation_history.insert_one(entry)

    def history_for(self, alert_id: str) -> list[dict]:
        return list(self.db.investigation_history.find({"alert_id": alert_id}).sort("at", 1))

    def add_note(self, note: dict) -> None:
        note.setdefault("created_at", utcnow())
        self.db.analyst_notes.insert_one(note)

    def notes_for(self, alert_id: str) -> list[dict]:
        return list(self.db.analyst_notes.find({"alert_id": alert_id}).sort("created_at", 1))

    # ------------------------------------------------------------------
    # IOCs & enrichment cache
    # ------------------------------------------------------------------
    def upsert_iocs(self, iocs: list[dict]) -> list[str]:
        """Upsert IOCs by unique value; return their values."""
        values = []
        for ioc in iocs:
            values.append(ioc["value"])
            self.db.iocs.update_one(
                {"value": ioc["value"]},
                {"$setOnInsert": {"type": ioc["type"], "first_seen": ioc.get("first_seen")},
                 "$set": {"last_seen": ioc.get("last_seen")}},
                upsert=True,
            )
        return values

    def link_iocs_to_alert(self, alert_id: str, ioc_values: list[str]) -> None:
        self.db.iocs.update_many(
            {"value": {"$in": ioc_values}}, {"$addToSet": {"alert_ids": alert_id}}
        )
        self.db.alerts.update_one(
            {"alert_id": alert_id}, {"$addToSet": {"ioc_values": {"$each": ioc_values}}}
        )

    def list_iocs(self, query: dict | None = None, limit: int = 500) -> list[dict]:
        return list(self.db.iocs.find(query or {}).sort("last_seen", -1).limit(limit))

    def get_ioc(self, value: str) -> dict | None:
        return self.db.iocs.find_one({"value": value})

    def update_ioc(self, value: str, changes: dict) -> None:
        self.db.iocs.update_one({"value": value}, {"$set": changes})

    def cache_get(self, ioc_value: str, ttl_hours: int) -> dict | None:
        from utils.time import epoch_seconds
        doc = self.db.ioc_enrichment_cache.find_one({"ioc_value": ioc_value})
        if not doc:
            return None
        age_hours = (epoch_seconds(utcnow()) - epoch_seconds(doc["fetched_at"])) / 3600
        if age_hours >= ttl_hours:
            return None
        return doc.get("result")

    def cache_set(self, ioc_value: str, ioc_type: str, result: dict) -> None:
        self.db.ioc_enrichment_cache.update_one(
            {"ioc_value": ioc_value},
            {"$set": {"ioc_value": ioc_value, "ioc_type": ioc_type,
                      "result": result, "fetched_at": utcnow()}},
            upsert=True,
        )

    # ------------------------------------------------------------------
    # allowlist / suppression
    # ------------------------------------------------------------------
    def list_allowlist(self) -> list[dict]:
        return list(self.db.allowlist.find().sort("added_at", -1))

    def add_allowlist_entry(self, entry: dict) -> None:
        entry.setdefault("added_at", utcnow())
        try:
            self.db.allowlist.insert_one(entry)
        except DuplicateKeyError:
            pass

    def remove_allowlist_entry(self, value: str) -> None:
        self.db.allowlist.delete_one({"value": value})

    def is_allowlisted(self, *values: str | None) -> bool:
        vals = [v for v in values if v]
        if not vals:
            return False
        return self.db.allowlist.count_documents({"value": {"$in": vals}}) > 0

    # ------------------------------------------------------------------
    # correlation
    # ------------------------------------------------------------------
    def save_correlation_group(self, group: dict) -> dict:
        if "group_id" not in group:
            group["group_id"] = self.next_id("CORR")
        group.setdefault("created_at", utcnow())
        self.db.correlation_groups.update_one(
            {"group_id": group["group_id"]}, {"$set": group}, upsert=True
        )
        return group

    def list_correlation_groups(self) -> list[dict]:
        return list(self.db.correlation_groups.find().sort("created_at", -1))

    def get_correlation_group(self, group_id: str) -> dict | None:
        return self.db.correlation_groups.find_one({"group_id": group_id})

    # ------------------------------------------------------------------
    # incidents, timeline, evidence
    # ------------------------------------------------------------------
    def create_incident(self, doc: dict) -> dict:
        doc["incident_id"] = self.next_id("INC")
        doc.setdefault("status", "Open")
        doc.setdefault("created_at", utcnow())
        doc.setdefault("updated_at", doc["created_at"])
        doc.setdefault("notes", [])
        self.db.incidents.insert_one(doc)
        for alert_id in doc.get("alert_ids", []):
            self.db.alerts.update_one(
                {"alert_id": alert_id},
                {"$set": {"incident_id": doc["incident_id"], "status": "Resolved"}},
            )
        return doc

    def list_incidents(self) -> list[dict]:
        return list(self.db.incidents.find().sort("created_at", -1))

    def get_incident(self, incident_id: str) -> dict | None:
        return self.db.incidents.find_one({"incident_id": incident_id})

    def update_incident(self, incident_id: str, changes: dict) -> None:
        changes["updated_at"] = utcnow()
        self.db.incidents.update_one({"incident_id": incident_id}, {"$set": changes})

    def add_timeline(self, entry: dict) -> None:
        entry.setdefault("recorded_at", utcnow())
        self.db.timeline.insert_one(entry)

    def timeline_for(self, entity_type: str, entity_id: str) -> list[dict]:
        return list(self.db.timeline.find(
            {"entity_type": entity_type, "entity_id": entity_id}
        ).sort("event_time", 1))

    def add_evidence(self, doc: dict) -> dict:
        doc["evidence_id"] = self.next_id("EV")
        doc.setdefault("created_at", utcnow())
        self.db.evidence.insert_one(doc)
        return doc

    def evidence_for(self, incident_id: str) -> list[dict]:
        return list(self.db.evidence.find({"incident_id": incident_id}).sort("created_at", 1))

    # ------------------------------------------------------------------
    # settings (analyst name, syslog year stored in DB, env is fallback)
    # ------------------------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        doc = self.db.settings.find_one({"_id": key})
        return doc["value"] if doc else default

    def set_setting(self, key: str, value: Any) -> None:
        self.db.settings.update_one(
            {"_id": key}, {"$set": {"value": value}}, upsert=True
        )

    def counts(self) -> dict[str, int]:
        return {
            "events": self.db.events.count_documents({}),
            "alerts": self.db.alerts.count_documents({}),
            "iocs": self.db.iocs.count_documents({}),
            "incidents": self.db.incidents.count_documents({}),
            "source_files": self.db.source_files.count_documents({}),
        }
