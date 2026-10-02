from utils.time import utcnow


def test_idempotent_reingestion(store):
    e = {"timestamp": utcnow(), "source_ip": "10.0.0.1", "event_hash": "h1",
         "raw_event": "raw", "line_number": 1}
    assert store.insert_events([e]) == (1, 0)
    assert store.insert_events([e]) == (0, 1)  # duplicate skipped


def test_human_readable_ids(store):
    assert store.next_id("ALT") == "ALT-0001"
    assert store.next_id("ALT") == "ALT-0002"
    assert store.next_id("CORR") == "CORR-001"
    assert store.next_id("INC") == "INC-0001"


def test_allowlist_crud(store):
    store.add_allowlist_entry({"type": "source_ip", "value": "10.10.5.5", "reason": "scanner"})
    assert store.is_allowlisted("10.10.5.5")
    assert not store.is_allowlisted("8.8.8.8")
    store.remove_allowlist_entry("10.10.5.5")
    assert not store.is_allowlisted("10.10.5.5")


def test_enrichment_cache_ttl(store):
    store.cache_set("203.0.113.99", "ipv4", {"reputation": "malicious", "source": "VirusTotal"})
    assert store.cache_get("203.0.113.99", ttl_hours=24)["reputation"] == "malicious"
    assert store.cache_get("203.0.113.99", ttl_hours=0) is None  # expired


def test_alert_lifecycle(store):
    from bson import ObjectId
    eid = store.db.events.insert_one({"timestamp": utcnow(), "event_hash": "eh",
                                      "raw_event": "r"}).inserted_id
    alert = store.create_alert({"detection_name": "brute_force", "severity": "high",
                                "event_ids": [eid], "source_ip": "1.2.3.4"})
    assert alert["alert_id"] == "ALT-0001" and alert["status"] == "New"
    store.update_alert(alert["alert_id"], {"status": "Investigating"})
    assert store.get_alert("ALT-0001")["status"] == "Investigating"
