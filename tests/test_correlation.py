from correlation.correlator import _is_subsequence, correlate
from utils.time import utcnow


def test_subsequence():
    assert _is_subsequence(["a", "b", "c"], ["x", "a", "y", "b", "c", "z"])
    assert not _is_subsequence(["a", "b", "c"], ["a", "c", "b"])


def test_attack_chain_detected(store):
    seq = ["password_spray", "success_after_failures", "account_creation",
           "scheduled_task_creation", "security_log_clearing"]
    for i, det in enumerate(seq):
        store.create_alert({"detection_name": det, "severity": "high",
                            "source_ip": "198.51.100.23", "username": "a.adams",
                            "hostname": "WS-12", "event_ids": [],
                            "earliest": utcnow(), "latest": utcnow(),
                            "risk_score": 50, "risk_breakdown": []})
    stats = correlate(store)
    assert stats["attack_chains_found"] >= 1
    groups = store.list_correlation_groups()
    assert any(g["attack_chains"] for g in groups)
    assert groups[0]["group_id"].startswith("CORR-")
