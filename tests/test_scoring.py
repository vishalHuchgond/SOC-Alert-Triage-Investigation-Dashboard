from scoring.risk_score import score_alert, score_band

W = {"severity": {"low": 10, "medium": 20, "high": 30, "critical": 40},
     "repeat": {"points_per_event": 4, "max_extra_events": 5}, "watchlist_hit": 20,
     "ioc_reputation": {"malicious": 25, "suspicious": 10}, "asset_criticality": 15,
     "mitre_mapped": 10, "correlated": 10}


def test_low_score_low_confidence():
    score, bd, conf = score_alert({"severity": "low", "repeat_count": 1}, {}, W)
    assert score == 10 and conf == "low"


def test_cap_at_100_and_high_confidence():
    alert = {"severity": "critical", "repeat_count": 99, "mitre_id": "T1110"}
    ctx = {"source_flagged": True, "asset_critical": True, "ioc_reputation": "malicious"}
    score, bd, conf = score_alert(alert, ctx, W)
    assert score == 100 and conf == "high"
    assert any("+10 MITRE T1110" in line for line in bd)


def test_band_boundaries():
    assert score_band(0) == "low" and score_band(39) == "low"
    assert score_band(40) == "medium" and score_band(69) == "medium"
    assert score_band(70) == "high" and score_band(89) == "high"
    assert score_band(90) == "critical" and score_band(100) == "critical"


def test_not_enriched_is_visible_not_silent_zero():
    _, bd, _ = score_alert({"severity": "medium", "repeat_count": 1}, {}, W)
    assert any("not enriched" in line for line in bd)


def test_no_randomness():
    alert = {"severity": "high", "repeat_count": 3}
    ctx = {"source_flagged": True}
    assert score_alert(alert, ctx, W)[0] == score_alert(alert, ctx, W)[0]
