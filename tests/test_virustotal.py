from threat_intel.virustotal import VirusTotalClient
from models.models import EnrichmentResult


class FakeResp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


def _client(store, monkeypatch, status=200, payload=None):
    from config.settings import Settings
    s = Settings(vt_api_key="fake-key-for-tests")
    c = VirusTotalClient(store, settings=s)
    monkeypatch.setattr("threat_intel.virustotal.requests.get",
                        lambda *a, **k: FakeResp(status, payload))
    return c


VT_PAYLOAD = {"data": {"attributes": {"last_analysis_stats":
                    {"malicious": 12, "suspicious": 1, "undetected": 60, "harmless": 5}}}}


def test_lookup_never_fabricates(store, monkeypatch):
    c = _client(store, monkeypatch, status=200, payload=VT_PAYLOAD)
    r = c.enrich({"type": "ipv4", "value": "203.0.113.99"})
    assert isinstance(r, EnrichmentResult) and r.source == "VirusTotal"
    assert r.reputation == "malicious" and r.malicious == 12


def test_rate_limit_429_graceful(store, monkeypatch):
    c = _client(store, monkeypatch, status=429)
    r = c.enrich({"type": "ipv4", "value": "203.0.113.99"})
    assert r.source == "Not enriched" and "unavailable" in r.reason


def test_private_ip_never_sent(store, monkeypatch):
    called = {"n": 0}
    def _boom(*a, **k):
        called["n"] += 1
        raise AssertionError("private IP must not be queried")
    monkeypatch.setattr("threat_intel.virustotal.requests.get", _boom)
    c = VirusTotalClient(store, settings=__import__("config.settings", fromlist=["Settings"]).Settings(vt_api_key="x"))
    r = c.enrich({"type": "ipv4", "value": "10.1.2.3"})
    assert called["n"] == 0 and r.source == "Not enriched"


def test_no_key_means_unavailable(store):
    from config.settings import Settings
    c = VirusTotalClient(store, settings=Settings(vt_api_key=None))
    assert not c.available
    r = c.enrich({"type": "domain", "value": "evil.example"})
    assert r.source == "Not enriched"
