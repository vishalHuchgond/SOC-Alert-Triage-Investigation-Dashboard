from ioc.extractor import extract, is_enrichable, refang
from utils.sanitize import csv_safe, escape_html


def test_private_ip_excluded_from_enrichment():
    r = extract("login from 10.1.2.3 and 203.0.113.99")
    vals = [i["value"] for i in r.iocs]
    assert "203.0.113.99" in vals and "10.1.2.3" in vals
    assert is_enrichable({"type": "ipv4", "value": "203.0.113.99"})
    assert not is_enrichable({"type": "ipv4", "value": "10.1.2.3"})


def test_filename_not_domain():
    r = extract("ran payload.exe from evil.example")
    assert any(o["value"] == "payload.exe" for o in r.observables)
    assert not any(i["value"] == "payload.exe" for i in r.iocs)
    assert any(i["value"] == "evil.example" for i in r.iocs)


def test_version_string_not_ip():
    assert extract("Windows 10.0.19045.1 build").iocs == []


def test_defang_and_hashes():
    r = extract(refang("hxxp://malware[.]example/path " + "a" * 64 + " " + "b" * 40 + " " + "c" * 32))
    types = {i["type"] for i in r.iocs}
    assert {"url", "sha256", "sha1", "md5"} <= types


def test_html_escaping():
    assert escape_html("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_csv_formula_injection():
    assert csv_safe("=cmd|'/c calc'!A1") == "'=cmd|'/c calc'!A1"
    assert csv_safe("+x") == "'+x" and csv_safe("-x") == "'-x" and csv_safe("@x") == "'@x"
    assert csv_safe("normal") == "normal"
