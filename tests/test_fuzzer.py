"""Aktif fuzzer testleri — requests.get mock'lanır (GERÇEK ağ YOK).

Detection akışı: payload bas → sahte cevap → detektör → POTANSİYEL bulgu. Ayrıca
scope-gating ve max_requests cap'i doğrular (güvenlik korkulukları)."""

from urllib.parse import unquote

import pytest

import bugtool.payloads as P
from bugtool.fuzzer import ParamFuzzer


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


def _fake_get(url, headers=None, timeout=None, allow_redirects=False, verify=False):
    """URL içeriğine göre zafiyet cevabı simüle eder."""
    import re
    raw = url
    unq = unquote(url)
    low = unq.lower()
    mm = re.search(r"bgtl[a-z0-9]{6}", raw)
    marker = mm.group(0) if mm else ""

    # XSS yansıması (tırnak içerdiği için SQLi'den ÖNCE kontrol)
    if any(s in low for s in ("<svg", "onerror", "<script", "onload", "ontoggle")):
        if marker:
            return FakeResp(text=f"<html> x <svg/onload=alert({marker})> y</html>")
        return FakeResp(text="reflected")
    if P.REDIRECT_HOST in low:
        return FakeResp(status_code=302, headers={"Location": f"https://{P.REDIRECT_HOST}/x"})
    if "bgtl-test" in low and marker:
        return FakeResp(headers={"Bgtl-Test": marker})
    if "passwd" in low:
        return FakeResp(text="root:x:0:0:root:/root:/bin/bash")
    if f"{P.SSTI_A}*{P.SSTI_B}" in unq:
        return FakeResp(text=f"answer {P.SSTI_RESULT} ok")
    if "169.254.169.254" in low or "metadata" in low:
        return FakeResp(text="ami-id: ami-1234")
    if "'" in unq or '"' in unq:
        return FakeResp(text="You have an error in your SQL syntax; check the MySQL server")
    return FakeResp(text="ok normal page")


@pytest.fixture
def patch_requests(monkeypatch):
    import requests
    monkeypatch.setattr(requests, "get", _fake_get)


def _classes_of(findings):
    return {f["class"] for f in findings}


def test_sqli_error(patch_requests):
    fz = ParamFuzzer()
    targets = [{"url": "http://a.example.com/p?id=1", "params": {"id": ["sqli"]}}]
    findings = fz.fuzz_targets(targets)
    assert "sqli" in _classes_of(findings)
    f = next(f for f in findings if f["class"] == "sqli")
    assert f["status"] == "unverified"
    assert f["severity"] == "high"


def test_lfi(patch_requests):
    fz = ParamFuzzer()
    targets = [{"url": "http://a.example.com/p?file=a", "params": {"file": ["lfi"]}}]
    assert "lfi" in _classes_of(fz.fuzz_targets(targets))


def test_open_redirect(patch_requests):
    fz = ParamFuzzer()
    targets = [{"url": "http://a.example.com/go?next=/home", "params": {"next": ["open_redirect"]}}]
    assert "open_redirect" in _classes_of(fz.fuzz_targets(targets))


def test_xss_reflection(patch_requests):
    fz = ParamFuzzer()
    targets = [{"url": "http://a.example.com/s?q=1", "params": {"q": ["xss"]}}]
    assert "xss" in _classes_of(fz.fuzz_targets(targets))


def test_ssti(patch_requests):
    fz = ParamFuzzer()
    targets = [{"url": "http://a.example.com/t?tpl=x", "params": {"tpl": ["ssti"]}}]
    assert "ssti" in _classes_of(fz.fuzz_targets(targets))


def test_no_false_positive_on_clean(patch_requests):
    fz = ParamFuzzer(classes=["cmdi"])   # zaman-tabanlı; mock hızlı döner → gecikme yok
    targets = [{"url": "http://a.example.com/p?cmd=ls", "params": {"cmd": ["cmdi"]}}]
    assert fz.fuzz_targets(targets) == []


def test_scope_gating_blocks_out_of_scope(patch_requests):
    fz = ParamFuzzer(scope_checker=lambda host: host.endswith("inscope.com"))
    targets = [{"url": "http://evil.com/p?id=1", "params": {"id": ["sqli"]}}]
    findings = fz.fuzz_targets(targets)
    assert findings == []
    assert fz._sent == 0          # kapsam-dışına HİÇ istek gitmedi


def test_max_requests_cap(patch_requests):
    fz = ParamFuzzer(max_requests=3)
    targets = [{"url": "http://a.example.com/p?id=1&q=2&file=3",
                "params": {"id": ["sqli"], "q": ["xss"], "file": ["lfi"]}}]
    fz.fuzz_targets(targets)
    assert fz._sent <= 3          # cap aşılmadı


def test_unavailable_returns_empty():
    fz = ParamFuzzer()
    fz.available = False
    assert fz.fuzz_targets([{"url": "http://a.example.com/p?id=1",
                             "params": {"id": ["sqli"]}}]) == []


def test_build_url_preserves_encoding():
    # önceden encode edilmiş payload çift-encode edilmemeli
    u = ParamFuzzer._build_url("http://a.example.com/p?x=1", "x", "%2e%2e%2fetc")
    assert "%2e%2e%2fetc" in u
    assert "%252e" not in u
