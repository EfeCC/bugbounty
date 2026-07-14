"""Aktif fuzzer testleri — requests.get mock'lanır (GERÇEK ağ YOK).

Detection akışı: payload bas → sahte cevap → detektör → POTANSİYEL bulgu. Ayrıca
scope-gating ve max_requests cap'i doğrular (güvenlik korkulukları)."""

import re
from urllib.parse import unquote

import pytest

import bugtool.payloads as P
import bugtool.timing as timing
from bugtool.fuzzer import ParamFuzzer


def _dose_request(self, url, marker=""):
    """Sahte _request: URL'deki sleep dozuna göre elapsed döndürür (gerçek enjeksiyon gibi
    süre ≈ 0.1 + doz). Timing-ladder'ı ağsız/deterministik test etmek için."""
    self._sent += 1
    m = re.search(r"sleep[\s(%]*?(\d+)", unquote(url), re.I)
    dose = float(m.group(1)) if m else 0.0
    return {"body": "", "headers": {}, "status": 200, "elapsed": 0.1 + dose,
            "baseline_elapsed": 0.0, "baseline_body": "", "marker": marker}


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
    # Fuzzer artık requests.Session() kullanıyor → Session.get'i mock'la
    import requests

    def _session_get(self, url, **kw):
        return _fake_get(url, **kw)

    monkeypatch.setattr(requests.sessions.Session, "get", _session_get)


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


def test_backoff_on_consecutive_blocks(monkeypatch):
    # Hedef art arda 429 (rate-limit) dönüyor → backoff tetiklenip erken durmalı
    import requests
    monkeypatch.setattr(requests.sessions.Session, "get",
                        lambda self, url, **kw: FakeResp(status_code=429))
    fz = ParamFuzzer(block_threshold=3)
    targets = [{"url": f"http://a.example.com/p{i}?id=1", "params": {"id": ["sqli"]}}
               for i in range(6)]
    fz.fuzz_targets(targets)
    assert fz.backoff_triggered
    assert fz._sent < 6 * 5          # 6 endpoint'in tümü test edilmeden durdu


def test_sqli_baseline_fp_suppressed(monkeypatch):
    # Genel hata sayfası HER istekte (baseline dahil) SQL hatası gösteriyor → FP,
    # payload'ın sebep olduğu bir şey değil → sqli bulgusu ÜRETİLMEMELİ
    import requests
    monkeypatch.setattr(requests.sessions.Session, "get",
                        lambda self, url, **kw: FakeResp(
                            text="You have an error in your SQL syntax; check the MySQL server"))
    fz = ParamFuzzer()
    targets = [{"url": "http://a.example.com/p?id=1", "params": {"id": ["sqli"]}}]
    assert "sqli" not in _classes_of(fz.fuzz_targets(targets))


def test_timing_ladder_fires(monkeypatch):
    # Temiz doğrusal doz-yanıt (süre ≈ 0.1 + doz) → zaman-tabanlı SQLi FIRED
    monkeypatch.setattr(ParamFuzzer, "_request", _dose_request)
    fz = ParamFuzzer(ladder_rounds=2)
    targets = [{"url": "http://a.example.com/p?id=1", "params": {"id": ["sqli"]}}]
    sqli = [f for f in fz.fuzz_targets(targets) if f["class"] == "sqli"]
    assert sqli
    assert sqli[0]["verdict"] == "fired"


def test_timing_ladder_not_fired_drops(monkeypatch):
    # Ucuz probe yavaş (fire) AMA merdiven NOT_FIRED (gürültü) → bulgu düşer
    monkeypatch.setattr(ParamFuzzer, "_request", _dose_request)
    monkeypatch.setattr(ParamFuzzer, "_timing_ladder",
                        lambda self, u, p, t, b: (timing.NOT_FIRED, 0.0))
    fz = ParamFuzzer()
    targets = [{"url": "http://a.example.com/p?id=1", "params": {"id": ["sqli"]}}]
    assert "sqli" not in _classes_of(fz.fuzz_targets(targets))


def test_timing_ladder_inconclusive(monkeypatch):
    # Merdiven INCONCLUSIVE → bulgu üretilir ama 'inconclusive' etiketli, düşük güven
    monkeypatch.setattr(ParamFuzzer, "_request", _dose_request)
    monkeypatch.setattr(ParamFuzzer, "_timing_ladder",
                        lambda self, u, p, t, b: (timing.INCONCLUSIVE, 0.4))
    fz = ParamFuzzer()
    targets = [{"url": "http://a.example.com/p?id=1", "params": {"id": ["sqli"]}}]
    sqli = [f for f in fz.fuzz_targets(targets) if f["class"] == "sqli"]
    assert sqli
    assert sqli[0]["verdict"] == "inconclusive"
    assert sqli[0]["status"] == "inconclusive"
    assert sqli[0]["confidence"] == "low"
