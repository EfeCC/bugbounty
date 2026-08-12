"""exposures — native ifşa/misconfig kontrolü testleri (requests mock'lu, GERÇEK ağ YOK).

test_newmodules.py'deki desenle aynı: requests.Session().get monkeypatch'lenir. `handler`
istenen path'e göre farklı cevap döndürebilsin diye url'i inceler."""

import json

import requests

from bugtool import exposures


class _Resp:
    def __init__(self, text="", status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}

    def json(self):
        return json.loads(self.text)


def _patch(monkeypatch, handler):
    def fake_get(self, url, **kw):
        return handler(url, **kw)
    monkeypatch.setattr(requests.sessions.Session, "get", fake_get)


def test_detects_env_file(monkeypatch):
    def handler(url, **kw):
        if url.endswith("/.env"):
            return _Resp(text="APP_KEY=base64:xxxx\nDB_PASSWORD=secret123\n",
                         headers={"content-type": "text/plain"})
        return _Resp(text="not found", status=404)
    _patch(monkeypatch, handler)
    out = exposures.check(["https://api.example.com"], concurrency=1)
    assert any(f["class"] == "env_exposure" and f["severity"] == "high" for f in out)


def test_no_fp_on_html_env(monkeypatch):
    # SPA her yola 200 + html döner → .env düz metin değil, elenmeli.
    def handler(url, **kw):
        return _Resp(text="<html><body>App</body></html>", status=200,
                     headers={"content-type": "text/html"})
    _patch(monkeypatch, handler)
    assert exposures.check(["https://x.example.com"], concurrency=1) == []


def test_soft404_catchall_suppressed(monkeypatch):
    # Host var olmayan yola da 200 + AYNI gövde dönüyor (catch-all). Gövde .env imzası
    # içerse bile (aynı jenerik cevap) → bulgu ÜRETİLMEMELİ.
    def handler(url, **kw):
        return _Resp(text="DB_PASSWORD=fake\n", status=200,
                     headers={"content-type": "text/plain"})
    _patch(monkeypatch, handler)
    # soft-404 gövdesi ile .env gövdesi bire bir aynı → catch-all koruması eler.
    assert exposures.check(["https://x.example.com"], concurrency=1) == []


def test_detects_aws_credentials_critical(monkeypatch):
    def handler(url, **kw):
        if url.endswith("/.aws/credentials"):
            return _Resp(text="[default]\naws_access_key_id=AKIAxxxx\naws_secret_access_key=yyy\n",
                         headers={"content-type": "text/plain"})
        return _Resp(text="nope", status=404)
    _patch(monkeypatch, handler)
    out = exposures.check(["https://x.example.com"], concurrency=1)
    assert any(f["class"] == "aws_credentials_exposure" and f["severity"] == "critical"
               for f in out)


def test_detects_actuator_env(monkeypatch):
    def handler(url, **kw):
        if url.endswith("/actuator/env"):
            return _Resp(text='{"activeProfiles":["prod"],"propertySources":[]}',
                         headers={"content-type": "application/json"})
        return _Resp(text="nope", status=404)
    _patch(monkeypatch, handler)
    out = exposures.check(["https://x.example.com"], concurrency=1)
    assert any(f["class"] == "spring_actuator_env" for f in out)


def test_status_not_200_ignored(monkeypatch):
    # .env var ama 403 dönüyor (erişilemiyor) → bulgu YOK.
    def handler(url, **kw):
        if url.endswith("/.env"):
            return _Resp(text="DB_PASSWORD=x", status=403,
                         headers={"content-type": "text/plain"})
        return _Resp(text="nope", status=404)
    _patch(monkeypatch, handler)
    assert exposures.check(["https://x.example.com"], concurrency=1) == []


def test_scope_gate_blocks_out_of_scope(monkeypatch):
    def handler(url, **kw):
        return _Resp(text="DB_PASSWORD=x", headers={"content-type": "text/plain"})
    _patch(monkeypatch, handler)
    out = exposures.check(["https://x.example.com"], concurrency=1,
                          scope_checker=lambda h: False)
    assert out == []


def test_empty_hosts_returns_empty():
    assert exposures.check([], concurrency=1) == []


def test_findings_have_standard_schema(monkeypatch):
    def handler(url, **kw):
        if url.endswith("/phpinfo.php"):
            return _Resp(text="<title>phpinfo()</title> phpinfo() PHP Version 8.1 Zend Engine",
                         headers={"content-type": "text/html"})
        return _Resp(text="nope", status=404)
    _patch(monkeypatch, handler)
    out = exposures.check(["https://x.example.com"], concurrency=1)
    assert out
    f = out[0]
    for key in ("title", "severity", "description", "evidence", "reproduction",
                "cvss", "class", "status"):
        assert key in f
    assert f["status"] == "unverified"
