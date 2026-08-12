"""fuzzer.fuzz_body_targets — POST/JSON body fuzzing testleri (Session.request mock'lu).

Query fuzzer'ıyla AYNI detektörleri kullandığını, ama enjeksiyonu JSON body alanına
yaptığını doğrular."""

import pytest

from bugtool.fuzzer import ParamFuzzer
import bugtool.payloads as P


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


def _make_request(record=None):
    def _req(self, method, url, headers=None, params=None, json=None, timeout=None,
             allow_redirects=False, verify=False):
        if record is not None:
            record.append({"method": method, "url": url, "json": json})
        val = " ".join(str(v) for v in json.values()) if isinstance(json, dict) else ""
        low = val.lower()
        if any(s in low for s in ("<svg", "onload", "onerror", "<script", "ontoggle")):
            return FakeResp(text=f"<html> {val} </html>")     # XSS ham yansıması
        if P.REDIRECT_HOST in low:
            return FakeResp(status_code=302, headers={"Location": f"https://{P.REDIRECT_HOST}/x"})
        return FakeResp(text="ok normal")
    return _req


def _fuzzer(monkeypatch, classes, record=None):
    import requests
    monkeypatch.setattr(requests.sessions.Session, "request", _make_request(record))
    fz = ParamFuzzer(classes=classes, delay=0.0, max_requests=100)
    if not fz.available:
        pytest.skip("requests kurulu değil")
    return fz


def _target(method="POST", body_params=None):
    body_params = body_params or {"q": ["xss"]}
    return {"url": "https://api.example.com/v1/comment", "method": method,
            "params": {}, "body_params": body_params,
            "body_template": {k: "1" for k in body_params}}


def test_body_xss_reflection(monkeypatch):
    rec = []
    fz = _fuzzer(monkeypatch, ["xss"], rec)
    out = fz.fuzz_body_targets([_target()])
    assert any(f["class"] == "xss" and f.get("location") == "body" for f in out)
    # İstek gerçekten POST + JSON body ile gitti
    assert any(r["method"] == "POST" and isinstance(r["json"], dict) for r in rec)


def test_body_open_redirect(monkeypatch):
    fz = _fuzzer(monkeypatch, ["open_redirect"])
    out = fz.fuzz_body_targets([_target(body_params={"next": ["open_redirect"]})])
    assert any(f["class"] == "open_redirect" and f.get("location") == "body" for f in out)


def test_body_no_finding_when_not_reflected(monkeypatch):
    import requests
    monkeypatch.setattr(requests.sessions.Session, "request",
                        lambda self, method, url, **kw: FakeResp(text="static page, nothing"))
    fz = ParamFuzzer(classes=["xss"], delay=0.0, max_requests=100)
    if not fz.available:
        pytest.skip("requests yok")
    assert fz.fuzz_body_targets([_target()]) == []


def test_body_scope_gating(monkeypatch):
    fz = _fuzzer(monkeypatch, ["xss"])
    fz.scope_checker = lambda h: h == "allowed.example"
    out = fz.fuzz_body_targets([_target()])   # api.example.com kapsam-dışı
    assert out == []


def test_body_skips_target_without_body_params(monkeypatch):
    fz = _fuzzer(monkeypatch, ["xss"])
    out = fz.fuzz_body_targets([{"url": "https://api.example.com/x", "method": "POST",
                                 "params": {}, "body_params": {}}])
    assert out == []


def test_build_body_replaces_only_target():
    body = ParamFuzzer._build_body({"a": "1", "b": "2"}, "a", "PAYLOAD")
    assert body == {"a": "PAYLOAD", "b": "2"}
