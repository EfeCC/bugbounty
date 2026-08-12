"""Ortağın eklediği 5 yeni modülün testleri — requests mock'lanır (GERÇEK ağ YOK).
takeover / ct_logs / secrets_scan / git_check / cors_check."""

import json

import requests

import bugtool.takeover as takeover
import bugtool.ct_logs as ct_logs
import bugtool.secrets_scan as secrets_scan
import bugtool.git_check as git_check
import bugtool.cors_check as cors_check


class _Resp:
    def __init__(self, text="", status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}

    def json(self):
        return json.loads(self.text)


def _patch_session_get(monkeypatch, handler):
    """requests.Session().get(...) çağrılarını handler(url, **kw) ile değiştirir."""
    def fake_get(self, url, **kw):
        return handler(url, **kw)
    monkeypatch.setattr(requests.sessions.Session, "get", fake_get)


# ── takeover ─────────────────────────────────────────────────────────────────
def test_takeover_detects_dangling(monkeypatch):
    monkeypatch.setattr(takeover, "have", lambda b: True)
    monkeypatch.setattr(takeover, "run",
                        lambda cmd, **k: {"stdout": "shop.example.com [foo.myshopify.com]\n",
                                          "success": True})
    _patch_session_get(monkeypatch,
                       lambda url, **kw: _Resp(text="Sorry, this shop is currently unavailable"))
    out = takeover.check(["shop.example.com"])
    assert len(out) == 1
    assert out[0]["class"] == "subdomain_takeover"
    assert out[0]["severity"] == "high"


def test_takeover_no_fp_when_service_active(monkeypatch):
    monkeypatch.setattr(takeover, "have", lambda b: True)
    monkeypatch.setattr(takeover, "run",
                        lambda cmd, **k: {"stdout": "shop.example.com [foo.myshopify.com]\n",
                                          "success": True})
    # CNAME shopify'e uyuyor AMA "unavailable" imzası yok → hâlâ aktif → bulgu YOK
    _patch_session_get(monkeypatch, lambda url, **kw: _Resp(text="Welcome to our store!"))
    assert takeover.check(["shop.example.com"]) == []


def test_takeover_skips_without_dnsx(monkeypatch):
    monkeypatch.setattr(takeover, "have", lambda b: False)
    assert takeover.check(["x.example.com"]) == []


# ── ct_logs ──────────────────────────────────────────────────────────────────
def test_ct_logs_fetch(monkeypatch):
    body = json.dumps([{"name_value": "a.example.com\nb.example.com"},
                       {"name_value": "*.example.com"}])
    monkeypatch.setattr(requests, "get", lambda url, **kw: _Resp(text=body, status=200))
    subs = ct_logs.fetch_subdomains("example.com")
    assert "a.example.com" in subs
    assert "b.example.com" in subs
    assert "example.com" in subs          # "*." öneki temizlendi


def test_ct_logs_graceful_on_error(monkeypatch):
    def boom(url, **kw):
        raise RuntimeError("crt.sh down")
    monkeypatch.setattr(requests, "get", boom)
    assert ct_logs.fetch_subdomains("example.com") == []


def test_ct_logs_requests_available():
    # requests bu test ortamında kurulu → True
    assert ct_logs.requests_available() is True


def test_ct_logs_requests_unavailable(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def blocked(name, *a, **kw):
        if name == "requests":
            raise ImportError("yok")
        return real_import(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", blocked)
    assert ct_logs.requests_available() is False


# ── secrets_scan ─────────────────────────────────────────────────────────────
def test_secrets_scan_finds_aws_key(monkeypatch):
    _patch_session_get(monkeypatch,
                       lambda url, **kw: _Resp(text='const k = "AKIA1234567890ABCDEF";'))
    out = secrets_scan.scan(["https://x.example.com/app.js"])
    assert len(out) == 1
    assert out[0]["class"] == "secret_leak"
    # secret TAM gösterilmemeli (maskeli)
    assert "AKIA1234567890ABCDEF" not in json.dumps(out)


def test_secrets_scan_filters_placeholder(monkeypatch):
    # AWS'in kendi örnek anahtarı ("...EXAMPLE") — placeholder, elenmeli
    _patch_session_get(monkeypatch,
                       lambda url, **kw: _Resp(text='key = "AKIAIOSFODNN7EXAMPLE";'))
    assert secrets_scan.scan(["https://x.example.com/app.js"]) == []


def test_secrets_scan_skips_cdn(monkeypatch):
    # 3.taraf/CDN JS → hiç indirilmemeli (boş liste, istek bile atılmaz)
    assert secrets_scan.scan(["https://code.jquery.com/jquery-3.6.0.min.js"]) == []


def test_secrets_mask():
    assert secrets_scan._mask("AKIA1234567890ABCDEF").startswith("AKIA")
    assert "1234567890" not in secrets_scan._mask("AKIA1234567890ABCDEF")


# ── git_check ────────────────────────────────────────────────────────────────
def test_git_check_detects_ref(monkeypatch):
    _patch_session_get(monkeypatch,
                       lambda url, **kw: _Resp(text="ref: refs/heads/main", status=200,
                                               headers={"content-type": "text/plain"}))
    out = git_check.check(["https://x.example.com"])
    assert len(out) == 1
    assert out[0]["class"] == "git_exposure"


def test_git_check_no_fp_on_html(monkeypatch):
    # SPA'lar her yola 200 + html döner → gerçek .git/HEAD değil, elenmeli
    _patch_session_get(monkeypatch,
                       lambda url, **kw: _Resp(text="<html>app</html>", status=200,
                                               headers={"content-type": "text/html"}))
    assert git_check.check(["https://x.example.com"]) == []


def test_git_check_head_matcher():
    assert git_check._looks_like_git_head("ref: refs/heads/main")
    assert git_check._looks_like_git_head("a" * 40)          # detached HEAD SHA
    assert not git_check._looks_like_git_head("<!DOCTYPE html>")


# ── cors_check ───────────────────────────────────────────────────────────────
def test_cors_reflection_with_credentials(monkeypatch):
    def handler(url, **kw):
        origin = kw.get("headers", {}).get("Origin", "")
        return _Resp(headers={"Access-Control-Allow-Origin": origin,
                              "Access-Control-Allow-Credentials": "true"})
    _patch_session_get(monkeypatch, handler)
    out = cors_check.check(["https://api.example.com"])
    assert out
    assert any(f["severity"] == "high" and f["class"] == "cors_misconfig" for f in out)


def test_cors_no_fp_when_not_reflected(monkeypatch):
    # Sabit/whitelist origin döner (yansıtmıyor) → bulgu YOK
    _patch_session_get(monkeypatch,
                       lambda url, **kw: _Resp(headers={"Access-Control-Allow-Origin":
                                                        "https://trusted.example.com"}))
    assert cors_check.check(["https://api.example.com"]) == []


def test_cors_no_fp_when_reflected_without_credentials(monkeypatch):
    # Regresyon (trip.com false-positive): origin/null YANSIYOR ama
    # Access-Control-Allow-Credentials YOK → saldırgan yalnızca public cevabı okur,
    # gerçek etki yok → bulgu ÜRETİLMEMELİ. (Akamai CDN edge'inin jenerik davranışı.)
    def handler(url, **kw):
        origin = kw.get("headers", {}).get("Origin", "")
        return _Resp(headers={"Access-Control-Allow-Origin": origin})  # ACAC yok
    _patch_session_get(monkeypatch, handler)
    assert cors_check.check(["https://pages.example.com"]) == []


def test_cors_no_fp_when_null_reflected_credentials_false(monkeypatch):
    # ACAC AÇIKÇA "false" olsa da bulgu üretilmemeli (yalnızca "true" sayılır).
    def handler(url, **kw):
        origin = kw.get("headers", {}).get("Origin", "")
        return _Resp(headers={"Access-Control-Allow-Origin": origin,
                              "Access-Control-Allow-Credentials": "false"})
    _patch_session_get(monkeypatch, handler)
    assert cors_check.check(["https://pages.example.com"]) == []


def test_cors_check_urls_tests_each_endpoint_not_host(monkeypatch):
    # check_urls host değil, TAM URL bazında test eder: aynı host'un 2 endpoint'i de sınanır.
    def handler(url, **kw):
        origin = kw.get("headers", {}).get("Origin", "")
        return _Resp(headers={"Access-Control-Allow-Origin": origin,
                              "Access-Control-Allow-Credentials": "true"})
    _patch_session_get(monkeypatch, handler)
    out = cors_check.check_urls(["https://api.example.com/v1/me",
                                 "https://api.example.com/v1/orders"])
    # aynı host ama iki farklı endpoint → host-dedup DEĞİL, ikisi de bulgu üretir
    urls = {f["reproduction"] for f in out}
    assert any("/v1/me" in u for u in urls)
    assert any("/v1/orders" in u for u in urls)


def test_cors_check_urls_scope_gated(monkeypatch):
    def handler(url, **kw):
        origin = kw.get("headers", {}).get("Origin", "")
        return _Resp(headers={"Access-Control-Allow-Origin": origin,
                              "Access-Control-Allow-Credentials": "true"})
    _patch_session_get(monkeypatch, handler)
    out = cors_check.check_urls(["https://out.example/v1/me"],
                                scope_checker=lambda h: h.endswith("in.example"))
    assert out == []
