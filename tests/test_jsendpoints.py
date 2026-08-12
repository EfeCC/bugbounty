"""jsendpoints — JS bundle'larından endpoint madenciliği testleri (requests mock'lu)."""

import requests

from bugtool import jsendpoints


class _Resp:
    def __init__(self, text="", status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}


def _patch_get(monkeypatch, handler):
    def fake_get(self, url, **kw):
        return handler(url, **kw)
    monkeypatch.setattr(requests.sessions.Session, "get", fake_get)


def test_extract_finds_paths():
    content = 'fetch("/api/internal/users");const u="/v2/orders?id=1";x.get(`/account/me`);'
    out = jsendpoints._extract(content, "https://app.example.com", per_file_cap=100)
    assert "https://app.example.com/api/internal/users" in out
    assert "https://app.example.com/v2/orders?id=1" in out
    assert "https://app.example.com/account/me" in out


def test_extract_skips_static_and_protocol_relative():
    content = 'src="/assets/app.css";img="/logo.png";cdn="//cdn.other.com/x.js";'
    out = jsendpoints._extract(content, "https://app.example.com", per_file_cap=100)
    assert out == []          # hepsi statik ya da protocol-relative → elenir


def test_extract_absolute_same_target_url():
    content = 'const api="https://api.example.com/v1/secret-data";'
    out = jsendpoints._extract(content, "https://app.example.com", per_file_cap=100)
    assert "https://api.example.com/v1/secret-data" in out


def test_mine_downloads_and_scopes(monkeypatch):
    # app.js iki endpoint içeriyor; biri kapsam-dışı host'a (elenmeli).
    def handler(url, **kw):
        if url.endswith("/app.js"):
            return _Resp(text='fetch("/api/orders");x="https://evil.com/api/z";')
        return _Resp(text="", status=404)
    _patch_get(monkeypatch, handler)
    out = jsendpoints.mine(["https://app.example.com/app.js"], concurrency=1,
                           scope_checker=lambda h: h.endswith("example.com"))
    assert "https://app.example.com/api/orders" in out
    assert all("evil.com" not in u for u in out)   # kapsam-dışı endpoint elendi


def test_mine_skips_cdn_js(monkeypatch):
    # 3.taraf/CDN JS hiç indirilmemeli → boş.
    called = {"n": 0}

    def handler(url, **kw):
        called["n"] += 1
        return _Resp(text='fetch("/api/x")')
    _patch_get(monkeypatch, handler)
    out = jsendpoints.mine(["https://code.jquery.com/jquery-3.6.0.min.js"], concurrency=1)
    assert out == []
    assert called["n"] == 0


def test_mine_empty_when_no_js():
    assert jsendpoints.mine(["https://x.example.com/index.html"], concurrency=1) == []
