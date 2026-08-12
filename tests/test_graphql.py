"""graphql_check — introspection tespiti testleri (requests.post mock'lu)."""

import requests

from bugtool import graphql_check


class _Resp:
    def __init__(self, text="", status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}


def _patch_post(monkeypatch, handler):
    def fake_post(self, url, **kw):
        return handler(url, **kw)
    monkeypatch.setattr(requests.sessions.Session, "post", fake_post)


def test_detects_open_introspection(monkeypatch):
    def handler(url, **kw):
        if url.endswith("/graphql"):
            return _Resp(text='{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
        return _Resp(text="not found", status=404)
    _patch_post(monkeypatch, handler)
    out = graphql_check.check(["https://api.example.com"], concurrency=1)
    assert any(f["class"] == "graphql_introspection" for f in out)


def test_no_fp_when_introspection_disabled(monkeypatch):
    def handler(url, **kw):
        return _Resp(text='{"errors":[{"message":"introspection is disabled"}]}', status=200)
    _patch_post(monkeypatch, handler)
    assert graphql_check.check(["https://api.example.com"], concurrency=1) == []


def test_no_fp_on_string_without_valid_json(monkeypatch):
    # Gövde "__schema"/"queryType" kelimelerini içeriyor ama geçerli JSON değil → elenmeli.
    def handler(url, **kw):
        return _Resp(text='<html>__schema queryType nonsense</html>', status=200)
    _patch_post(monkeypatch, handler)
    assert graphql_check.check(["https://api.example.com"], concurrency=1) == []


def test_uses_discovered_graphql_urls(monkeypatch):
    seen = []

    def handler(url, **kw):
        seen.append(url)
        if url.endswith("/gql"):
            return _Resp(text='{"data":{"__schema":{"queryType":{"name":"Q"}}}}')
        return _Resp(text="{}", status=404)
    _patch_post(monkeypatch, handler)
    out = graphql_check.check([], urls=["https://api.example.com/gql?x=1"], concurrency=1)
    assert any(f["class"] == "graphql_introspection" for f in out)
    assert any(u.endswith("/gql") for u in seen)


def test_looks_introspectable_helper():
    assert graphql_check._looks_introspectable(
        200, '{"data":{"__schema":{"queryType":{"name":"Q"}}}}')
    assert not graphql_check._looks_introspectable(200, '{"data":null}')
    assert not graphql_check._looks_introspectable(404, '{"data":{"__schema":{}}}')
