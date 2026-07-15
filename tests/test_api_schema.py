"""api_schema.py — Swagger/OpenAPI şema keşfi ve ayrıştırma (mock requests, ağ yok)."""

import json

import requests

import bugtool.api_schema as api_schema


class _Resp:
    def __init__(self, text="", status=200):
        self.text = text
        self.status_code = status


SWAGGER_2 = {
    "swagger": "2.0",
    "basePath": "/api",
    "paths": {
        "/users/{id}": {
            "get": {"parameters": [{"name": "id", "in": "path"},
                                   {"name": "verbose", "in": "query"}]},
            "post": {"parameters": [{"name": "body", "in": "body",
                                     "schema": {"$ref": "#/definitions/User"}}]},
        }
    },
    "definitions": {
        "User": {"properties": {"email": {"type": "string"}, "role": {"type": "string"}}}
    },
}

OPENAPI_3 = {
    "openapi": "3.0.0",
    "paths": {
        "/orders": {
            "post": {
                "requestBody": {"content": {"application/json": {
                    "schema": {"properties": {"amount": {"type": "number"},
                                              "currency": {"type": "string"}}}}}}
            }
        }
    },
}


def _patch_session_get(monkeypatch, handler):
    monkeypatch.setattr(requests.sessions.Session, "get", lambda self, url, **kw: handler(url, **kw))


def test_discover_swagger2_extracts_query_and_body_params(monkeypatch):
    _patch_session_get(monkeypatch, lambda url, **kw: _Resp(text=json.dumps(SWAGGER_2)))
    targets = api_schema.discover(["https://api.example.com"], [])
    assert targets
    get_t = next(t for t in targets if t["method"] == "GET")
    assert "verbose" in get_t["params"]
    assert "/api/users/1" in get_t["url"]           # basePath + path-param doldurma
    post_t = next(t for t in targets if t["method"] == "POST")
    assert "email" in post_t["body_params"] and "role" in post_t["body_params"]  # $ref çözüldü


def test_discover_openapi3_request_body(monkeypatch):
    _patch_session_get(monkeypatch, lambda url, **kw: _Resp(text=json.dumps(OPENAPI_3)))
    targets = api_schema.discover(["https://api.example.com"], [])
    assert targets
    t = targets[0]
    assert t["method"] == "POST"
    assert "amount" in t["body_params"] and "currency" in t["body_params"]


def test_discover_no_schema_found(monkeypatch):
    _patch_session_get(monkeypatch, lambda url, **kw: _Resp(status=404))
    assert api_schema.discover(["https://api.example.com"], []) == []


def test_discover_scope_gated(monkeypatch):
    _patch_session_get(monkeypatch, lambda url, **kw: _Resp(text=json.dumps(SWAGGER_2)))
    targets = api_schema.discover(["https://evil.com"], [],
                                  scope_checker=lambda host: host.endswith("example.com"))
    assert targets == []


def test_discover_graceful_without_requests(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def blocked(name, *a, **kw):
        if name == "requests":
            raise ImportError("yok")
        return real_import(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", blocked)
    assert api_schema.discover(["https://api.example.com"], []) == []


def test_resolve_ref_and_schema_props():
    root = {"definitions": {"X": {"properties": {"a": {}, "b": {}}}}}
    node = {"$ref": "#/definitions/X"}
    props = api_schema._schema_props(root, node)
    assert set(props) == {"a", "b"}


def test_looks_like_schema():
    assert api_schema._looks_like_schema({"swagger": "2.0", "paths": {}})
    assert api_schema._looks_like_schema({"openapi": "3.0.0", "paths": {}})
    assert not api_schema._looks_like_schema({"paths": {}})     # ne swagger ne openapi
    assert not api_schema._looks_like_schema("not a dict")


def test_discover_dedups_identical_schema_at_multiple_urls(monkeypatch):
    # Aynı şema (aynı title+path-sayısı) hem bilinen konumda hem keşfedilen URL'de
    # bulunursa iki kez parse edilmemeli
    doc = dict(SWAGGER_2)
    calls = {"n": 0}

    def handler(url, **kw):
        calls["n"] += 1
        return _Resp(text=json.dumps(doc))
    _patch_session_get(monkeypatch, handler)
    targets = api_schema.discover(
        ["https://api.example.com"], ["https://api.example.com/swagger.json"])
    # Aynı doküman (fingerprint eşleşiyor) → targets sadece bir kez üretilmeli
    get_targets = [t for t in targets if t["method"] == "GET"]
    assert len(get_targets) == 1
