"""api_probe IDOR/BOLA sezgisi testleri — requests.Session.request mock'lanır (ağ YOK)."""

import re

import pytest

from bugtool.api_probe import ApiProbe


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


def _probe(**kw):
    api = ApiProbe(scope_checker=lambda h: True, **kw)
    if not api.available:
        pytest.skip("requests kurulu değil")
    return api


def _req_per_id(record=None):
    """/users/<id> için ID'ye göre FARKLI gövde döndürür (gerçek IDOR gibi)."""
    def _req(method, url, headers=None, params=None, json=None, timeout=None,
             allow_redirects=False, verify=False):
        if record is not None:
            record.append({"method": method, "url": url})
        m = re.search(r"/(\d+)(?:/|$)", url)
        if m:
            uid = m.group(1)
            return FakeResp(text='{"id":%s,"email":"u%s@corp.com","ssn":"x"}' % (uid, uid))
        return FakeResp(text="ok")
    return _req


def test_idor_detected_on_sensitive_numeric(monkeypatch):
    api = _probe()
    api._session.request = _req_per_id()
    finds = api._probe_idor("https://t.example.com/api/users/42")
    assert any(f["class"] == "idor_bola" and f["severity"] == "high" for f in finds)


def test_no_idor_when_same_body(monkeypatch):
    api = _probe()

    def _same(method, url, **kw):
        return FakeResp(text='{"static":"identical for all ids"}')
    api._session.request = _same
    # Aynı gövde her ID'de → farklı nesne yok → IDOR sayılmaz.
    assert api._probe_idor("https://t.example.com/api/users/42") == []


def test_no_idor_on_non_sensitive_path(monkeypatch):
    api = _probe()
    rec = []
    api._session.request = _req_per_id(rec)
    # /catalog/items/5 hassas isim değil → hiç istek atmadan atlanır (public katalog FP'si).
    assert api._probe_idor("https://t.example.com/catalog/items/5") == []
    assert rec == []


def test_no_idor_when_base_forbidden(monkeypatch):
    api = _probe()

    def _forbidden(method, url, **kw):
        return FakeResp(text="denied", status_code=403)
    api._session.request = _forbidden
    # Kimliksiz zaten erişilemiyorsa (403) IDOR yok.
    assert api._probe_idor("https://t.example.com/api/account/42") == []


def test_idor_disabled_by_flag(monkeypatch):
    api = _probe(idor=False)
    rec = []
    api._session.request = _req_per_id(rec)
    res = api.probe([{"url": "https://t.example.com/api/users/42",
                      "path": "/api/users/42"}])
    assert not any(f["class"] == "idor_bola" for f in res["findings"])
