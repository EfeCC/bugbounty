"""API-probe testleri — requests.Session.request mock'lanır (GERÇEK ağ YOK).

Doğrulananlar:
  - triage.api_endpoints: path-tabanlı endpoint çıkarımı (statik varlık eleme + dedup).
  - metot/yetki haritası: OPTIONS Allow + GET status; hassas-isimli kimliksiz 2xx → bulgu.
  - OOB/SSRF ekimi: url-çeken endpoint'e GET-query probu; POST-JSON YALNIZCA bağlantı-test
    edici + yıkıcı-OLMAYAN endpoint'e (yan-etkili isimlere asla POST atılmaz).
  - GÜVENLİK korkulukları: scope-gating + max_requests cap.
"""

import pytest

from bugtool.triage import Triage
from bugtool.api_probe import ApiProbe
from bugtool.oob import OobManager


# ── Sahte requests.Session.request ───────────────────────────────────────────
class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


def _fake_request(record):
    """Kaydedici sahte request: her çağrıyı record'a yazar, endpoint'e göre cevap üretir."""
    def _req(method, url, headers=None, params=None, json=None, timeout=None,
             allow_redirects=False, verify=False):
        record.append({"method": method, "url": url, "params": params, "json": json})
        if method == "OPTIONS":
            return FakeResp(status_code=204, headers={"Allow": "GET, POST, OPTIONS"})
        if "/api/storage-providers" in url and method == "GET":
            return FakeResp(text='{"providers":[]}', status_code=200)   # hassas + kimliksiz 200
        if "/api/otp/verify" in url and method == "GET":
            return FakeResp(status_code=401)                            # yetki gerekli
        if "/api/boom" in url and method == "GET":
            return FakeResp(status_code=500)                            # sunucu hatası
        return FakeResp(text="ok", status_code=200)
    return _req


def _probe(scope=lambda h: True, **kw):
    api = ApiProbe(scope_checker=scope, **kw)
    if not api.available:
        pytest.skip("requests kurulu değil")
    return api


# ── triage.api_endpoints ─────────────────────────────────────────────────────
def test_api_endpoints_extraction_and_dedup():
    urls = [
        "https://t.example.com/api/storage-providers",
        "https://t.example.com/api/storage-providers?x=1",   # aynı path → dedup
        "https://t.example.com/api/static/chunks/abc.js",    # statik → elenmeli
        "https://t.example.com/recaptcha/api.js?onload=",    # statik .js → elenmeli
        "https://t.example.com/",                            # API değil
        "https://t.example.com/admin/users",                 # /admin → dahil
        "https://t.example.com/blog/post",                   # API değil
    ]
    eps = Triage().analyze(urls)["api_endpoints"]
    paths = {e["path"] for e in eps}
    assert "/api/storage-providers" in paths
    assert "/admin/users" in paths
    assert "/blog/post" not in paths
    assert not any(e["url"].endswith(".js") for e in eps)
    # dedup: storage-providers tek kez, ve url query'siz
    sp = [e for e in eps if e["path"] == "/api/storage-providers"]
    assert len(sp) == 1
    assert "?" not in sp[0]["url"]


# ── metot/yetki haritası ─────────────────────────────────────────────────────
def test_method_map_flags_sensitive_unauth_2xx():
    api = _probe()
    rec = []
    api._session.request = _fake_request(rec)
    res = api.probe([{"url": "https://t.example.com/api/storage-providers",
                      "path": "/api/storage-providers"}])
    row = res["method_map"][0]
    assert row["get_status"] == 200
    assert "GET" in row["allow"]                       # OPTIONS Allow başlığı okundu
    assert any(f["class"] == "broken_access_control" for f in res["findings"])
    # hepsi "lead" — otomatik doğrulanmış değil
    assert all(f["verdict"] == "lead" for f in res["findings"])


def test_method_map_auth_required_no_finding():
    api = _probe()
    rec = []
    api._session.request = _fake_request(rec)
    res = api.probe([{"url": "https://t.example.com/api/otp/verify",
                      "path": "/api/otp/verify"}])
    assert res["method_map"][0]["get_status"] == 401
    assert not any(f["class"] == "broken_access_control" for f in res["findings"])


def test_server_error_becomes_lead():
    api = _probe()
    rec = []
    api._session.request = _fake_request(rec)
    res = api.probe([{"url": "https://t.example.com/api/boom", "path": "/api/boom"}])
    assert any(f["class"] == "server_error" for f in res["findings"])


# ── OOB / SSRF ekimi ─────────────────────────────────────────────────────────
def test_oob_conn_tester_gets_get_and_post():
    api = _probe()
    rec = []
    api._session.request = _fake_request(rec)
    oob = OobManager("oob.example")
    api.probe([{"url": "https://t.example.com/api/x/oauth/callback",
                "path": "/api/x/oauth/callback"}], oob=oob)
    methods = [r["method"] for r in rec]
    assert "POST" in methods                          # bağlantı-test edici → POST-JSON probu var
    assert any(r["method"] == "GET" and r["params"] for r in rec)   # GET-query probu
    assert len(oob.probes) > 0                         # token'lar depoya kaydedildi


def test_oob_destructive_endpoint_never_posts():
    api = _probe()
    rec = []
    api._session.request = _fake_request(rec)
    oob = OobManager("oob.example")
    # /import url-çeken AMA yıkıcı isim → GET-query OK, POST YASAK
    api.probe([{"url": "https://t.example.com/api/backup/import",
                "path": "/api/backup/import"}], oob=oob)
    methods = [r["method"] for r in rec]
    assert "POST" not in methods                       # yan-etkili isme asla otomatik POST
    assert any(r["method"] == "GET" and r["params"] for r in rec)   # ama GET-query probu var


def test_oob_non_fetch_endpoint_no_probe():
    api = _probe()
    rec = []
    api._session.request = _fake_request(rec)
    oob = OobManager("oob.example")
    # storage-providers url-çeken değil → SSRF probu YOK (sadece OPTIONS+GET haritalama)
    api.probe([{"url": "https://t.example.com/api/storage-providers",
                "path": "/api/storage-providers"}], oob=oob)
    assert len(oob.probes) == 0
    assert [r["method"] for r in rec] == ["OPTIONS", "GET"]


def test_oob_post_disabled_by_flag():
    api = _probe(oob_post=False)
    rec = []
    api._session.request = _fake_request(rec)
    oob = OobManager("oob.example")
    api.probe([{"url": "https://t.example.com/api/x/oauth/callback",
                "path": "/api/x/oauth/callback"}], oob=oob)
    assert "POST" not in [r["method"] for r in rec]    # api_oob_post=False → POST yok


# ── güvenlik korkulukları ────────────────────────────────────────────────────
def test_scope_gating_blocks_out_of_scope():
    api = _probe(scope=lambda h: h == "in.example")
    rec = []
    api._session.request = _fake_request(rec)
    res = api.probe([{"url": "https://out.example/api/x", "path": "/api/x"}])
    assert rec == []                                   # kapsam-dışı → HİÇ istek yok
    assert res["method_map"] == []


def test_max_requests_cap():
    api = _probe(max_requests=1)
    rec = []
    api._session.request = _fake_request(rec)
    res = api.probe([{"url": "https://t.example.com/api/a", "path": "/api/a"},
                     {"url": "https://t.example.com/api/b", "path": "/api/b"}])
    # cap endpoint sınırında kontrol edilir → sadece ilk endpoint işlenir
    assert all("/api/a" in r["url"] for r in rec)
    assert len(res["method_map"]) == 1
