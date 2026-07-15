"""probe.parallel_collect + per-host modüllerin paralelliği/scope-gating (ağsız, mock)."""

import time

import requests

import bugtool.probe as probe
import bugtool.git_check as git_check
import bugtool.cors_check as cors_check


def test_parallel_collect_flattens_and_filters_empty():
    out = probe.parallel_collect(lambda x: [x, x * 10] if x else [], [1, 0, 2], concurrency=4)
    assert sorted(out) == [1, 2, 10, 20]


def test_parallel_collect_empty_input():
    assert probe.parallel_collect(lambda x: [x], [], concurrency=4) == []


def test_parallel_collect_serial_when_concurrency_1():
    # concurrency<=1 → sıralı (deterministik)
    order = []
    probe.parallel_collect(lambda x: (order.append(x), [x])[1], [3, 1, 2], concurrency=1)
    assert order == [3, 1, 2]


def test_parallel_collect_actually_concurrent():
    # Her iş 0.1sn "uyursa", 10 iş sıralı 1sn sürer; paralel (10 worker) ~0.1sn.
    def slow(x):
        time.sleep(0.1)
        return [x]
    t0 = time.time()
    out = probe.parallel_collect(slow, list(range(10)), concurrency=10)
    elapsed = time.time() - t0
    assert len(out) == 10
    assert elapsed < 0.5          # sıralı olsaydı ~1sn olurdu → gerçekten paralel


def _patch_session_get(monkeypatch, handler):
    monkeypatch.setattr(requests.sessions.Session, "get", lambda self, url, **kw: handler(url, **kw))


class _Resp:
    def __init__(self, text="", status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}


def test_git_check_parallel_scope_gated(monkeypatch):
    # Kapsam-dışı host'a HİÇ istek gitmemeli (paralel katmandan önce filtrelenir)
    called = []

    def handler(url, **kw):
        called.append(url)
        return _Resp(text="ref: refs/heads/main", headers={"content-type": "text/plain"})
    _patch_session_get(monkeypatch, handler)
    out = git_check.check(["https://in.example.com", "https://evil.com"],
                          scope_checker=lambda h: h.endswith("example.com"))
    assert len(out) == 1                                   # sadece in-scope host bulundu
    assert all("evil.com" not in u for u in called)        # evil.com'a hiç istek yok


def test_git_check_parallel_many_hosts(monkeypatch):
    # Çok host → hepsi kontrol edilir (paralel), git ifşası olanlar bulunur
    def handler(url, **kw):
        # host adında "vuln" geçen host'lar .git ifşa ediyor
        if "vuln" in url:
            return _Resp(text="ref: refs/heads/main", headers={"content-type": "text/plain"})
        return _Resp(text="<html>ok</html>", headers={"content-type": "text/html"})
    _patch_session_get(monkeypatch, handler)
    hosts = [f"https://h{i}.example.com" for i in range(20)] + \
            ["https://vuln1.example.com", "https://vuln2.example.com"]
    out = git_check.check(hosts, concurrency=10)
    assert len(out) == 2                                   # iki vuln host bulundu


def test_cors_check_parallel_multiple_findings_per_host(monkeypatch):
    # Bir host hem rastgele hem null origin yansıtırsa 2 bulgu → düzleştirilmeli
    def handler(url, **kw):
        origin = kw.get("headers", {}).get("Origin", "")
        return _Resp(headers={"Access-Control-Allow-Origin": origin,
                              "Access-Control-Allow-Credentials": "true"})
    _patch_session_get(monkeypatch, handler)
    out = cors_check.check(["https://a.example.com"], concurrency=4)
    # rastgele origin yansıması + null origin yansıması = 2 bulgu
    assert len(out) == 2
