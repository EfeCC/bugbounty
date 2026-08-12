"""hostrank — canlı host önceliklendirme testleri (saf/deterministik, ağ YOK)."""

from bugtool import hostrank


def _h(url, status=200, title="", tech=None, webserver=""):
    return {"url": url, "status": status, "title": title,
            "tech": tech or [], "webserver": webserver}


def test_interesting_subdomain_beats_boring():
    api = _h("https://api.example.com", status=200)
    cdn = _h("https://cdn.example.com", status=200)
    assert hostrank.score_host(api) > hostrank.score_host(cdn)


def test_200_beats_redirect():
    ok = _h("https://a.example.com", status=200)
    red = _h("https://a.example.com", status=301)
    assert hostrank.score_host(ok) > hostrank.score_host(red)


def test_401_403_is_interesting():
    # Korumalı endpoint (401/403) 3xx yönlendirmesinden değerlidir.
    protected = _h("https://a.example.com", status=403)
    redirect = _h("https://a.example.com", status=302)
    assert hostrank.score_host(protected) > hostrank.score_host(redirect)


def test_interesting_tech_boosts():
    plain = _h("https://a.example.com", status=200, tech=["nginx"])
    jira = _h("https://a.example.com", status=200, tech=["Atlassian Jira"])
    assert hostrank.score_host(jira) > hostrank.score_host(plain)


def test_parked_title_penalized():
    normal = _h("https://a.example.com", status=200, title="Home")
    parked = _h("https://a.example.com", status=200, title="This domain is for sale")
    assert hostrank.score_host(normal) > hostrank.score_host(parked)


def test_rank_orders_and_dedups():
    hosts = [
        _h("https://cdn.example.com", status=200),
        _h("https://admin.example.com", status=200),
        _h("https://api.example.com", status=200),
        _h("https://cdn.example.com", status=200),   # duplicate url
    ]
    ranked = hostrank.rank(hosts, domain="example.com")
    # admin + api (ilginç) cdn'den (boring) önce; duplicate tekilleşti
    assert ranked.index("https://admin.example.com") < ranked.index("https://cdn.example.com")
    assert ranked.index("https://api.example.com") < ranked.index("https://cdn.example.com")
    assert ranked.count("https://cdn.example.com") == 1


def test_rank_stable_on_ties():
    # Aynı skorlu iki host httpx (orijinal) sırasını korumalı.
    hosts = [_h("https://b.example.com", status=200, title="x"),
             _h("https://c.example.com", status=200, title="x")]
    ranked = hostrank.rank(hosts, domain="example.com")
    assert ranked == ["https://b.example.com", "https://c.example.com"]


def test_rank_urls_fallback_prioritizes_interesting():
    urls = ["https://static.example.com/", "https://api.example.com/", "https://www.example.com/"]
    ranked = hostrank.rank_urls(urls, domain="example.com")
    assert ranked[0] == "https://api.example.com/"
    assert ranked[-1] == "https://static.example.com/"


def test_apex_gets_small_boost_over_equal_generic_sub():
    apex = _h("https://example.com", status=200)
    sub = _h("https://blog.example.com", status=200)   # 'blog' nötr label
    assert hostrank.score_host(apex, domain="example.com") > hostrank.score_host(sub, domain="example.com")


# ── host dedup (aynı app'in N kopyası) ───────────────────────────────────────
def _hf(url, favicon="", title="app", status=200, cl=100):
    return {"url": url, "status": status, "title": title, "tech": [], "webserver": "",
            "favicon": favicon, "content_length": cl}


def test_dedup_pushes_same_favicon_to_end():
    # 3 host aynı favicon (aynı app) + 1 farklı → aynı olanların kopyaları sona itilir.
    hosts = [
        _hf("https://a.example.com", favicon="111"),
        _hf("https://b.example.com", favicon="111"),
        _hf("https://c.example.com", favicon="111"),
        _hf("https://uniq.example.com", favicon="999"),
    ]
    ranked = hostrank.rank(hosts, domain="example.com")
    assert len(ranked) == 4                       # hiçbir host ATILMADI
    # ilk 2 farklı imza (a + uniq), b/c sona itildi
    assert set(ranked[:2]) == {"https://a.example.com", "https://uniq.example.com"}
    assert set(ranked[2:]) == {"https://b.example.com", "https://c.example.com"}


def test_dedup_off_keeps_score_order():
    hosts = [_hf("https://a.example.com", favicon="111"),
             _hf("https://b.example.com", favicon="111")]
    ranked = hostrank.rank(hosts, domain="example.com", dedup=False)
    assert ranked == ["https://a.example.com", "https://b.example.com"]


def test_dedup_none_signature_never_collapses():
    # favicon yok + title boş → imza None → HER host tekil (yanlış birleştirme yok).
    hosts = [_hf("https://a.example.com", favicon="", title=""),
             _hf("https://b.example.com", favicon="", title="")]
    ranked = hostrank.rank(hosts, domain="example.com")
    assert len(ranked) == 2
    assert set(ranked) == {"https://a.example.com", "https://b.example.com"}


def test_dedup_signature_prefers_favicon():
    assert hostrank.dedup_signature(_hf("x", favicon="42"))[0] == "fav"
    # favicon 0 = "yok" sayılır → title+len imzasına düşer
    sig = hostrank.dedup_signature(_hf("x", favicon="0", title="T", cl=50))
    assert sig[0] == "tsl"
