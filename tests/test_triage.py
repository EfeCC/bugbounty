"""Pasif triyaj testleri — param çıkarımı, ifşa dosya, tech (ağ yok)."""

from bugtool.triage import Triage


def test_param_targets_dedup():
    t = Triage()
    r = t.analyze([
        "http://a.example.com/s?q=1",
        "http://a.example.com/s?q=2",          # aynı şablon → deduplike
        "http://a.example.com/p?id=1",
        "http://a.example.com/static/app.js",  # parametresiz → atlanır
    ])
    assert r["stats"]["param_endpoints"] == 2
    params_seen = set()
    for pt in r["param_targets"]:
        params_seen |= set(pt["params"].keys())
    assert params_seen == {"q", "id"}


def test_param_classes_hinted():
    t = Triage()
    r = t.analyze(["http://a.example.com/x?redirect=/home&file=a&id=1"])
    pmap = r["param_targets"][0]["params"]
    assert "open_redirect" in pmap["redirect"]
    assert "lfi" in pmap["file"]
    assert "sqli" in pmap["id"]


def test_interesting_urls():
    t = Triage()
    r = t.analyze([
        "http://a.example.com/.git/config",
        "http://a.example.com/backup.sql",
        "http://a.example.com/admin/",
        "http://a.example.com/api/v1/users",
        "http://a.example.com/index.html",     # sıradan → işaretlenmez
    ])
    urls = [x["url"] for x in r["interesting_urls"]]
    assert any(".git" in u for u in urls)
    assert any("backup.sql" in u for u in urls)
    assert any("/admin" in u for u in urls)
    assert not any(u.endswith("index.html") for u in urls)


def test_tech_flags():
    t = Triage()
    r = t.analyze([], [
        {"url": "http://a.example.com", "tech": ["WordPress", "PHP"], "webserver": "Apache"},
        {"url": "http://b.example.com", "tech": [], "webserver": "nginx"},
    ])
    assert len(r["tech"]) == 1
    assert "WordPress" in r["tech"][0]["tech"]


def test_analyze_dir(tmp_path):
    (tmp_path / "urls.txt").write_text(
        "http://a.example.com/s?q=1\nhttp://a.example.com/.git/config\n", encoding="utf-8")
    (tmp_path / "httpx.jsonl").write_text(
        '{"url":"http://a.example.com","tech":["Jenkins"]}\n', encoding="utf-8")
    r = Triage().analyze_dir(str(tmp_path))
    assert r["stats"]["param_endpoints"] == 1
    assert r["interesting_urls"]
    assert r["tech"]


def test_analyze_dir_missing_files(tmp_path):
    # Boş dizin → çökmeden boş sonuç
    r = Triage().analyze_dir(str(tmp_path))
    assert r["stats"]["urls"] == 0
    assert r["param_targets"] == []


def test_analyze_dir_reads_api_schema_targets(tmp_path):
    import json
    targets = [{"url": "https://a.example.com/api/orders", "method": "POST",
               "params": {}, "body_params": {"amount": []}}]
    (tmp_path / "api_schema_targets.json").write_text(json.dumps(targets), encoding="utf-8")
    r = Triage().analyze_dir(str(tmp_path))
    assert r["stats"]["api_schema_endpoints"] == 1
    assert r["api_schema_targets"][0]["url"] == "https://a.example.com/api/orders"


def test_analyze_dir_api_schema_missing_is_graceful(tmp_path):
    r = Triage().analyze_dir(str(tmp_path))
    assert r["stats"]["api_schema_endpoints"] == 0
    assert r["api_schema_targets"] == []
