"""webrecon pipeline parse + orkestrasyon testleri (mock shell.run — binary/ağ GEREKTİRMEZ)."""

import bugtool.webrecon as webrecon_mod
from bugtool.webrecon import WebRecon

SUBS = "example.com\napi.example.com\nout.example.com\n"
HTTPX = ('{"url":"https://api.example.com","status_code":200,"title":"API","tech":["nginx"]}\n'
         '{"url":"https://example.com","status_code":301,"title":""}\n')
KATANA = "https://api.example.com/v1/users\nhttps://api.example.com/v1/login\n"
GAU = "https://example.com/robots.txt\nhttps://api.example.com/v1/users\n"
NUCLEI = ("[tech-detect] [http] [info] https://example.com\n"
          "[exposed-git] [http] [medium] https://api.example.com/.git/\n")


def _patch(monkeypatch, have=True):
    def fake_have(binary):
        return have

    def fake_run(cmd, timeout=300, **kw):
        c = cmd.lower()
        out = ""
        if "subfinder" in c:
            out = SUBS
        elif "dnsx" in c:
            out = SUBS
        elif "httpx" in c:
            out = HTTPX
        elif "katana" in c:
            out = KATANA
        elif "gau" in c:
            out = GAU
        elif "nuclei" in c:
            out = NUCLEI
        return {"success": True, "stdout": out, "stderr": "", "command": cmd}

    monkeypatch.setattr(webrecon_mod, "have", fake_have)
    monkeypatch.setattr(webrecon_mod, "run", fake_run)


def test_pipeline_full(monkeypatch, tmp_path):
    _patch(monkeypatch)
    wr = WebRecon()
    p = wr.run_pipeline("https://example.com/", output_dir=str(tmp_path))

    assert p["domain"] == "example.com"
    assert "api.example.com" in p["subdomains"]
    assert any(h["url"] == "https://api.example.com" and h["status"] == 200 for h in p["live_hosts"])
    assert "https://api.example.com/v1/users" in p["urls"]
    assert "/v1/users" in p["discovered_endpoints"]

    titles = [f["title"] for f in p["findings"]]
    assert "Nuclei: exposed-git" in titles
    assert all("tech-detect" not in t for t in titles)


def test_scope_filter_drops_out_of_scope(monkeypatch, tmp_path):
    _patch(monkeypatch)
    wr = WebRecon()
    p = wr.run_pipeline("example.com", output_dir=str(tmp_path),
                        scope_checker=lambda h: not h.startswith("out."))
    assert "out.example.com" not in p["subdomains"]
    assert "api.example.com" in p["subdomains"]


def test_passive_only_skips_katana(monkeypatch, tmp_path):
    _patch(monkeypatch)
    wr = WebRecon(passive_only=True)
    p = wr.run_pipeline("example.com", output_dir=str(tmp_path))
    assert "katana" in p["stages_skipped"]
    assert "gau" in p["stages_run"]


def test_graceful_degrade_no_binaries(monkeypatch, tmp_path):
    _patch(monkeypatch, have=False)
    wr = WebRecon()
    p = wr.run_pipeline("example.com", output_dir=str(tmp_path))
    assert "example.com" in p["subdomains"]
    assert "subfinder" in p["stages_skipped"]
    assert "httpx" in p["stages_skipped"]
    assert "nuclei" in p["stages_skipped"]
    assert p["findings"] == []


def test_parse_httpx():
    wr = WebRecon()
    hosts = wr._parse_httpx(HTTPX)
    assert len(hosts) == 2
    assert hosts[0]["url"] == "https://api.example.com"
    assert hosts[0]["tech"] == ["nginx"]


def test_parse_nuclei_filters_info():
    wr = WebRecon()
    findings = wr._parse_nuclei(NUCLEI)
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["title"] == "Nuclei: exposed-git"


def test_bare_domain_and_endpoints():
    wr = WebRecon()
    assert wr._bare_domain("https://api.example.com/x") == "api.example.com"
    assert wr._bare_domain("example.com") == "example.com"
    eps = wr._extract_endpoints(["https://x/a/b", "https://x/", "https://x/a/b?q=1", "https://x"])
    assert "/a/b" in eps
    assert "/" not in eps


def test_dedup_scope_urls():
    wr = WebRecon()
    urls = ["https://a.example.com/1", "https://a.example.com/1", "https://out.com/2"]
    out = wr._dedup_scope_urls(urls, lambda h: h.endswith("example.com"))
    assert out == ["https://a.example.com/1"]
