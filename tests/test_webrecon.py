"""webrecon pipeline parse + orkestrasyon testleri (mock shell.run — binary/ağ GEREKTİRMEZ).

NOT: Yeni ağ-modülleri (ct_logs/takeover/git_check/cors/secrets) `requests`'i DOĞRUDAN
çağırır (mock'lanan `run` üzerinden değil). Bu çekirdek testlerde onları no-op'a çevirip
gerçek ağ isteğini engelliyoruz; kendi ayrı testlerinde (test_newmodules.py) mock'lu."""

import re
import json as _json

import bugtool.webrecon as webrecon_mod
from bugtool.webrecon import WebRecon

SUBS = "example.com\napi.example.com\nout.example.com\n"
HTTPX = ('{"url":"https://api.example.com","status_code":200,"title":"API","tech":["nginx"]}\n'
         '{"url":"https://example.com","status_code":301,"title":""}\n')
KATANA = "https://api.example.com/v1/users\nhttps://api.example.com/v1/login\n"
GAU = "https://example.com/robots.txt\nhttps://api.example.com/v1/users\n"
# nuclei artık -jsonl (satır satır JSON) — info seviyesi filtrelenir, medium kalır
NUCLEI = ('{"template-id":"tech-detect","info":{"severity":"info","name":"Tech"},'
          '"matched-at":"https://example.com"}\n'
          '{"template-id":"exposed-git","info":{"severity":"medium","name":"Exposed .git"},'
          '"matched-at":"https://api.example.com/.git/",'
          '"curl-command":"curl https://api.example.com/.git/"}\n')


def _patch(monkeypatch, have=True):
    def fake_have(binary):
        return have

    def fake_run(cmd, timeout=300, **kw):
        c = cmd.lower()
        out = ""
        if "ffuf" in c:
            # ffuf artık -o <path> -of json ile JSON dosyaya yazıyor → dosyayı üret
            mo = re.search(r"-o (\S+)", cmd)
            mu = re.search(r"-u (\S+)/FUZZ", cmd)
            if mo:
                base = mu.group(1) if mu else "https://x"
                with open(mo.group(1), "w", encoding="utf-8") as fh:
                    _json.dump({"results": [{"url": f"{base}/admin"},
                                            {"url": f"{base}/backup.zip"}]}, fh)
        elif "subfinder" in c:
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
    # Ağ-modüllerini no-op'la (gerçek istek atmasınlar) — kendi testlerinde ayrıca test edilir
    monkeypatch.setattr(webrecon_mod.ct_logs, "fetch_subdomains", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.takeover, "check", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.git_check, "check", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.cors_check, "check", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.secrets_scan, "scan", lambda *a, **k: [])


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


def test_scope_checker_exception_fails_closed(monkeypatch, tmp_path):
    # Regresyon: scope kontrolü hata verirse fail-CLOSED olmalı (host'u kapsam-dışı say).
    _patch(monkeypatch)

    def boom(host):
        raise RuntimeError("scope patladı")

    wr = WebRecon()
    p = wr.run_pipeline("example.com", output_dir=str(tmp_path), scope_checker=boom)
    assert p["subdomains"] == []          # hepsi (apex dahil) güvenli tarafta düştü


def test_passive_only_skips_katana(monkeypatch, tmp_path):
    _patch(monkeypatch)
    wr = WebRecon(passive_only=True)
    p = wr.run_pipeline("example.com", output_dir=str(tmp_path))
    assert "katana" in p["stages_skipped"]
    assert "gau" in p["stages_run"]
    assert "ffuf" in p["stages_skipped"]       # passive_only → ffuf de kapalı


def test_ffuf_content_discovery(monkeypatch, tmp_path):
    _patch(monkeypatch)
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\nbackup.zip\n", encoding="utf-8")
    wr = WebRecon(ffuf_wordlist=str(wl))
    p = wr.run_pipeline("example.com", output_dir=str(tmp_path / "out"))
    assert "ffuf" in p["stages_run"]
    # ffuf ile bulunan linklenmemiş yollar urls'e girmeli
    assert any(u.endswith("/admin") for u in p["urls"])
    assert any(u.endswith("/backup.zip") for u in p["urls"])


def test_ffuf_skipped_without_wordlist(monkeypatch, tmp_path):
    _patch(monkeypatch)
    wr = WebRecon()                            # wordlist yok (test ortamında SecLists yok)
    p = wr.run_pipeline("example.com", output_dir=str(tmp_path))
    assert "ffuf" in p["stages_skipped"]


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
