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
    monkeypatch.setattr(webrecon_mod.api_schema, "discover", lambda *a, **k: [])
    # _probe_scheme (httpx boş sonuç yedek yöntemi) gerçek ağa çıkmasın — varsayılan
    # olarak "https" başarılı gibi davran (eski davranışla aynı sonuç, testler bozulmaz)
    import requests as _requests
    monkeypatch.setattr(_requests, "head", lambda url, **kw: None)


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


# ── _probe_scheme (httpx boş sonuç yedek yöntemi) ───────────────────────────
def test_probe_scheme_prefers_https_when_both_work(monkeypatch):
    import requests
    monkeypatch.setattr(requests, "head", lambda url, **kw: None)
    assert WebRecon._probe_scheme("example.com") == "https"


def test_probe_scheme_falls_back_to_http_only(monkeypatch):
    import requests

    def fake_head(url, **kw):
        if url.startswith("https://"):
            raise requests.exceptions.SSLError("no TLS")
        return None
    monkeypatch.setattr(requests, "head", fake_head)
    assert WebRecon._probe_scheme("http-only.example.com") == "http"


def test_probe_scheme_both_fail_defaults_https(monkeypatch):
    import requests

    def always_fail(url, **kw):
        raise requests.exceptions.ConnectionError("unreachable")
    monkeypatch.setattr(requests, "head", always_fail)
    # Regresyon-güvenli: ikisi de başarısızsa eski davranışla aynı sonuca (https) düş
    assert WebRecon._probe_scheme("dead.example.com") == "https"


def test_probe_scheme_no_requests_defaults_https(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def blocked_import(name, *a, **kw):
        if name == "requests":
            raise ImportError("no requests")
        return real_import(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", blocked_import)
    assert WebRecon._probe_scheme("example.com") == "https"


# ── ctlogs mesaj netliği (requests-yok vs sonuç-yok ayrımı) ─────────────────
def test_ctlogs_message_distinguishes_no_requests(monkeypatch, tmp_path):
    _patch(monkeypatch)
    monkeypatch.setattr(webrecon_mod.ct_logs, "fetch_subdomains", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.ct_logs, "requests_available", lambda: False)
    events = []

    class Rec:
        def stage(self, label):
            import contextlib
            return contextlib.nullcontext()

        def done(self, msg, path=None):
            events.append(("done", msg))

        def skip(self, msg):
            events.append(("skip", msg))

        def info(self, msg):
            pass

        def error(self, msg):
            pass

    wr = WebRecon()
    wr.run_pipeline("example.com", output_dir=str(tmp_path), reporter=Rec())
    assert any("requests" in m and "kurulu değil" in m for k, m in events if k == "skip")


def test_ctlogs_message_when_requests_available_but_empty(monkeypatch, tmp_path):
    _patch(monkeypatch)
    monkeypatch.setattr(webrecon_mod.ct_logs, "fetch_subdomains", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.ct_logs, "requests_available", lambda: True)
    events = []

    class Rec:
        def stage(self, label):
            import contextlib
            return contextlib.nullcontext()

        def done(self, msg, path=None):
            events.append(("done", msg))

        def skip(self, msg):
            events.append(("skip", msg))

        def info(self, msg):
            pass

        def error(self, msg):
            pass

    wr = WebRecon()
    wr.run_pipeline("example.com", output_dir=str(tmp_path), reporter=Rec())
    assert any("sertifika kaydı bulunamadı" in m for k, m in events if k == "skip")
    assert not any("kurulu değil" in m for k, m in events if k == "skip" and "crt.sh" in m)


# ── apischema aşaması (Swagger/OpenAPI keşfi) ────────────────────────────────
def test_apischema_stage_writes_targets_and_return_key(monkeypatch, tmp_path):
    _patch(monkeypatch)
    fake_targets = [{"url": "https://api.example.com/orders", "method": "POST",
                     "params": {}, "body_params": {"amount": []}}]
    monkeypatch.setattr(webrecon_mod.api_schema, "discover", lambda *a, **k: fake_targets)
    wr = WebRecon()
    p = wr.run_pipeline("example.com", output_dir=str(tmp_path))
    assert p["api_schema_targets"] == fake_targets
    assert "apischema" in p["stages_run"]
    import json, os
    from bugtool import artifacts
    out_file = artifacts.out_path(str(tmp_path), "api_schema")   # 07_api_sema_hedefleri.json
    assert os.path.exists(out_file)
    with open(out_file, encoding="utf-8") as f:
        assert json.load(f) == fake_targets


def test_apischema_stage_can_be_disabled(monkeypatch, tmp_path):
    _patch(monkeypatch)
    called = {"n": 0}

    def spy(*a, **k):
        called["n"] += 1
        return []
    monkeypatch.setattr(webrecon_mod.api_schema, "discover", spy)
    wr = WebRecon(stages={"apischema": False})
    p = wr.run_pipeline("example.com", output_dir=str(tmp_path))
    assert "apischema" in p["stages_skipped"]
    assert called["n"] == 0


def test_webrecon_uses_probe_scheme_when_httpx_empty(monkeypatch, tmp_path):
    # httpx kurulu AMA boş çıktı verdi (0 host) → yedek yöntem devreye girip gerçek
    # protokolü (http-only hedef) bulmalı, körlemesine https yazmamalı.
    _patch(monkeypatch)

    def fake_run(cmd, timeout=300, **kw):
        if "httpx" in cmd.lower():
            return {"success": True, "stdout": "", "stderr": "", "command": cmd}
        if "subfinder" in cmd.lower() or "dnsx" in cmd.lower():
            return {"success": True, "stdout": SUBS, "stderr": "", "command": cmd}
        return {"success": True, "stdout": "", "stderr": "", "command": cmd}

    monkeypatch.setattr(webrecon_mod, "run", fake_run)
    import requests
    monkeypatch.setattr(requests, "head",
                        lambda url, **kw: (_ for _ in ()).throw(Exception("no https"))
                        if url.startswith("https://") else None)

    wr = WebRecon()
    p = wr.run_pipeline("example.com", output_dir=str(tmp_path))
    from bugtool import artifacts
    with open(artifacts.out_path(str(tmp_path), "livehosts"), encoding="utf-8") as f:
        content = f.read()
    assert "http://" in content and "https://" not in content
