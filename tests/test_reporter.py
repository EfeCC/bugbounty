"""İlerleme raporlayıcı entegrasyonu — reporter olayları + NullReporter varsayılanı + on_progress."""

import contextlib

import bugtool.webrecon as webrecon_mod
from bugtool.reporter import NullReporter
from bugtool.webrecon import WebRecon
from bugtool.fuzzer import ParamFuzzer


class RecordingReporter:
    """Test için — çağrıları kaydeder (spinner yerine)."""

    def __init__(self):
        self.events = []

    @contextlib.contextmanager
    def stage(self, label):
        self.events.append(("stage", label))
        yield

    def done(self, msg, path=None):
        self.events.append(("done", msg))

    def skip(self, msg):
        self.events.append(("skip", msg))

    def info(self, msg):
        self.events.append(("info", msg))

    def error(self, msg):
        self.events.append(("error", msg))

    def finding(self, f):
        self.events.append(("finding", f))


def _neutralize_net(monkeypatch):
    """Ağ-modüllerini no-op'la — gerçek istek atmasınlar (kendi testlerinde test edilir)."""
    monkeypatch.setattr(webrecon_mod.ct_logs, "fetch_subdomains", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.takeover, "check", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.git_check, "check", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.cors_check, "check", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.cors_check, "check_urls", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.exposures, "check", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.jsendpoints, "mine", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.graphql_check, "check", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.secrets_scan, "scan", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.api_schema, "discover", lambda *a, **k: [])
    # httpx boş → _probe_scheme fallback gerçek requests.head atmasın
    import requests
    monkeypatch.setattr(requests, "head", lambda *a, **k: None)


def test_reporter_receives_events(monkeypatch, tmp_path):
    # Binary yok → her aşama skip; reporter bunları almalı
    monkeypatch.setattr(webrecon_mod, "have", lambda b: False)
    monkeypatch.setattr(webrecon_mod, "run", lambda *a, **k: {"stdout": "", "success": True})
    _neutralize_net(monkeypatch)
    rep = RecordingReporter()
    WebRecon().run_pipeline("example.com", output_dir=str(tmp_path), reporter=rep)
    kinds = [e[0] for e in rep.events]
    assert "info" in kinds                       # başlangıç hedef/çıktı bilgisi
    assert kinds.count("skip") >= 5              # subfinder/dnsx/httpx/katana/gau/nuclei


def test_reporter_done_on_success(monkeypatch, tmp_path):
    # subfinder çalışırsa → stage + done olayı
    monkeypatch.setattr(webrecon_mod, "have", lambda b: b == "subfinder")
    monkeypatch.setattr(webrecon_mod, "run",
                        lambda *a, **k: {"stdout": "example.com\napi.example.com\n", "success": True})
    _neutralize_net(monkeypatch)
    rep = RecordingReporter()
    WebRecon().run_pipeline("example.com", output_dir=str(tmp_path), reporter=rep)
    assert any(e[0] == "stage" and "subfinder" in e[1] for e in rep.events)
    assert any(e[0] == "done" and "subdomain" in e[1] for e in rep.events)


def test_null_reporter_default_no_crash(monkeypatch, tmp_path):
    monkeypatch.setattr(webrecon_mod, "have", lambda b: False)
    monkeypatch.setattr(webrecon_mod, "run", lambda *a, **k: {"stdout": "", "success": True})
    _neutralize_net(monkeypatch)
    # reporter=None → NullReporter; çökmemeli
    out = WebRecon().run_pipeline("example.com", output_dir=str(tmp_path))
    assert out["domain"] == "example.com"
    # açıkça NullReporter da sorunsuz
    WebRecon().run_pipeline("example.com", output_dir=str(tmp_path), reporter=NullReporter())


def test_console_reporter_finding_prints():
    # ConsoleReporter.finding bir bulguyu ekrana basmalı (canlı çıktı).
    from rich.console import Console
    from bugtool.reporter import ConsoleReporter
    import io
    buf = io.StringIO()
    ConsoleReporter(Console(file=buf, force_terminal=False, width=200)).finding(
        {"class": "secret_leak", "severity": "high",
         "title": "Secret Sızıntısı: AWS (x.example.com)", "evidence": "AKIA…1234"})
    out = buf.getvalue()
    assert "BULUNDU" in out
    assert "Secret Sızıntısı" in out


def test_recon_findings_written_to_category_files(monkeypatch, tmp_path):
    # exposures bir bulgu üretince reports/<oturum>/bulgular/ifsa_misconfig.jsonl oluşmalı.
    import re as _re
    monkeypatch.setattr(webrecon_mod, "have", lambda b: False)
    monkeypatch.setattr(webrecon_mod, "run", lambda *a, **k: {"stdout": "", "success": True})
    _neutralize_net(monkeypatch)
    monkeypatch.setattr(webrecon_mod.exposures, "check",
                        lambda *a, **k: [{"class": "env_exposure", "severity": "high",
                                          "title": "Ortam Dosyası İfşası (.env): x", "evidence": "e"}])
    WebRecon().run_pipeline("example.com", output_dir=str(tmp_path))
    assert (tmp_path / "bulgular" / "ifsa_misconfig.jsonl").exists()
    assert (tmp_path / "bulgular" / "_TUMU.json").exists()


def test_reporter_finding_called_live_for_recon(monkeypatch, tmp_path):
    # Bulgu, aşama sonu sayacı DEĞİL, on_finding üzerinden CANLI raporlanmalı.
    monkeypatch.setattr(webrecon_mod, "have", lambda b: False)
    monkeypatch.setattr(webrecon_mod, "run", lambda *a, **k: {"stdout": "", "success": True})
    _neutralize_net(monkeypatch)

    def fake_exposures_check(*a, on_finding=None, **k):
        f = {"class": "env_exposure", "severity": "high", "title": "t", "evidence": "e"}
        if on_finding:
            on_finding(f)          # webrecon reporter.finding'i buraya geçirir → canlı
        return [f]
    monkeypatch.setattr(webrecon_mod.exposures, "check", fake_exposures_check)
    rep = RecordingReporter()
    WebRecon().run_pipeline("example.com", output_dir=str(tmp_path), reporter=rep)
    assert any(e[0] == "finding" for e in rep.events)


def test_fuzzer_on_progress(monkeypatch):
    import requests

    class _R:
        text = "ok normal page"
        status_code = 200
        headers = {}

    monkeypatch.setattr(requests, "get", lambda *a, **k: _R())
    calls = []
    fz = ParamFuzzer()
    targets = [
        {"url": "http://a.example.com/p?id=1", "params": {"id": ["sqli"]}},
        {"url": "http://a.example.com/q?x=1", "params": {"x": ["xss"]}},
    ]
    fz.fuzz_targets(targets, on_progress=lambda i, t, s, n: calls.append((i, t)))
    assert calls, "on_progress hiç çağrılmadı"
    assert calls[-1] == (2, 2)                   # son endpoint 2/2
