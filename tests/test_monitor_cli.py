"""main.py `monitor --notify` — webhook sonuç geri bildirimi (CliRunner, ağsız/mock)."""

from click.testing import CliRunner

import main
import bugtool.webrecon as webrecon_mod
from bugtool.monitor import AssetMonitor


def _neutralize_pipeline(monkeypatch):
    """webrecon pipeline'ını tamamen sessiz/ağsız yap — sadece monitor komutunun
    webhook-geri-bildirim mantığını izole test etmek istiyoruz."""
    monkeypatch.setattr(webrecon_mod, "have", lambda b: False)
    monkeypatch.setattr(webrecon_mod, "run", lambda *a, **k: {"stdout": "", "success": True})
    monkeypatch.setattr(webrecon_mod.ct_logs, "fetch_subdomains", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.takeover, "check", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.git_check, "check", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.cors_check, "check", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.secrets_scan, "scan", lambda *a, **k: [])
    monkeypatch.setattr(webrecon_mod.api_schema, "discover", lambda *a, **k: [])


def _fake_config(baseline_dir):
    return {"monitor": {"baseline_dir": str(baseline_dir), "webhook_url": "https://hooks.example/x"}}


def test_notify_success_shows_green_check(monkeypatch, tmp_path):
    _neutralize_pipeline(monkeypatch)
    monkeypatch.setattr(main, "load_config", lambda: _fake_config(tmp_path))
    monkeypatch.setattr(AssetMonitor, "has_changes", staticmethod(lambda delta: True))
    monkeypatch.setattr(AssetMonitor, "notify_webhook",
                        lambda self, delta, url, fmt: {"success": True, "status_code": 200})
    result = CliRunner().invoke(main.cli, ["monitor", "example.com", "--notify"])
    assert result.exit_code == 0
    assert "Webhook bildirimi gönderildi" in result.output
    assert "BAŞARISIZ" not in result.output


def test_notify_failure_shows_red_error_with_reason(monkeypatch, tmp_path):
    _neutralize_pipeline(monkeypatch)
    monkeypatch.setattr(main, "load_config", lambda: _fake_config(tmp_path))
    monkeypatch.setattr(AssetMonitor, "has_changes", staticmethod(lambda delta: True))
    monkeypatch.setattr(AssetMonitor, "notify_webhook",
                        lambda self, delta, url, fmt: {"success": False, "error": "timeout"})
    result = CliRunner().invoke(main.cli, ["monitor", "example.com", "--notify"])
    assert result.exit_code == 0
    assert "BAŞARISIZ" in result.output
    assert "timeout" in result.output


def test_notify_failure_falls_back_to_status_code(monkeypatch, tmp_path):
    _neutralize_pipeline(monkeypatch)
    monkeypatch.setattr(main, "load_config", lambda: _fake_config(tmp_path))
    monkeypatch.setattr(AssetMonitor, "has_changes", staticmethod(lambda delta: True))
    monkeypatch.setattr(AssetMonitor, "notify_webhook",
                        lambda self, delta, url, fmt: {"success": False, "status_code": 500})
    result = CliRunner().invoke(main.cli, ["monitor", "example.com", "--notify"])
    assert "HTTP 500" in result.output
