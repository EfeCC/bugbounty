"""AssetMonitor — yeni-asset diff / baseline mantığı (saf-Python, deterministik)."""

from bugtool.monitor import AssetMonitor


def _parsed(subs, hosts=(), eps=(), findings=()):
    return {
        "subdomains": list(subs),
        "live_hosts": [{"url": u} for u in hosts],
        "discovered_endpoints": list(eps),
        "findings": [{"title": t} for t in findings],
    }


def test_snapshot_normalizes(tmp_path):
    mon = AssetMonitor("example.com", baseline_dir=str(tmp_path))
    snap = mon.snapshot(_parsed(["b", "a", "a"], hosts=["https://a"], findings=["Nuclei: x"]))
    assert snap["subdomains"] == ["a", "b"]
    assert snap["live_hosts"] == ["https://a"]
    assert snap["findings"] == ["Nuclei: x"]


def test_diff_new_only(tmp_path):
    mon = AssetMonitor("example.com", baseline_dir=str(tmp_path))
    old = mon.snapshot(_parsed(["a.example.com"], hosts=["https://a.example.com"], eps=["/x"]))
    new = mon.snapshot(_parsed(["a.example.com", "b.example.com"],
                               hosts=["https://a.example.com"], eps=["/x", "/y"]))
    delta = mon.diff(old, new)
    assert delta["new_subdomains"] == ["b.example.com"]
    assert delta["new_endpoints"] == ["/y"]
    assert delta["new_live_hosts"] == []
    assert mon.has_changes(delta) is True


def test_diff_tracks_removed(tmp_path):
    # Artık canlı olmayan host / kaybolan bulgu da izlenmeli (yama sinyali)
    mon = AssetMonitor("example.com", baseline_dir=str(tmp_path))
    old = mon.snapshot(_parsed(["a.example.com"],
                               hosts=["https://a.example.com", "https://b.example.com"],
                               findings=["Nuclei: exposed-git"]))
    new = mon.snapshot(_parsed(["a.example.com"], hosts=["https://a.example.com"]))
    delta = mon.diff(old, new)
    assert "https://b.example.com" in delta["gone_live_hosts"]
    assert "Nuclei: exposed-git" in delta["gone_findings"]
    assert mon.has_changes(delta) is True


def test_first_run_everything_new(tmp_path):
    mon = AssetMonitor("x.com", baseline_dir=str(tmp_path))
    assert mon.load_latest() is None
    delta = mon.diff(mon.load_latest(), mon.snapshot(_parsed(["x.com"])))
    assert delta["new_subdomains"] == ["x.com"]


def test_no_change(tmp_path):
    mon = AssetMonitor("x.com", baseline_dir=str(tmp_path))
    snap = mon.snapshot(_parsed(["x.com"]))
    assert mon.has_changes(mon.diff(snap, snap)) is False


def test_save_load_and_history(tmp_path):
    mon = AssetMonitor("h.com", baseline_dir=str(tmp_path))
    mon.save(mon.snapshot(_parsed(["1"])))
    mon.save(mon.snapshot(_parsed(["1", "2"])))
    assert mon.load_latest()["subdomains"] == ["1", "2"]
    history = mon.load_history()
    assert len(history) == 2
    import json
    with open(history[-1], encoding="utf-8") as f:
        assert json.load(f)["subdomains"] == ["1", "2"]


def test_notify_webhook_noop_without_url(tmp_path):
    mon = AssetMonitor("x.com", baseline_dir=str(tmp_path))
    delta = {"new_subdomains": ["a"], "new_live_hosts": [], "new_endpoints": [], "new_findings": []}
    assert mon.notify_webhook(delta, "") == {}


def test_notify_webhook_noop_without_changes(tmp_path):
    mon = AssetMonitor("x.com", baseline_dir=str(tmp_path))
    delta = {"new_subdomains": [], "new_live_hosts": [], "new_endpoints": [], "new_findings": []}
    assert mon.notify_webhook(delta, "https://example.com/hook") == {}
