"""bugtool — CLI giriş noktası.

Bug bounty asset recon + yeni-asset izleme. Tamamen deterministik: hiçbir komut
LLM çağırmaz. AI (Windsurf/Claude/vs.) yalnızca ÇIKTIYI analiz etmek için kullanılır
(bkz. .windsurfrules, docs/windsurf-workflow.md).
"""

import json
import os

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from bugtool.webrecon import WebRecon
from bugtool.monitor import AssetMonitor
from bugtool.scope import ScopeChecker

console = Console()


def load_config() -> dict:
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def _scope_checker(config: dict) -> ScopeChecker:
    sc = config.get("scope", {}) or {}
    scope_file = sc.get("scope_file")
    if scope_file and not os.path.isabs(scope_file):
        scope_file = os.path.join(os.path.dirname(__file__), scope_file)
    return ScopeChecker(scope_file=scope_file,
                        allowed=sc.get("allowed_targets", []),
                        excluded=sc.get("excluded_targets", []))


def _run_webrecon(target: str, config: dict, output_dir: str, passive: bool = None) -> dict:
    wr = WebRecon.from_config(config)
    if passive is not None:
        wr.passive_only = passive
    checker = _scope_checker(config)
    if not checker.is_in_scope(target):
        raise click.ClickException(
            f"KAPSAM DIŞI: {target} — scope.txt / config.yaml → scope bölümünü kontrol edin.")
    return wr.run_pipeline(target, output_dir=output_dir, scope_checker=checker.is_in_scope)


def _print_summary(parsed: dict, output_dir: str):
    t = Table(title="🌐 Web Recon Özeti", border_style="cyan")
    t.add_column("Metrik", style="bold")
    t.add_column("Adet", justify="right")
    t.add_row("Subdomain", str(len(parsed.get("subdomains", []))))
    t.add_row("Canlı host", str(len(parsed.get("live_hosts", []))))
    t.add_row("URL", str(len(parsed.get("urls", []))))
    t.add_row("Endpoint", str(len(parsed.get("discovered_endpoints", []))))
    t.add_row("Nuclei bulgusu", str(len(parsed.get("findings", []))))
    console.print(t)
    ran = ", ".join(parsed.get("stages_run", [])) or "-"
    skipped = ", ".join(parsed.get("stages_skipped", [])) or "-"
    console.print(f"[dim]  Çalışan aşamalar: {ran}[/dim]")
    console.print(f"[yellow]  Atlanan (binary yok?): {skipped}[/yellow]")
    console.print(f"[dim]  Artifact'ler: {output_dir}[/dim]")
    findings = parsed.get("findings", [])
    if findings:
        console.print("\n[bold yellow]Nuclei Bulguları:[/bold yellow]")
        for f in findings[:30]:
            console.print(f"  • [{f['severity']}] {f['title']} — {f.get('evidence', '')[:100]}")


def _print_monitor_delta(scope: str, delta: dict, first_run: bool = False):
    if first_run:
        console.print(Panel(
            f"[bold cyan]🔭 İlk baseline kaydedildi: {scope}[/bold cyan]\n"
            f"[dim]  Diff için tekrar çalıştırın: python main.py monitor {scope}[/dim]",
            border_style="cyan"))
    if not AssetMonitor.has_changes(delta):
        console.print(f"[green]✅ {scope}: yeni asset yok (son taramadan beri değişiklik yok).[/green]")
        return
    labels = [
        ("new_live_hosts", "🆕 Yeni Canlı Host"),
        ("new_subdomains", "🆕 Yeni Subdomain"),
        ("new_endpoints", "🆕 Yeni Endpoint"),
        ("new_findings", "🆕 Yeni Nuclei Bulgusu"),
    ]
    for key, title in labels:
        items = delta.get(key, [])
        if not items:
            continue
        console.print(f"\n[bold yellow]{title} ({len(items)}):[/bold yellow]")
        for it in items[:50]:
            console.print(f"  • {it}")
        if len(items) > 50:
            console.print(f"  [dim]… ve {len(items) - 50} tane daha[/dim]")


@click.group()
def cli():
    """🐛 bugtool — Bug Bounty Recon & Monitor (deterministik, LLM'siz)."""
    pass


@cli.command()
@click.argument("target")
@click.option("--output-dir", default="", help="Artifact dizini (boşsa reports/<hedef>_<ts>/)")
@click.option("--passive", is_flag=True, default=False, help="Sadece pasif kaynaklar (aktif crawl kapalı)")
def recon(target, output_dir, passive):
    """🌐 Web Recon: subdomain → httpx → URL → nuclei.

    Örnekler:
        python main.py recon example.com
        python main.py recon example.com --passive
    """
    config = load_config()
    if not output_dir:
        from datetime import datetime
        safe = target.replace("://", "_").replace("/", "_")
        output_dir = os.path.join("reports", f"{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    console.print(Panel(f"[bold cyan]🌐 Web Recon başlatılıyor: {target}[/bold cyan]", border_style="cyan"))
    parsed = _run_webrecon(target, config, output_dir, passive=(passive or None))
    _print_summary(parsed, output_dir)


@cli.command()
@click.argument("scope")
@click.option("--passive", is_flag=True, default=False, help="Sadece pasif kaynaklar")
@click.option("--diff-only", is_flag=True, default=False,
              help="Yeniden tarama yapma; kaydedilmiş son iki baseline'ı diff'le")
@click.option("--notify", is_flag=True, default=False, help="Yeni asset bulununca webhook'a bildir")
def monitor(scope, passive, diff_only, notify):
    """🔭 Monitor: bir scope için YENİ asset diff'i.

    Örnekler:
        python main.py monitor example.com
        python main.py monitor example.com --diff-only
        python main.py monitor example.com --notify
    """
    config = load_config()
    mcfg = config.get("monitor", {}) or {}
    mon = AssetMonitor(scope=scope, baseline_dir=mcfg.get("baseline_dir", "recon"))

    if diff_only:
        history = mon.load_history()
        if len(history) < 2:
            console.print(f"[yellow]Diff için en az 2 baseline gerekli. Önce `python main.py monitor "
                          f"{scope}` (taramalı) çalıştırın.[/yellow]")
            return
        with open(history[-2], "r", encoding="utf-8") as f:
            old = json.load(f)
        with open(history[-1], "r", encoding="utf-8") as f:
            new = json.load(f)
        _print_monitor_delta(scope, mon.diff(old, new))
        return

    console.print(Panel(f"[bold cyan]🔭 Monitor: {scope}[/bold cyan]", border_style="cyan"))
    output_dir = os.path.join(mcfg.get("baseline_dir", "recon"), "_scan_tmp")
    parsed = _run_webrecon(scope, config, output_dir, passive=(passive or None))
    snap = mon.snapshot(parsed)
    old = mon.load_latest()
    delta = mon.diff(old, snap)
    mon.save(snap)
    _print_monitor_delta(scope, delta, first_run=(old is None))

    if (notify or mcfg.get("notify", False)) and mon.has_changes(delta):
        webhook_url = mcfg.get("webhook_url")
        if webhook_url:
            console.print("[dim]  📡 Yeni asset'ler webhook'a bildiriliyor…[/dim]")
            mon.notify_webhook(delta, webhook_url, mcfg.get("webhook_format", "generic"))
        else:
            console.print("[yellow]  ⚠ --notify verildi ama config.yaml → monitor.webhook_url boş.[/yellow]")


if __name__ == "__main__":
    cli()
