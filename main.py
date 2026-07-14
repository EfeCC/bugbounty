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
from bugtool.triage import Triage
from bugtool.fuzzer import ParamFuzzer
from bugtool.reporter import ConsoleReporter

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


def _run_webrecon(target: str, config: dict, output_dir: str, passive: bool = None,
                  reporter=None) -> dict:
    wr = WebRecon.from_config(config)
    if passive is not None:
        wr.passive_only = passive
    checker = _scope_checker(config)
    if not checker.is_in_scope(target):
        raise click.ClickException(
            f"KAPSAM DIŞI: {target} — scope.txt / config.yaml → scope bölümünü kontrol edin.")
    return wr.run_pipeline(target, output_dir=output_dir, scope_checker=checker.is_in_scope,
                           reporter=reporter)


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
            console.print(f"  • ({f['severity']}) {f['title']} — {f.get('evidence', '')[:100]}")


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
        ("gone_live_hosts", "📴 Artık Canlı Olmayan Host"),
        ("gone_findings", "✅ Artık Görünmeyen Bulgu (yama?)"),
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
    parsed = _run_webrecon(target, config, output_dir, passive=(passive or None),
                           reporter=ConsoleReporter(console))
    console.print()
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
    parsed = _run_webrecon(scope, config, output_dir, passive=(passive or None),
                           reporter=ConsoleReporter(console))
    console.print()
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


def _latest_reports_dir() -> str:
    base = "reports"
    if not os.path.isdir(base):
        return ""
    dirs = [os.path.join(base, d) for d in os.listdir(base)
            if os.path.isdir(os.path.join(base, d))]
    return max(dirs, key=os.path.getmtime) if dirs else ""


def _render_triage(result: dict):
    """Triyaj sonucunu (ilginç URL / tech / parametreli endpoint) konsola basar."""
    s = result["stats"]
    console.print(f"[dim]  {s['urls']} URL · {s['param_endpoints']} parametreli endpoint · "
                  f"{s['interesting']} ilginç URL · {s['tech_flags']} tech işareti[/dim]")
    if result["interesting_urls"]:
        console.print("\n[bold yellow]⚠️  İlginç / İfşa URL'ler:[/bold yellow]")
        for it in result["interesting_urls"][:40]:
            console.print(f"  • ({it['reason']}) {it['url']}")
    if result["tech"]:
        console.print("\n[bold yellow]🧩 Teknoloji İşaretleri:[/bold yellow]")
        for t in result["tech"][:30]:
            console.print(f"  • {t['url']} — {t['note']} ({', '.join(t['tech'][:5])})")
    if result["param_targets"]:
        console.print("\n[bold yellow]🎯 Parametreli Endpoint'ler (aday vuln sınıfı):[/bold yellow]")
        for pt in result["param_targets"][:40]:
            for name, classes in pt["params"].items():
                tag = ", ".join(classes) if classes else "genel"
                console.print(f"  • {name} → ({tag})  {pt['url'][:90]}")


def _run_active_test(result: dict, config: dict, session_dir: str):
    """Aktif detection-payload testini çalıştırır (opt-in). POTANSİYEL bulguları kaydeder.

    GÜVENLİK: gerçek bir kapsam (scope.txt dolu VEYA allowed_targets) yoksa SERT DURUR —
    hiç istek atmaz. Eskiden yalnızca sarı uyarı basıp devam ediyordu; taze kurulumda
    scope.txt henüz yokken aktif test fiilen kapsamsız çalışabiliyordu."""
    checker = _scope_checker(config)
    if not checker.has_real_scope():
        console.print(Panel(
            "[bold red]❌ AKTİF TEST DURDURULDU[/bold red]\n"
            "Gerçek bir kapsam tanımı yok: scope.txt yok/boş ve config.yaml → "
            "scope.allowed_targets de boş.\n"
            "[dim]Önce program kapsamını scope.txt'ye ekle (satır formatı: `example.com` / "
            "`*.example.com` izinli, `!admin.example.com` yasak) ya da config.yaml → "
            "scope.allowed_targets'ı doldur, sonra tekrar dene.[/dim]",
            border_style="red"))
        return
    fuzzer = ParamFuzzer.from_config(config, scope_checker=checker.is_in_scope)
    if not fuzzer.available:
        console.print("[bold red]❌ 'requests' kurulu değil — aktif test yapılamıyor "
                      "(pip install requests).[/bold red]")
        return
    if not result["param_targets"]:
        console.print("[dim]  Aktif test için parametreli endpoint yok — atlandı.[/dim]")
        return

    console.print(Panel(
        f"[bold red]⚡ AKTİF TEST[/bold red] — {len(result['param_targets'])} endpoint, "
        f"max {fuzzer.max_requests} istek, delay {fuzzer.delay}s.\n"
        f"[dim]Non-destructive detection payload'ları · yalnızca scope-içi host'lar.[/dim]",
        border_style="red"))

    def _report(f):
        console.print(f"  [bold red]🎯 {f['class'].upper()}[/bold red] "
                      f"({f['confidence']}) {f['param']} @ {f['url'][:70]} — {f['evidence'][:90]}")

    with console.status("[bold red]Aktif test başlıyor…[/bold red]", spinner="dots") as status:
        def _progress(i, total, sent, nf):
            status.update(f"[bold red]Aktif test — {i}/{total} endpoint · {sent} istek · "
                          f"{nf} POTANSİYEL bulgu[/bold red]")
        findings = fuzzer.fuzz_targets(result["param_targets"],
                                       on_finding=_report, on_progress=_progress)

    console.print(f"\n[bold]Aktif test bitti — {fuzzer._sent} istek, "
                  f"{len(findings)} POTANSİYEL bulgu.[/bold]")
    out_file = os.path.join(session_dir, "triage_findings.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({"findings": findings}, f, indent=2, ensure_ascii=False)
    console.print(f"[dim]  Bulgular: {out_file}[/dim]")
    if findings:
        console.print("[dim]  Hepsi POTANSİYEL — Windsurf/Burp ile manuel doğrula.[/dim]")


@cli.command()
@click.option("--dir", "session_dir", default="", help="Recon oturum dizini (boşsa reports/ altındaki en son)")
@click.option("--active", is_flag=True, default=False,
              help="AKTİF test: bulunan parametrelere detection payload'ları bas (scope-içi, opt-in)")
def triage(session_dir, active):
    """🔎 Triyaj: recon çıktısını analiz et → tehlikeli param/dosya/tech işaretle.

    --active ile bulunan parametreler XSS/SQLi/LFI/SSTI/redirect/CRLF/CMDi/SSRF için
    scope-içi, non-destructive detection payload'larıyla test edilir (POTANSİYEL bulgu).

    Örnekler:
        python main.py triage
        python main.py triage --dir reports/example.com_20260713_120000
        python main.py triage --active
    """
    config = load_config()
    if not session_dir:
        session_dir = _latest_reports_dir()
    if not session_dir or not os.path.isdir(session_dir):
        console.print("[bold red]❌ Recon oturumu bulunamadı. Önce: python main.py recon <hedef>[/bold red]")
        return

    console.print(Panel(f"[bold cyan]🔎 Triyaj: {session_dir}[/bold cyan]", border_style="cyan"))
    with console.status("[bold cyan]Recon çıktısı analiz ediliyor (param/dosya/tech)…[/bold cyan]",
                        spinner="dots"):
        result = Triage().analyze_dir(session_dir)
    _render_triage(result)

    if not active:
        console.print("\n[dim]  Aktif test için: python main.py triage --active[/dim]")
        return
    _run_active_test(result, config, session_dir)


@cli.command()
@click.argument("target")
@click.option("--passive", is_flag=True, default=False, help="Sadece pasif kaynaklar (aktif crawl/ffuf kapalı)")
@click.option("--active", is_flag=True, default=False,
              help="Triyaj sonrası AKTİF payload testi de yap (scope-içi, opt-in)")
def hunt(target, passive, active):
    """🎯 Hunt: TEK KOMUTTA recon → triyaj (→ opsiyonel aktif test).

    recon (subdomain→httpx→ffuf→url→nuclei) + triyaj (param/dosya/tech) otomatik zincir.
    --active eklersen bulunan parametreler detection payload'larıyla da test edilir.

    Örnekler:
        python main.py hunt example.com
        python main.py hunt example.com --active
    """
    config = load_config()
    from datetime import datetime
    safe = target.replace("://", "_").replace("/", "_")
    output_dir = os.path.join("reports", f"{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    console.print(Panel(f"[bold magenta]🎯 Hunt başlatılıyor: {target}[/bold magenta]\n"
                        f"[dim]recon → triyaj" + (" → aktif test" if active else "") + "[/dim]",
                        border_style="magenta"))

    # ── Aşama 1: recon ──
    console.print("\n[bold cyan]▶ Aşama 1/2 — Recon[/bold cyan]")
    parsed = _run_webrecon(target, config, output_dir, passive=(passive or None),
                           reporter=ConsoleReporter(console))
    console.print()
    _print_summary(parsed, output_dir)

    # ── Aşama 2: triyaj ──
    console.print("\n[bold cyan]▶ Aşama 2/2 — Triyaj[/bold cyan]")
    with console.status("[bold cyan]Recon çıktısı analiz ediliyor…[/bold cyan]", spinner="dots"):
        result = Triage().analyze_dir(output_dir)
    _render_triage(result)

    if active:
        _run_active_test(result, config, output_dir)
    else:
        console.print("\n[dim]  Aktif test için: python main.py hunt "
                      f"{target} --active[/dim]")


if __name__ == "__main__":
    cli()
