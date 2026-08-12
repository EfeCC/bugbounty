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
from bugtool.scope import ScopeChecker, auto_scope_entry, host_only
from bugtool.triage import Triage
from bugtool import artifacts
from bugtool.fuzzer import ParamFuzzer
from bugtool.api_probe import ApiProbe
from bugtool.reporter import ConsoleReporter
from bugtool.oob import OobManager, read_hit_tokens
from bugtool.shell import set_binary_paths, detect_httpx_conflict
from bugtool.preflight import check_dependencies

console = Console()

_CONFLICT_WARNED = False
_PREFLIGHT_DONE = False


def load_config() -> dict:
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    else:
        cfg = {}

    # Binary yol override'larını shell.py registry'sine yükle (Kali httpx çakışması vb.)
    binaries = cfg.get("binaries", {}) or {}
    set_binary_paths(binaries)

    # İlk çağrıda httpx çakışma kontrolü
    global _CONFLICT_WARNED
    if not _CONFLICT_WARNED:
        _CONFLICT_WARNED = True
        warning = detect_httpx_conflict()
        if warning:
            console.print(Panel(f"[bold yellow]{warning}[/bold yellow]",
                                border_style="yellow", title="Binary Çakışması"))

    # İlk çağrıda ön-uçuş bağımlılık kontrolü — pipeline başlamadan ÖNCE eksikleri gösterir.
    # Eskiden binary yoksa ancak 600sn timeout'tan sonra anlaşılıyordu.
    global _PREFLIGHT_DONE
    if not _PREFLIGHT_DONE:
        _PREFLIGHT_DONE = True
        check_dependencies(cfg, console=console)

    return cfg


def _scope_checker(config: dict, extra_allowed=None) -> ScopeChecker:
    """Scope kontrolcüsü kurar. `extra_allowed` = hedeften OTOMATİK türetilen izin
    girdileri (ör. `*.staging.gitsec.io` ya da test edilecek endpoint host'ları).

    `scope.auto_from_target` (varsayılan True) açıkken bu otomatik girdiler config'in
    `allowed_targets`'ına EKLENİR — böylece her yeni site için scope.txt'i elle
    değiştirmek gerekmez. scope.txt yine okunur: `excluded_targets`/`!` girdileri HER
    ZAMAN önce kontrol edilir ve otomatik izni EZER (carve-out korunur). Flag False ise
    otomatik girdiler yok sayılır → eski katı davranış (yalnızca scope.txt/allowed)."""
    sc = config.get("scope", {}) or {}
    scope_file = sc.get("scope_file")
    if scope_file and not os.path.isabs(scope_file):
        scope_file = os.path.join(os.path.dirname(__file__), scope_file)
    allowed = list(sc.get("allowed_targets", []) or [])
    if sc.get("auto_from_target", True) and extra_allowed:
        allowed += [e for e in extra_allowed if e]
    return ScopeChecker(scope_file=scope_file,
                        allowed=allowed,
                        excluded=sc.get("excluded_targets", []))


def _run_webrecon(target: str, config: dict, output_dir: str, passive: bool = None,
                  reporter=None) -> dict:
    wr = WebRecon.from_config(config)
    if passive is not None:
        wr.passive_only = passive
    # Hedefi OTOMATİK scope'a ekle: `*.<host>` — hem hedefi yetkiler hem recon'un bulduğu
    # subdomain URL'lerini scope-içi sayar. scope.txt'in `!exclusion`'ları yine önce
    # kontrol edilir; hedef bir exclusion'a takılırsa aşağıdaki is_in_scope False döner.
    checker = _scope_checker(config, extra_allowed=[auto_scope_entry(target)])
    if not checker.is_in_scope(target):
        raise click.ClickException(
            f"KAPSAM DIŞI: {target} — scope.txt'te `!` ile hariç tutulmuş görünüyor "
            f"(ya da scope.auto_from_target=false ve scope.txt'te yok). "
            f"config.yaml → scope bölümünü kontrol edin.")
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


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """🐛 bugtool — Bug Bounty Recon & Monitor (deterministik, LLM'siz).

    Parametresiz çalıştırılırsa (python main.py) interaktif menü açılır.
    """
    if ctx.invoked_subcommand is None:
        _interactive_menu(ctx)


_MENU = [
    ("Hunt", "recon → triyaj tek komut (en sık kullanılan)"),
    ("Recon", "sadece keşif (subdomain → httpx → ffuf → nuclei)"),
    ("Monitor", "yeni/kaybolan asset takibi (baseline diff)"),
    ("Triage", "mevcut recon çıktısını analiz et (+ opsiyonel aktif test)"),
    ("OOB korelasyon", "collaborator callback'lerini gömülü problarla eşleştir"),
    ("Bağımlılık kontrolü", "tüm araçların kurulu olup olmadığını kontrol et"),
]


def _interactive_menu(ctx):
    """Parametresiz başlatınca çıkan numaralı mod menüsü. Her mod için gereken girdileri
    tek tek sorar, sonra ilgili komutu çağırır. 0 = çıkış."""
    console.print(Panel("[bold cyan]🐛 bugtool[/bold cyan] — Bug Bounty Recon & Analiz\n"
                        "[dim]deterministik · LLM'siz · asistan[/dim]", border_style="cyan"))
    while True:
        console.print("\n[bold]Mod seç:[/bold]")
        for i, (name, desc) in enumerate(_MENU, 1):
            console.print(f"  [bold cyan]{i}[/bold cyan]) {name}  [dim]— {desc}[/dim]")
        console.print("  [bold cyan]0[/bold cyan]) Çıkış")
        try:
            choice = click.prompt("\nSeçiminiz", type=click.IntRange(0, len(_MENU)), default=1)
        except click.Abort:
            console.print("\n[dim]Çıkılıyor.[/dim]")
            return
        if choice == 0:
            console.print("[dim]Görüşürüz.[/dim]")
            return
        try:
            if choice == 1:
                target = click.prompt("Hedef (domain / URL)")
                passive = click.confirm("Sadece pasif kaynaklar mı? (aktif crawl/ffuf kapalı)",
                                        default=False)
                active = click.confirm("Aktif payload testi yapılsın mı? (scope-içi, opt-in)",
                                       default=False)
                oob = ""
                if active:
                    oob = click.prompt("OOB collaborator domain (kör açıklar; boş=atla)",
                                       default="", show_default=False).strip()
                ctx.invoke(hunt, target=target, passive=passive, active=active, oob_domain=oob)
            elif choice == 2:
                target = click.prompt("Hedef (domain / URL)")
                passive = click.confirm("Sadece pasif kaynaklar mı?", default=False)
                ctx.invoke(recon, target=target, output_dir="", passive=passive)
            elif choice == 3:
                scope = click.prompt("Scope (domain)")
                passive = click.confirm("Sadece pasif kaynaklar mı?", default=False)
                notify = click.confirm("Yeni asset'te webhook bildirimi gönderilsin mi?",
                                       default=False)
                ctx.invoke(monitor, scope=scope, passive=passive, diff_only=False, notify=notify)
            elif choice == 4:
                sd = click.prompt("Recon oturum dizini (boş = en son)",
                                  default="", show_default=False).strip()
                active = click.confirm("Aktif payload testi yapılsın mı?", default=False)
                oob = ""
                if active:
                    oob = click.prompt("OOB collaborator domain (boş=atla)",
                                       default="", show_default=False).strip()
                ctx.invoke(triage, session_dir=sd, active=active, oob_domain=oob)
            elif choice == 5:
                sd = click.prompt("Prob'un gömüldüğü oturum dizini (boş = en son)",
                                  default="", show_default=False).strip()
                hits = click.prompt("Callback token dosyası (hits)")
                ctx.invoke(oob_correlate, session_dir=sd, hits_file=hits)
            elif choice == 6:
                ctx.invoke(check)
        except click.Abort:
            console.print("\n[yellow]İptal edildi, menüye dönülüyor.[/yellow]")
        except click.ClickException as e:
            console.print(f"[bold red]Hata: {e.format_message()}[/bold red]")
        except Exception as e:  # menüyü canlı tut — bir mod patlarsa menü kapanmasın
            console.print(f"[bold red]Beklenmedik hata: {e}[/bold red]")

        if not click.confirm("\nMenüye dön?", default=True):
            console.print("[dim]Görüşürüz.[/dim]")
            return


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
            result = mon.notify_webhook(delta, webhook_url, mcfg.get("webhook_format", "generic"))
            if result.get("success"):
                console.print("[green]  ✅ Webhook bildirimi gönderildi.[/green]")
            else:
                # DÜZELTME: eskiden bu dönüş değeri hiç kontrol edilmiyordu — webhook
                # başarısız olsa bile kullanıcı hiçbir şey görmüyordu.
                reason = result.get("error") or f"HTTP {result.get('status_code', '?')}"
                console.print(f"[bold red]  ❌ Webhook bildirimi BAŞARISIZ: {reason}[/bold red]")
        else:
            console.print("[yellow]  ⚠ --notify verildi ama config.yaml → monitor.webhook_url boş.[/yellow]")


def _latest_reports_dir() -> str:
    base = "reports"
    if not os.path.isdir(base):
        return ""
    dirs = [os.path.join(base, d) for d in os.listdir(base)
            if os.path.isdir(os.path.join(base, d))]
    return max(dirs, key=os.path.getmtime) if dirs else ""


def _write_api_endpoints_file(session_dir: str, result: dict):
    """Triyajda çıkarılan path-tabanlı API endpoint'lerini 06_api_endpointler.txt'ye yazar
    (göz gezdirilebilir liste + aktif testin hedefi)."""
    eps = result.get("api_endpoints") or []
    if not session_dir or not eps:
        return
    try:
        with open(artifacts.out_path(session_dir, "api_endpoints"), "w", encoding="utf-8") as f:
            f.write("\n".join(e["url"] for e in eps) + "\n")
    except OSError:
        pass


def _render_triage(result: dict):
    """Triyaj sonucunu (ilginç URL / tech / parametreli endpoint / API şema) konsola basar."""
    s = result["stats"]
    console.print(f"[dim]  {s['urls']} URL · {s['param_endpoints']} parametreli endpoint · "
                  f"{s.get('api_endpoints', 0)} API endpoint · "
                  f"{s['interesting']} ilginç URL · {s['tech_flags']} tech işareti · "
                  f"{s.get('api_schema_endpoints', 0)} API şema endpoint'i[/dim]")
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
                # İpucu eşleşmeyen parametre yine de aktif testte varsayılan (ucuz+yüksek
                # değerli) xss/sqli/redirect ile denenir — "genel" yerine bunu göster ki
                # kullanıcı "bundan ne çıkar?" diye sormasın.
                tag = ", ".join(classes) if classes else "varsayılan: xss/sqli/redirect"
                console.print(f"  • {name} → ({tag})  {pt['url'][:90]}")
    if result.get("api_endpoints"):
        eps = result["api_endpoints"]
        console.print(f"\n[bold yellow]🧩 Path-tabanlı API Endpoint'ler ({len(eps)}) "
                      f"— --active ile metot/yetki + kör SSRF test edilir:[/bold yellow]")
        for e in eps[:40]:
            console.print(f"  • {e['url'][:100]}")
    if result.get("api_schema_targets"):
        body_count = sum(1 for t in result["api_schema_targets"] if t.get("body_params"))
        console.print(f"\n[bold yellow]📋 API Şema Keşfi (Swagger/OpenAPI) — "
                      f"{len(result['api_schema_targets'])} gizli endpoint, "
                      f"{body_count} body-parametreli:[/bold yellow]")
        for t in result["api_schema_targets"][:30]:
            params = list(t.get("params", {}).keys()) + list(t.get("body_params", {}).keys())
            tag = f"({', '.join(params[:5])})" if params else ""
            console.print(f"  • {t.get('method', 'GET')} {t['url'][:85]} {tag}")
        console.print("[dim]  (--active ile POST/PUT/PATCH + body-parametreliler otomatik "
                      "body-fuzzing'e beslenir; GET olanlar api-probe/manuel)[/dim]")


def _render_api_probe(api_res: dict, sent: int):
    """API-probe sonucunu (metot/yetki haritası tablosu) konsola basar."""
    mm = api_res.get("method_map", [])
    console.print(f"\n[bold]API-probe bitti — {sent} istek, "
                  f"{len(api_res.get('findings', []))} ipucu, "
                  f"{api_res.get('oob_planted', 0)} OOB probu.[/bold]")
    if not mm:
        return
    table = Table(title="🔎 Metot / Yetki Haritası (kimliksiz)")
    table.add_column("Endpoint", overflow="fold", style="cyan")
    table.add_column("GET", justify="right")
    table.add_column("Allow (OPTIONS)")
    table.add_column("Not")
    for row in mm[:60]:
        st = row.get("get_status")
        if isinstance(st, int) and 200 <= st < 300:
            color = "green"
        elif isinstance(st, int) and st >= 500:
            color = "red"
        else:
            color = "yellow"
        st_s = f"[{color}]{st}[/{color}]" if st is not None else "—"
        ep = row.get("url", "").split("://", 1)[-1]
        table.add_row(ep, st_s, (row.get("allow") or "")[:40], row.get("note", ""))
    console.print(table)


def _endpoint_hosts(param_targets: list, api_endpoints: list) -> list:
    """Aktif testte istek atılacak DISTINCT host'ları toplar (otomatik scope girdisi).
    Bu host'lar recon'un `*.<hedef>` filtresinden geçmiştir (hepsi hedefin altında),
    dolayısıyla onları izinli saymak = 'yazdığın hedefi test et' demektir."""
    hosts: list = []
    seen = set()
    for t in list(param_targets) + list(api_endpoints):
        h = host_only(t.get("url", "")) if isinstance(t, dict) else ""
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)
    return hosts


def _run_active_test(result: dict, config: dict, session_dir: str, oob_domain: str = ""):
    """Aktif test (opt-in): query-param fuzzing + path-tabanlı API-probe (metot/yetki +
    kör SSRF OOB). POTANSİYEL bulguları kaydeder.

    GÜVENLİK: `scope.auto_from_target` (varsayılan True) açıkken test edilecek endpoint
    host'ları OTOMATİK izinli sayılır (recon'un `*.<hedef>` filtresinden geçmiş host'lar) —
    scope.txt'i elle doldurmadan hedefe-özel yetkilenir. Flag False VE scope.txt/allowed
    boşsa SERT DURUR, hiç istek atmaz. scope.txt'in `!exclusion`'ları her iki modda da
    önce kontrol edilir ve otomatik izni EZER."""
    param_targets = result.get("param_targets") or []
    api_endpoints = result.get("api_endpoints") or []
    # api_schema'dan çıkarılan POST/PUT/PATCH + body-parametreli endpoint'ler → body fuzzing.
    body_targets = [t for t in (result.get("api_schema_targets") or [])
                    if t.get("body_params")
                    and (t.get("method") or "").upper() in ("POST", "PUT", "PATCH")]
    if not param_targets and not api_endpoints and not body_targets:
        console.print("[dim]  Aktif test için parametreli endpoint / API endpoint / body-param "
                      "yok — atlandı.[/dim]")
        return

    # OTOMATİK scope: istek atılacak host'ları izinli say (auto_from_target açıksa).
    endpoint_hosts = _endpoint_hosts(param_targets, list(api_endpoints) + list(body_targets))
    checker = _scope_checker(config, extra_allowed=endpoint_hosts)
    if not checker.has_real_scope():
        console.print(Panel(
            "[bold red]❌ AKTİF TEST DURDURULDU[/bold red]\n"
            "Kapsam belirlenemedi: scope.auto_from_target=false VE scope.txt yok/boş "
            "VE config.yaml → scope.allowed_targets de boş.\n"
            "[dim]Ya scope.auto_from_target'ı açık bırak (hedef otomatik yetkilenir), "
            "ya da program kapsamını scope.txt'ye ekle (satır formatı: `example.com` / "
            "`*.example.com` izinli, `!admin.example.com` yasak), sonra tekrar dene.[/dim]",
            border_style="red"))
        return

    fuzzer = ParamFuzzer.from_config(config, scope_checker=checker.is_in_scope)
    if not fuzzer.available:
        console.print("[bold red]❌ 'requests' kurulu değil — aktif test yapılamıyor "
                      "(pip install requests).[/bold red]")
        return

    all_findings: list = []
    # OOB manager'ı bir kez oluştur — hem param query probları hem API SSRF probları AYNI
    # depoya (oob_probes.json) yazsın ki tek `oob-correlate` ile hepsi eşleşsin.
    oob = (OobManager(oob_domain, seed=os.path.basename(session_dir.rstrip("/\\")) or "bugtool")
           if oob_domain else None)
    oob_planted = 0

    # ── 1. Query-param fuzzing (?param= olan URL'ler) ──
    if param_targets:
        console.print(Panel(
            f"[bold red]⚡ AKTİF TEST (parametre)[/bold red] — {len(param_targets)} endpoint, "
            f"max {fuzzer.max_requests} istek, delay {fuzzer.delay}s.\n"
            f"[dim]Non-destructive detection payload'ları · yalnızca scope-içi host'lar.[/dim]",
            border_style="red"))

        def _report(f):
            if f.get("verdict") == "inconclusive":
                console.print(f"  [yellow]❓ {f['class'].upper()} (BELİRSİZ)[/yellow] "
                              f"{f['param']} @ {f['url'][:66]} — {f['evidence'][:80]}")
            else:
                console.print(f"  [bold red]🎯 {f['class'].upper()}[/bold red] "
                              f"({f['confidence']}) {f['param']} @ {f['url'][:70]} — {f['evidence'][:90]}")

        with console.status("[bold red]Aktif test başlıyor…[/bold red]", spinner="dots") as status:
            def _progress(i, total, sent, nf):
                status.update(f"[bold red]Aktif test — {i}/{total} endpoint · {sent} istek · "
                              f"{nf} POTANSİYEL bulgu[/bold red]")
            findings = fuzzer.fuzz_targets(param_targets, on_finding=_report, on_progress=_progress)
        all_findings.extend(findings)
        fired = [f for f in findings if f.get("verdict") != "inconclusive"]
        incon = [f for f in findings if f.get("verdict") == "inconclusive"]
        console.print(f"\n[bold]Parametre testi bitti — {fuzzer._sent} istek, "
                      f"{len(fired)} POTANSİYEL + {len(incon)} BELİRSİZ bulgu.[/bold]")
        if fuzzer.backoff_triggered:
            console.print("[yellow]  ⚠ Hedef art arda 403/429 döndü — WAF/rate-limit'e çarpıldı, "
                          "tarama erken durduruldu.[/yellow]")

    # ── 1b. POST/JSON body fuzzing (api_schema body_params) ──
    if body_targets:
        console.print(Panel(
            f"[bold red]⚡ AKTİF TEST (JSON body)[/bold red] — {len(body_targets)} "
            f"POST/PUT/PATCH endpoint.\n"
            f"[dim]api_schema'dan çıkarılan body parametrelerine detection payload'ları "
            f"(aynı bütçe) · yalnızca scope-içi.[/dim]", border_style="red"))

        def _breport(f):
            if f.get("verdict") == "inconclusive":
                console.print(f"  [yellow]❓ {f['class'].upper()} (BELİRSİZ)[/yellow] "
                              f"{f['param']} @ {f['url'][:64]} — {f['evidence'][:80]}")
            else:
                console.print(f"  [bold red]🎯 {f['class'].upper()}[/bold red] "
                              f"({f['confidence']}) body:{f['param']} @ {f['url'][:60]} — "
                              f"{f['evidence'][:80]}")

        with console.status("[bold red]Body fuzzing…[/bold red]", spinner="dots") as status:
            def _bprog(i, total, sent, nf):
                status.update(f"[bold red]Body fuzzing — {i}/{total} endpoint · {sent} istek · "
                              f"{nf} bulgu[/bold red]")
            body_findings = fuzzer.fuzz_body_targets(body_targets, on_finding=_breport,
                                                     on_progress=_bprog)
        all_findings.extend(body_findings)
        console.print(f"\n[bold]Body testi bitti — {len(body_findings)} POTANSİYEL bulgu.[/bold]")

    # ── 2. Path-tabanlı API-probe (metot/yetki haritası + kör SSRF OOB) ──
    if api_endpoints:
        api = ApiProbe.from_config(config, scope_checker=checker.is_in_scope)
        if api.available:
            console.print(Panel(
                f"[bold red]⚡ API-PROBE[/bold red] — {len(api_endpoints)} path-tabanlı endpoint.\n"
                f"[dim]Metot/yetki haritası (OPTIONS+GET, non-destructive)"
                + (f" + kör SSRF OOB → {oob_domain}" if oob else "")
                + " · yalnızca scope-içi.[/dim]", border_style="red"))

            def _areport(f):
                console.print(f"  [bold red]🎯 {f['class'].upper()}[/bold red] "
                              f"({f['confidence']}) {f['param']} @ {f['url'][:64]} — {f['evidence'][:80]}")

            with console.status("[bold red]API-probe…[/bold red]", spinner="dots") as status:
                def _aprog(i, total, sent, nf):
                    status.update(f"[bold red]API-probe — {i}/{total} endpoint · {sent} istek · "
                                  f"{nf} ipucu[/bold red]")
                api_res = api.probe(api_endpoints, oob=oob, on_finding=_areport, on_progress=_aprog)
            all_findings.extend(api_res["findings"])
            oob_planted += api_res.get("oob_planted", 0)
            _render_api_probe(api_res, api._sent)
            if api.backoff_triggered:
                console.print("[yellow]  ⚠ API-probe: hedef art arda 403/429 döndü — erken durduruldu.[/yellow]")

    # ── 3. Parametre OOB ekimi (kör SSRF/CMDi/XSS — query params) ──
    if oob and param_targets:
        with console.status("[magenta]Parametre OOB probları gömülüyor…[/magenta]", spinner="dots"):
            oob_planted += fuzzer.plant_oob(param_targets, oob)

    # ── OOB deposunu kaydet + korelasyon talimatı ──
    if oob:
        probe_file = artifacts.out_path(session_dir, "oob")
        oob.save(probe_file)
        console.print(f"\n[bold magenta]📡 {oob_planted} OOB probu gömüldü[/bold magenta] "
                      f"(collaborator: {oob_domain}) — depo: {probe_file}")
        console.print(f"[dim]  1) {oob_domain} altında gelen callback'leri izle.[/dim]")
        console.print(f"[dim]  2) Gelen token'ları bir dosyaya al, sonra:[/dim]")
        console.print(f"[cyan]     python main.py oob-correlate --dir {session_dir} --hits hits.txt[/cyan]")

    # ── bulguları kaydet ──
    out_file = artifacts.out_path(session_dir, "findings")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({"findings": all_findings}, f, indent=2, ensure_ascii=False)
    # Aktif-test bulgularını da kategori dosyalarına ekle (reports/<oturum>/bulgular/<tip>.jsonl).
    # recon'un yazdığı bulgularla BİRLEŞİR (üzerine ezmez).
    artifacts.write_findings_files(session_dir, all_findings)
    console.print(f"\n[dim]  Bulgular: {out_file}  ·  kategori dosyaları: "
                  f"{os.path.join(session_dir, 'bulgular')}/[/dim]")
    if all_findings:
        console.print("[dim]  Hepsi POTANSİYEL — Windsurf/Burp ile manuel doğrula.[/dim]")


@cli.command()
@click.option("--dir", "session_dir", default="", help="Recon oturum dizini (boşsa reports/ altındaki en son)")
@click.option("--active", is_flag=True, default=False,
              help="AKTİF test: bulunan parametrelere detection payload'ları bas (scope-içi, opt-in)")
@click.option("--oob", "oob_domain", default="",
              help="OOB/OAST collaborator domain'i (interactsh/Burp) — kör SSRF/CMDi/XSS probu göm")
def triage(session_dir, active, oob_domain):
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
    _write_api_endpoints_file(session_dir, result)
    _render_triage(result)

    if not active:
        console.print("\n[dim]  Aktif test için: python main.py triage --active[/dim]")
        return
    _run_active_test(result, config, session_dir, oob_domain=oob_domain)


@cli.command()
@click.argument("target")
@click.option("--passive", is_flag=True, default=False, help="Sadece pasif kaynaklar (aktif crawl/ffuf kapalı)")
@click.option("--active", is_flag=True, default=False,
              help="Triyaj sonrası AKTİF payload testi de yap (scope-içi, opt-in)")
@click.option("--oob", "oob_domain", default="",
              help="OOB/OAST collaborator domain'i (interactsh/Burp) — kör SSRF/CMDi/XSS probu göm")
def hunt(target, passive, active, oob_domain):
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
    _write_api_endpoints_file(output_dir, result)
    _render_triage(result)

    if active:
        _run_active_test(result, config, output_dir, oob_domain=oob_domain)
    else:
        # Recon zaten bu dizine kaydedildi — aktif test için tekrar recon YAPMAYA gerek yok.
        # `triage --active` bu son reconu yeniden kullanır (hunt --active baştan recon yapardı).
        console.print("\n[dim]  Aktif test (bu reconu yeniden kullanır, tekrar recon YAPMAZ):[/dim]")
        console.print("[cyan]    python main.py triage --active[/cyan]")


@cli.command(name="oob-correlate")
@click.option("--dir", "session_dir", default="", help="OOB probunun gömüldüğü oturum (boşsa en son)")
@click.option("--hits", "hits_file", required=True,
              help="Collaborator callback token'larını içeren dosya (interactsh çıktısı / elle kopyalanan)")
def oob_correlate(session_dir, hits_file):
    """📡 OOB callback'lerini gömülü problarla eşleştir → KANITLANMIŞ kör bulgu.

    `--oob` ile prob gömdükten sonra collaborator'ında gelen token'ları bir dosyaya al,
    sonra bunu çalıştır. Eşleşen her prob 'confirmed_oob' olarak triage_findings.json'a eklenir.
    """
    if not session_dir:
        session_dir = _latest_reports_dir()
    probe_file = artifacts.read_path(session_dir or "", "oob")
    oob = OobManager.load(probe_file)
    if oob is None:
        console.print(f"[bold red]❌ OOB prob deposu bulunamadı: {probe_file}[/bold red]")
        return
    hits = read_hit_tokens(hits_file)
    if not hits:
        console.print(f"[yellow]  {hits_file} boş ya da okunamadı — callback token'ı yok.[/yellow]")
        return

    confirmed = oob.correlate(hits)
    console.print(Panel(f"[bold magenta]📡 OOB Korelasyon[/bold magenta] — {len(oob.probes)} prob, "
                        f"{len(hits)} callback → [bold]{len(confirmed)} KANITLANMIŞ kör bulgu[/bold]",
                        border_style="magenta"))
    for f in confirmed:
        console.print(f"  [bold red]✅ {f['class'].upper()}[/bold red] {f['param']} @ "
                      f"{f['url'][:70]} — {f['evidence'][:90]}")
    if not confirmed:
        console.print("[dim]  Eşleşme yok — gelen token'lar bu oturumun problarıyla örtüşmüyor.[/dim]")
        return

    # Mevcut bulgular dosyasına ekle (varsa) — yeni ad yoksa legacy'e düşer.
    out_file = artifacts.read_path(session_dir, "findings")
    existing = []
    if os.path.exists(out_file):
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                existing = (json.load(f) or {}).get("findings", [])
        except (OSError, ValueError):
            existing = []
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({"findings": existing + confirmed}, f, indent=2, ensure_ascii=False)
    artifacts.write_findings_files(session_dir, confirmed)   # kategori dosyalarına da ekle
    console.print(f"[dim]  Bulgulara eklendi: {out_file}[/dim]")


@cli.command()
def check():
    """🔧 Bağımlılık kontrolü: tüm araçların kurulu olup olmadığını raporlar.

    Pipeline başlamadan önce hangi araçların eksik olduğunu görmek için:
        python main.py check
    """
    config = load_config()
    # load_config() zaten preflight çalıştırıyor, ama burada _PREFLIGHT_DONE
    # True olmuş olabilir (önceki çağrıdan). Tekrar çalıştır:
    check_dependencies(config, console=console)


if __name__ == "__main__":
    cli()
