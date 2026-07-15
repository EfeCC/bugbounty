"""Ön-uçuş (preflight) bağımlılık kontrolü — pipeline başlamadan ÖNCE eksikleri gösterir.

Eskiden bir binary (katana/gau/ffuf/…) yoksa ancak 600 sn timeout'tan sonra anlaşılıyordu.
Şimdi `check_dependencies()` pipeline başlamadan hemen önce tüm binary + wordlist durumunu
tek seferde raporlar: EKSİK olanı kırmızıyla, MEVCUT olanı yeşille gösterir. Böylece
kullanıcı pipeline'ı durdurarak gereksiz beklemeyi önleyebilir.

Sadece bugtool'un gerçekten kullandığı binary'leri kontrol eder (kurulum talimatları dahil).
"""

import os
import shutil
from typing import Dict, List, Optional, Tuple

from .shell import resolve


# ── Kontrol edilecek araçlar ─────────────────────────────────────────────────
# (binary_adı, açıklama, kurulum_komutu, zorunlu_mu)
# zorunlu_mu=False → eksikse sarı uyarı, True → kırmızı hata
_TOOLS: List[Tuple[str, str, str, bool]] = [
    ("subfinder", "Subdomain enumerasyonu", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", True),
    ("dnsx", "DNS çözümleme + takeover", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", False),
    ("httpx", "HTTP probe (canlı host tespiti)", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", True),
    ("katana", "Aktif URL crawl", "go install github.com/projectdiscovery/katana/cmd/katana@latest", False),
    ("gau", "Pasif arşiv URL toplama", "go install github.com/lc/gau/v2/cmd/gau@latest", False),
    ("nuclei", "Zafiyet taraması (template)", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", True),
    ("ffuf", "İçerik keşfi (dizin brute)", "go install github.com/ffuf/ffuf/v2@latest", False),
]

# ffuf wordlist aday konumları (webrecon.py ile senkron)
_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]


def _tool_available(name: str) -> bool:
    """Binary PATH'te (veya config override'ında) var mı?"""
    resolved = resolve(name)
    return shutil.which(resolved) is not None


def _find_wordlist(config_wordlist: str = "") -> str:
    """Config veya bilinen konumlarda wordlist bulur."""
    if config_wordlist and os.path.exists(config_wordlist):
        return config_wordlist
    for cand in _WORDLIST_CANDIDATES:
        if os.path.exists(cand):
            return cand
    return ""


def check_dependencies(config: Optional[dict] = None, console=None) -> Dict[str, bool]:
    """Tüm dış bağımlılıkları kontrol eder ve durumlarını konsola basar.

    Returns:
        dict: {tool_name: is_available} eşleştirmesi (programatik kullanım için).
    """
    from rich.table import Table
    from rich.panel import Panel

    if console is None:
        from rich.console import Console
        console = Console()

    config = config or {}
    wc = config.get("webrecon", {}) or {}

    results: Dict[str, bool] = {}
    missing_critical: List[str] = []
    missing_optional: List[str] = []

    # ── Araç tablosu oluştur ─────────────────────────────────────────
    table = Table(title="🔧 Bağımlılık Durumu", border_style="cyan", show_lines=False)
    table.add_column("Araç", style="bold", width=12)
    table.add_column("Durum", width=10, justify="center")
    table.add_column("Açıklama", style="dim")
    table.add_column("Yol / Kurulum", style="dim", max_width=60)

    for name, desc, install_cmd, critical in _TOOLS:
        available = _tool_available(name)
        results[name] = available

        if available:
            resolved_path = shutil.which(resolve(name)) or "?"
            table.add_row(name, "[green]✅ VAR[/green]", desc, resolved_path)
        else:
            if critical:
                missing_critical.append(name)
                table.add_row(name, "[bold red]❌ YOK[/bold red]", desc,
                              f"[red]{install_cmd}[/red]")
            else:
                missing_optional.append(name)
                table.add_row(name, "[yellow]⚠ YOK[/yellow]", desc,
                              f"[yellow]{install_cmd}[/yellow]")

    # ── Wordlist kontrolü ────────────────────────────────────────────
    ffuf_wordlist_cfg = str(wc.get("ffuf_wordlist", "") or "")
    wordlist = _find_wordlist(ffuf_wordlist_cfg)
    if wordlist:
        table.add_row("wordlist", "[green]✅ VAR[/green]", "ffuf wordlist dosyası",
                       wordlist)
        results["wordlist"] = True
    else:
        table.add_row("wordlist", "[yellow]⚠ YOK[/yellow]", "ffuf wordlist dosyası",
                       "[yellow]sudo apt install seclists[/yellow]")
        results["wordlist"] = False
        missing_optional.append("wordlist")

    # ── Python modülleri ─────────────────────────────────────────────
    try:
        import requests  # noqa: F401
        table.add_row("requests", "[green]✅ VAR[/green]", "HTTP kütüphanesi (aktif test)",
                       "pip")
        results["requests"] = True
    except ImportError:
        table.add_row("requests", "[yellow]⚠ YOK[/yellow]", "HTTP kütüphanesi (aktif test)",
                       "[yellow]pip install requests[/yellow]")
        results["requests"] = False
        missing_optional.append("requests")

    # ── Go kontrol ───────────────────────────────────────────────────
    go_available = shutil.which("go") is not None
    if not go_available and (missing_critical or missing_optional):
        table.add_row("go", "[red]❌ YOK[/red]", "Go derleyici (araç kurulumu için)",
                       "[red]https://go.dev/doc/install[/red]")
        results["go"] = False
    elif go_available:
        results["go"] = True

    console.print()
    console.print(table)

    # ── Özet panel ───────────────────────────────────────────────────
    if missing_critical:
        console.print(Panel(
            f"[bold red]❌ KRİTİK EKSİK: {', '.join(missing_critical)}[/bold red]\n"
            f"[dim]Bu araçlar olmadan ana pipeline düzgün çalışamaz.\n"
            f"Kurulum: ./scripts/install_dependencies.sh\n"
            f"Kali: sudo apt install -y {' '.join(missing_critical)}[/dim]",
            border_style="red", title="Eksik Bağımlılıklar"))
    elif missing_optional:
        console.print(Panel(
            f"[yellow]⚠ Opsiyonel eksik: {', '.join(missing_optional)}[/yellow]\n"
            f"[dim]Pipeline çalışır ama bu aşamalar atlanır. Tam recon için kurmanız önerilir.\n"
            f"Kurulum: ./scripts/install_dependencies.sh[/dim]",
            border_style="yellow", title="Eksik Bağımlılıklar"))
    else:
        console.print("[green]  ✅ Tüm bağımlılıklar hazır — tam recon mümkün.[/green]")

    console.print()
    return results
