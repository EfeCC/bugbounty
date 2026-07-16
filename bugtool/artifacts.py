"""Artifact dosya adları — TEK KAYNAK (single source of truth).

Recon → triyaj → aktif-test çıktıları, klasörde göz gezdirince ne olduğu belli olsun
diye AÇIKLAYICI, aşama-sırasına göre NUMARALI Türkçe adlarla kaydedilir
(00_OZET, 01_subdomainler, 02_cozumlenen_dns, …). Site zaten rapor KLASÖRÜNÜN adında
(reports/https_<site>_<ts>/) olduğu için dosya adında tekrar edilmez.

GERİYE-UYUMLULUK: eski raporlar düz İngilizce adlarla yazılmıştı (subdomains.txt,
urls.txt, httpx.jsonl…). Her anahtarın bir de LEGACY adı var; `read_path` yeni ad yoksa
eskiye düşer, böylece eski recon dizinlerinde `triage --active` çalışmaya devam eder.
Yazma (`out_path`) her zaman YENİ adı kullanır.
"""

import os
from typing import Dict, Tuple

# anahtar -> (yeni açıklayıcı ad, eski/legacy ad)
_NAMES: Dict[str, Tuple[str, str]] = {
    "summary":       ("00_OZET.txt",                "00_OZET.txt"),
    "subdomains":    ("01_subdomainler.txt",        "subdomains.txt"),
    "resolved":      ("02_cozumlenen_dns.txt",      "resolved.txt"),
    "livehosts":     ("03_canli_hostlar.txt",       "livehosts.txt"),
    "httpx":         ("04_web_servisleri.jsonl",    "httpx.jsonl"),
    "urls":          ("05_urller.txt",              "urls.txt"),
    "api_endpoints": ("06_api_endpointler.txt",     "api_endpointler.txt"),
    "api_schema":    ("07_api_sema_hedefleri.json", "api_schema_targets.json"),
    "nuclei":        ("08_nuclei_zafiyet.jsonl",    "nuclei.jsonl"),
    "findings":      ("09_triyaj_bulgulari.json",   "triage_findings.json"),
    "oob":           ("10_oob_problari.json",       "oob_probes.json"),
    "katana":        ("katana_hedefleri.txt",       "katana_targets.txt"),
}

# Klasörde göz gezdirirken her dosyanın ne olduğunu anlatan kısa açıklama (00_OZET için).
DESCRIPTIONS: Dict[str, str] = {
    "subdomains":    "bulunan subdomain'ler",
    "resolved":      "DNS çözümlenen host'lar",
    "livehosts":     "canlı web servisleri (URL)",
    "httpx":         "httpx çıktısı — host detayları (tech/status/title)",
    "urls":          "toplanan tüm URL'ler (katana+gau+ffuf)",
    "api_endpoints": "path-tabanlı API endpoint'leri (--active hedefi)",
    "api_schema":    "Swagger/OpenAPI şema keşfi",
    "nuclei":        "nuclei zafiyet bulguları",
    "findings":      "AKTİF test bulguları (--active ile oluşur)",
    "oob":           "OOB/SSRF probları (--oob ile oluşur)",
}


def out_path(session_dir: str, key: str) -> str:
    """Yazma yolu — her zaman YENİ açıklayıcı ad."""
    return os.path.join(session_dir, _NAMES[key][0])


def read_path(session_dir: str, key: str) -> str:
    """Okuma yolu — yeni ad varsa o; yoksa eski/legacy ad (geriye-uyumlu); o da yoksa
    yeni ad (var-olmayan dosya için tutarlı yol)."""
    new, legacy = _NAMES[key]
    p_new = os.path.join(session_dir, new)
    if os.path.exists(p_new):
        return p_new
    p_legacy = os.path.join(session_dir, legacy)
    if os.path.exists(p_legacy):
        return p_legacy
    return p_new


def new_name(key: str) -> str:
    """Bir anahtarın yeni (açıklayıcı) dosya adı — 00_OZET listelemesi için."""
    return _NAMES[key][0]


def ffuf_name(safe_host: str) -> str:
    """ffuf içerik-keşfi sonucu (host başına) — açıklayıcı ad."""
    return f"icerik_kesfi_{safe_host}.json"
