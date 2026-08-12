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

import json
import os
import re
from typing import Any, Dict, List, Tuple

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


# ── Bulgu kategori dosyaları (reports/<oturum>/bulgular/<kategori>.jsonl) ─────
# Her bulgu TİPİ ayrı bir dosyaya toplanır (secret sızıntısı, CORS, ifşa/misconfig,
# git, takeover, graphql, IDOR + aktif-test sınıfları). Hem recon (webrecon) hem
# aktif test (main._run_active_test) AYNI dizine yazar (union — üzerine ezmez).
_FINDING_CATEGORY: Dict[str, str] = {
    "secret_leak": "secret_sizintisi",
    "cors_misconfig": "cors",
    "git_exposure": "git_ifsasi",
    "subdomain_takeover": "takeover",
    "graphql_introspection": "graphql",
    "idor_bola": "idor",
    "broken_access_control": "yetki_atlatma",
    "server_error": "sunucu_hatasi",
    "confirmed_oob": "oob_kanitli",
}
# Native exposures modülünün tüm sınıfları → tek "ifsa_misconfig" kategorisi.
_EXPOSURE_CLASSES = {
    "env_exposure", "aws_credentials_exposure", "svn_exposure", "hg_exposure",
    "apache_status", "apache_info", "phpinfo", "ds_store", "spring_actuator",
    "spring_actuator_env", "prometheus_metrics", "laravel_telescope",
    "symfony_profiler", "wp_config_backup",
}


def finding_category(f: Dict[str, Any]) -> str:
    """Bir bulgunun rapor dosyası kategorisini döner. Bilinen sınıflar güzel Türkçe ada
    eşlenir; exposures sınıfları tek kategoride toplanır; nuclei title'dan tanınır;
    bilinmeyen ama `class`'ı olan bulgu KENDİ sınıf adıyla dosyalanır (xss→xss, sqli→sqli…)."""
    cls = str(f.get("class") or "").strip()
    if cls in _FINDING_CATEGORY:
        return _FINDING_CATEGORY[cls]
    if cls in _EXPOSURE_CLASSES:
        return "ifsa_misconfig"
    if str(f.get("title") or "").startswith("Nuclei:"):
        return "nuclei"
    if cls:
        return re.sub(r"[^a-z0-9_]+", "_", cls.lower()).strip("_") or "diger"
    return "diger"


def write_findings_files(session_dir: str, findings: List[Dict[str, Any]]):
    """Bulguları kategoriye göre `reports/<oturum>/bulgular/<kategori>.jsonl` dosyalarına
    yazar (+ `_TUMU.json`). Mevcut `_TUMU.json` ile BİRLEŞTİRİR (üzerine ezmez) — böylece
    recon aşaması yazdıktan sonra aktif test de aynı dizine ekleyebilir. Bulgu yoksa no-op."""
    if not findings or not session_dir:
        return
    bdir = os.path.join(session_dir, "bulgular")
    try:
        os.makedirs(bdir, exist_ok=True)
    except OSError:
        return
    tumu_path = os.path.join(bdir, "_TUMU.json")
    existing: List[Dict[str, Any]] = []
    if os.path.exists(tumu_path):
        try:
            with open(tumu_path, "r", encoding="utf-8") as fh:
                existing = (json.load(fh) or {}).get("findings", []) or []
        except (OSError, ValueError):
            existing = []
    combined = list(existing) + list(findings)
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for f in combined:
        grouped.setdefault(finding_category(f), []).append(f)
    for cat, items in grouped.items():
        try:
            with open(os.path.join(bdir, f"{cat}.jsonl"), "w", encoding="utf-8") as fh:
                for it in items:
                    fh.write(json.dumps(it, ensure_ascii=False) + "\n")
        except OSError:
            pass
    try:
        with open(tumu_path, "w", encoding="utf-8") as fh:
            json.dump({"findings": combined}, fh, indent=2, ensure_ascii=False)
    except OSError:
        pass
