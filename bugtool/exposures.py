"""Native yüksek-değerli ifşa / yanlış-yapılandırma kontrolü — nuclei'siz.

NEDEN (kullanıcı isteği): nuclei binlerce şablonu HER canlı host'a denediği için 300 host'ta
saatlerce sürüp `nuclei_timeout`'a çarpıp yarım kesiliyordu. Ama nuclei'nin gerçek dünyada
EN ÇOK ürettiği bulgular aslında az sayıda, YÜKSEK-İSABETLİ, tek-GET ile kanıtlanabilen
şeylerdir: ifşa olmuş `.env`, açık Spring `actuator`, `phpinfo`, `server-status`, sızmış
VCS metadata'sı, Laravel Telescope/Symfony profiler, wp-config yedeği… Bu modül tam da
onları — CORS/takeover/git-check gibi — NATIVE (Python) kontrole çevirir: `probe.py`'nin
paralel katmanıyla 300 host'ta dakikalar değil saniyeler sürer.

YÖNTEM (git_check/cors_check ile birebir aynı desen):
  - Her canlı host için küçük, KÜRE EDİLMİŞ yüksek-sinyal yol listesini tek tek GET eder.
  - Sadece `200` + o ifşaya ÖZGÜ içerik imzası eşleşirse bulgu üretir (imzalar spesifik →
    SPA/catch-all 200 sayfaları eşleşmez).
  - Ek FP koruması: host'a önce rastgele (var olmayan) bir yol atılır (soft-404 kalibrasyonu);
    bir kontrolün cevabı bu "bulunamadı" gövdesiyle AYNIYSA elenir (her yola 200 dönen host).
  - HTML content-type gerektiren-DIŞI dosya sızıntılarında html cevap elenir (özel hata sayfası).

Tamamen pasif/düşük-riskli: sadece GET, payload YOK, hiçbir kaynağı değiştirmez —
bir tarayıcının o adrese girmesiyle aynı doğada. --active GEREKTİRMEZ, her recon'da çalışır.
Yine de scope_checker'dan geçer; kapsam-dışı host'a asla istek gitmez.
"""
import random
import re
import string
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 bugtool")

_SOFT404_SNIPPET = 2048   # soft-404 kalibrasyonunda karşılaştırılan gövde ön-eki (karakter)


# ── İçerik imzası detektörleri ───────────────────────────────────────────────
# Her biri (body, content_type, status) alır → bool. Sadece status==200 iken çağrılır.
# İmzalar bilerek SPESİFİK: SPA'nın index.html'i / jenerik 404 sayfası bunlara uymaz.

_ENV_KEY_RE = re.compile(
    r"(?im)^\s*(?:export\s+)?(DB_|DATABASE_|APP_KEY|APP_SECRET|APP_ENV|SECRET_?KEY|"
    r"AWS_|S3_|MAIL_|SMTP_|REDIS_|API_?KEY|ACCESS_?KEY|AUTH_?TOKEN|JWT_|STRIPE_|"
    r"TWILIO_|SENDGRID_|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*\s*=")


def _detect_env(body: str, ctype: str, status: int) -> bool:
    if "html" in ctype:                      # gerçek .env düz metindir, html değil
        return False
    return "=" in body and bool(_ENV_KEY_RE.search(body))


def _detect_aws(body: str, ctype: str, status: int) -> bool:
    low = body.lower()
    return "aws_access_key_id" in low or "aws_secret_access_key" in low


def _detect_sqlite(body: str, ctype: str, status: int) -> bool:
    return body[:16].startswith("SQLite format 3")


def _detect_hg(body: str, ctype: str, status: int) -> bool:
    if "html" in ctype:
        return False
    return "revlogv1" in body or ("dotencode" in body and "store" in body)


def _detect_apache_status(body: str, ctype: str, status: int) -> bool:
    return "Apache Server Status" in body


def _detect_apache_info(body: str, ctype: str, status: int) -> bool:
    return "Apache Server Information" in body


def _detect_phpinfo(body: str, ctype: str, status: int) -> bool:
    return "phpinfo()" in body or ("PHP Version" in body and "Zend" in body)


def _detect_dsstore(body: str, ctype: str, status: int) -> bool:
    return "Bud1" in body[:64]


def _detect_actuator(body: str, ctype: str, status: int) -> bool:
    if "json" not in ctype and "{" not in body[:64]:
        return False
    return '"_links"' in body and ('"health"' in body or '"self"' in body or '"env"' in body)


def _detect_actuator_env(body: str, ctype: str, status: int) -> bool:
    return '"activeProfiles"' in body or '"propertySources"' in body


def _detect_prometheus(body: str, ctype: str, status: int) -> bool:
    return "# HELP" in body and "# TYPE" in body


def _detect_telescope(body: str, ctype: str, status: int) -> bool:
    return ("Telescope" in body and "Laravel" in body) or "telescope-recorder" in body


def _detect_symfony(body: str, ctype: str, status: int) -> bool:
    return "Symfony Profiler" in body or "sf-toolbar-icon" in body


def _detect_wpconfig(body: str, ctype: str, status: int) -> bool:
    if "html" in ctype:
        return False
    return "DB_PASSWORD" in body or "DB_NAME" in body


# ── Kontrol kataloğu ─────────────────────────────────────────────────────────
# path · detect · class · severity · cvss · title · desc({url} yer tutucu)
_CHECKS: List[Dict[str, Any]] = [
    {"path": "/.env", "detect": _detect_env, "class": "env_exposure",
     "severity": "high", "cvss": 8.6, "title": "Ortam Dosyası İfşası (.env)",
     "desc": "{url}/.env uygulama ortam dosyası gibi görünüyor — DB parolası / API "
             "anahtarı / secret içerebilir."},
    {"path": "/.env.local", "detect": _detect_env, "class": "env_exposure",
     "severity": "high", "cvss": 8.6, "title": "Ortam Dosyası İfşası (.env.local)",
     "desc": "{url}/.env.local ortam dosyası gibi görünüyor — secret içerebilir."},
    {"path": "/.env.production", "detect": _detect_env, "class": "env_exposure",
     "severity": "high", "cvss": 8.6, "title": "Ortam Dosyası İfşası (.env.production)",
     "desc": "{url}/.env.production ortam dosyası gibi görünüyor — production secret içerebilir."},
    {"path": "/.aws/credentials", "detect": _detect_aws, "class": "aws_credentials_exposure",
     "severity": "critical", "cvss": 9.4, "title": "AWS Kimlik Bilgisi İfşası",
     "desc": "{url}/.aws/credentials AWS erişim anahtarı içeriyor gibi görünüyor — "
             "bulut hesabı tamamen ele geçirilebilir."},
    {"path": "/.svn/wc.db", "detect": _detect_sqlite, "class": "svn_exposure",
     "severity": "high", "cvss": 8.1, "title": "SVN Deposu İfşası (.svn/wc.db)",
     "desc": "{url}/.svn/wc.db bir SQLite veritabanı (SVN working-copy) — kaynak kod ve "
             "geçmişi çıkarılabilir."},
    {"path": "/.hg/requires", "detect": _detect_hg, "class": "hg_exposure",
     "severity": "medium", "cvss": 5.3, "title": "Mercurial Deposu İfşası (.hg)",
     "desc": "{url}/.hg/requires bir Mercurial deposu metadata dosyası — kaynak kod ifşa olabilir."},
    {"path": "/server-status", "detect": _detect_apache_status, "class": "apache_status",
     "severity": "medium", "cvss": 5.3, "title": "Apache server-status İfşası",
     "desc": "{url}/server-status açık — aktif istekler, istemci IP'leri ve iç yollar sızıyor."},
    {"path": "/server-info", "detect": _detect_apache_info, "class": "apache_info",
     "severity": "medium", "cvss": 5.3, "title": "Apache server-info İfşası",
     "desc": "{url}/server-info açık — sunucu yapılandırması ve modül detayları sızıyor."},
    {"path": "/phpinfo.php", "detect": _detect_phpinfo, "class": "phpinfo",
     "severity": "medium", "cvss": 5.3, "title": "phpinfo() İfşası",
     "desc": "{url}/phpinfo.php PHP yapılandırmasını, ortam değişkenlerini ve yolları ifşa ediyor."},
    {"path": "/info.php", "detect": _detect_phpinfo, "class": "phpinfo",
     "severity": "medium", "cvss": 5.3, "title": "phpinfo() İfşası (info.php)",
     "desc": "{url}/info.php PHP yapılandırmasını ve ortam bilgisini ifşa ediyor."},
    {"path": "/.DS_Store", "detect": _detect_dsstore, "class": "ds_store",
     "severity": "low", "cvss": 3.7, "title": "macOS .DS_Store İfşası",
     "desc": "{url}/.DS_Store dizin içeriği listesini sızdırıyor — gizli dosya/dizin adları çıkarılabilir."},
    {"path": "/actuator", "detect": _detect_actuator, "class": "spring_actuator",
     "severity": "medium", "cvss": 5.8, "title": "Spring Boot Actuator Açık",
     "desc": "{url}/actuator kimliksiz erişilebilir — /actuator/env, /heapdump gibi hassas "
             "endpoint'ler de açık olabilir."},
    {"path": "/actuator/env", "detect": _detect_actuator_env, "class": "spring_actuator_env",
     "severity": "high", "cvss": 8.2, "title": "Spring Actuator /env İfşası",
     "desc": "{url}/actuator/env tüm uygulama yapılandırmasını (parolalar/secret'lar dahil) ifşa ediyor."},
    {"path": "/metrics", "detect": _detect_prometheus, "class": "prometheus_metrics",
     "severity": "low", "cvss": 4.3, "title": "Prometheus /metrics İfşası",
     "desc": "{url}/metrics kimliksiz açık — iç metrikler, yollar ve altyapı detayları sızıyor."},
    {"path": "/telescope/requests", "detect": _detect_telescope, "class": "laravel_telescope",
     "severity": "high", "cvss": 7.5, "title": "Laravel Telescope Açık",
     "desc": "{url}/telescope debug panosu kimliksiz açık — istekler, sorgular, secret'lar izlenebilir."},
    {"path": "/_profiler/empty/search/results", "detect": _detect_symfony,
     "class": "symfony_profiler", "severity": "high", "cvss": 7.5,
     "title": "Symfony Profiler Açık",
     "desc": "{url}/_profiler debug profiler'ı production'da açık — istek/DB/secret detayları sızıyor."},
    {"path": "/wp-config.php.bak", "detect": _detect_wpconfig, "class": "wp_config_backup",
     "severity": "critical", "cvss": 9.1, "title": "WordPress wp-config Yedeği İfşası",
     "desc": "{url}/wp-config.php.bak veritabanı kimlik bilgilerini ve auth secret'larını ifşa ediyor."},
    {"path": "/wp-config.php~", "detect": _detect_wpconfig, "class": "wp_config_backup",
     "severity": "critical", "cvss": 9.1, "title": "WordPress wp-config Yedeği İfşası (~)",
     "desc": "{url}/wp-config.php~ editör yedeği DB kimlik bilgilerini ifşa ediyor."},
]


def _finding(base_url: str, chk: Dict[str, Any]) -> Dict[str, Any]:
    target = base_url + chk["path"]
    return {
        "title": f"{chk['title']}: {urlparse(base_url).hostname}",
        "severity": chk["severity"],
        "description": chk["desc"].format(url=base_url),
        "evidence": f"{target} 200 döndü ve '{chk['class']}' içerik imzasını taşıyor",
        "reproduction": f"curl -i {target}",
        "cvss": chk["cvss"],
        "class": chk["class"],
        "status": "unverified",
        "note": "POTANSİYEL (native imza eşleşmesi) — içeriği elle (tarayıcı/curl) doğrula. "
                "Kanıtlarken hassas veriyi indirip saklama; erişilebilir olduğunu göstermek yeter.",
    }


def _check_one(base_url: str, timeout: int) -> List[Dict[str, Any]]:
    """Tek host'ta kürelenmiş yol listesini prob'lar — thread havuzunda paralel çağrılır.
    Session worker-başına oluşturulur (thread-safe). Kendi exception'ını yutar."""
    import requests
    session = requests.Session()
    base = base_url.rstrip("/")

    # ── soft-404 kalibrasyonu: var olmayan bir yolun cevabını al (catch-all 200 koruması) ──
    marker = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    soft_status = None
    soft_body = ""
    try:
        rb = session.get(f"{base}/bugtool-{marker}-404", timeout=timeout, verify=False,
                         allow_redirects=False, headers={"User-Agent": _DEFAULT_UA})
        soft_status = rb.status_code
        soft_body = (rb.text or "")[:_SOFT404_SNIPPET]
    except Exception:
        pass

    found: List[Dict[str, Any]] = []
    for chk in _CHECKS:
        try:
            resp = session.get(f"{base}{chk['path']}", timeout=timeout, verify=False,
                               allow_redirects=False, headers={"User-Agent": _DEFAULT_UA})
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        body = resp.text or ""
        ctype = (resp.headers.get("content-type") or "").lower()
        # Catch-all koruması: host var olmayan yola da 200 + AYNI gövde dönüyorsa (SPA/
        # jenerik sayfa) bu bir ifşa değildir — ele.
        if soft_status == 200 and body[:_SOFT404_SNIPPET] == soft_body:
            continue
        try:
            if chk["detect"](body, ctype, resp.status_code):
                found.append(_finding(base, chk))
        except Exception:
            continue
    return found


def check(live_hosts: List[str], max_hosts: int = 150, timeout: int = 8,
          concurrency: int = 20,
          scope_checker: Optional[Callable[[str], bool]] = None) -> List[Dict[str, Any]]:
    """Her canlı host'ta yüksek-değerli ifşa/misconfig yollarını prob'lar. Host'lar PARALEL
    kontrol edilir (çok subdomain'de saniyeler içinde biter). `requests` kurulu değilse ya da
    hiç canlı host yoksa boş liste döner (graceful-degrade). `max_hosts <= 0` → cap yok (hepsi)."""
    if not live_hosts:
        return []
    try:
        import requests  # noqa: F401
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            pass
    except ImportError:
        return []

    targets = _scoped_targets(live_hosts, max_hosts, scope_checker)
    from .probe import parallel_collect
    return parallel_collect(lambda b: _check_one(b, timeout), targets, concurrency)


def _scoped_targets(live_hosts: List[str], max_hosts: int,
                    scope_checker: Optional[Callable[[str], bool]]) -> List[str]:
    """Host-bazlı dedup + scope-gate + cap (kapsam-dışı host paralel katmana gitmez).
    `max_hosts <= 0` → cap uygulanmaz (tüm host'lar)."""
    out: List[str] = []
    seen = set()
    for base_url in live_hosts:
        if max_hosts > 0 and len(out) >= max_hosts:
            break
        host = urlparse(base_url).hostname or ""
        if not host or host in seen:
            continue
        seen.add(host)
        if scope_checker:
            try:
                if not scope_checker(host):
                    continue
            except Exception:
                continue
        out.append(base_url)
    return out
