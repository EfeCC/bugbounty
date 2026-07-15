"""JS/config dosyalarında sızmış secret (API key, token, private key vb.) tarama.

Bug bounty'de en yüksek getirili bulgu kaynaklarından biri: geliştiriciler sık sık
API anahtarlarını/token'ları JS bundle'larına sabit kodlar (frontend'den bir 3.
taraf servisi çağırmak için, ya da yanlışlıkla build sürecinde sızar). Bu dosyalar
zaten herkese açık servis ediliyor — bir tarayıcı sekmesi açmak kadar zararsız bir
okuma, saldırı payload'ı içermiyor.

YÖNTEM:
  1. Recon'da toplanan URL'lerden .js/.mjs olanları seç.
  2. Aşikâr 3. taraf/CDN dosyalarını (jquery, google-analytics vb.) ele — bunlarda
     hedefin kendi secret'ı olmaz, boşa istek harcamamak için.
  3. Kalanları (cap'li, dedup'lı) indir, ~25 servisin imzalı formatlarıyla + genel
     "anahtar_kelime: değer" kalıbıyla eşleştir.
  4. Placeholder/örnek değerleri (YOUR_API_KEY, xxxx, AKIA...EXAMPLE vb.) ele.

GÜVENLİK: bulunan değerler çıktıda TAM olarak gösterilmez — yalnızca ilk 4 + son 4
karakter (gitleaks/trufflehog gibi araçların standart pratiği). Bu hem raporlama
sırasında secret'ın kazara başka bir yere kopyalanmasını önler hem de "kanıt yeterli
mi" değerlendirmesi için hâlâ işe yarar.

Tamamen pasif/düşük-riskli: sadece GET, hiçbir payload yok — bir tarayıcının zaten
yapacağı indirmeyi tekrarlıyor. --active gerektirmez.

ÖNEMLİ: gerçek bir secret bulursan onu KULLANARAK başka bir servise/API'ye istek
ATMA (giriş yapma, veri çekme vb.) — bu artık sızıntıyı kanıtlamaktan çıkıp ayrı,
yetkisiz bir erişim denemesi olur. Sadece sızıntının varlığını (maskelenmiş kanıtla)
bildir.
"""
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 bugtool")

# (isim, regex, severity, gösterilecek grup-index'i [0=tüm eşleşme])
# Kaynak: gitleaks/trufflehog'un da kullandığı, servislerin kendi doküman edilmiş
# önek formatları — yüksek özgüllük, düşük yanlış-pozitif riski.
PATTERNS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "high", 0),
    ("AWS Secret Access Key (bağlamsal)",
     re.compile(r"(?i)aws[a-z_]*(?:secret|access)[a-z_]*\s*[:=]\s*['\"]([0-9a-zA-Z/+]{40})['\"]"),
     "high", 1),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "high", 0),
    ("Google OAuth Client ID",
     re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), "medium", 0),
    ("Firebase Cloud Messaging Key",
     re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"), "high", 0),
    ("GitHub Token (classic)", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "high", 0),
    ("GitHub Token (fine-grained)", re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "high", 0),
    ("GitLab Personal Access Token", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), "high", 0),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,72}"), "high", 0),
    ("Slack Webhook URL",
     re.compile(r"hooks\.slack\.com/services/T[0-9A-Z]{6,}/B[0-9A-Z]{6,}/[0-9a-zA-Z]{20,}"), "high", 0),
    ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{20,}"), "high", 0),
    ("Stripe Live Restricted Key", re.compile(r"rk_live_[0-9a-zA-Z]{20,}"), "high", 0),
    ("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}"), "high", 0),
    ("SendGrid API Key", re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"), "high", 0),
    ("Mailgun API Key", re.compile(r"key-[0-9a-zA-Z]{32}"), "high", 0),
    ("NPM Access Token", re.compile(r"npm_[0-9A-Za-z]{36}"), "high", 0),
    ("Shopify Access Token", re.compile(r"shpat_[0-9a-fA-F]{32}"), "high", 0),
    ("DigitalOcean Token", re.compile(r"dop_v1_[a-f0-9]{64}"), "high", 0),
    ("Facebook Access Token", re.compile(r"EAACEdEose0cBA[0-9A-Za-z]{20,}"), "high", 0),
    ("OpenAI API Key (project)", re.compile(r"sk-proj-[A-Za-z0-9_\-]{20,}"), "high", 0),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), "high", 0),
    ("Private Key Block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "high", 0),
    ("JWT (JSON Web Token)",
     re.compile(r"eyJ[0-9A-Za-z_-]{5,}\.eyJ[0-9A-Za-z_-]{5,}\.[0-9A-Za-z_-]{10,}"), "medium", 0),
    ("Heroku API Key (bağlamsal)",
     re.compile(r"(?i)heroku[a-z_]*\s*[:=]\s*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
               r"[0-9a-f]{4}-[0-9a-f]{12})['\"]"), "medium", 1),
]

# Daha genel/bağlamsal: bilinen bir anahtar-kelime + tırnaklı değer. Servis-özel
# önek yakalayamadığında yine de bir sinyal verir, ama daha çok manuel doğrulama
# gerektirir (o yüzden ayrı, "medium" sabit önem derecesiyle işaretleniyor).
_GENERIC_RE = re.compile(
    r"(?i)(api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)"
    r"['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_/+=]{20,60})['\"]"
)

_PLACEHOLDER_PREFIX_RE = re.compile(
    r"(?i)^(your[_-]?|xxx|test[_-]?|demo|placeholder|changeme|insert[_-]?|<|\{\{|"
    r"1234567|abcdef|dummy|fake[_-]?|sample|foo|bar|null|undefined|none)")
_PLACEHOLDER_CONTAINS_RE = re.compile(r"(?i)(example|placeholder|yourkey|xxxxxxxx)")

_JS_EXT_RE = re.compile(r"\.(?:js|mjs)(?:\?|$)", re.I)
_BORING_JS_RE = re.compile(
    r"(?i)(jquery|bootstrap|google-analytics|googletagmanager|[/.]gtag|"
    r"cloudflareinsights|hotjar|segment\.(?:com|io)|fbevents|"
    r"stripe\.com/v3|recaptcha|polyfill|fontawesome|/gtm\.js|"
    r"cdn\.jsdelivr|cdnjs\.cloudflare|unpkg\.com)")


def _is_placeholder(value: str) -> bool:
    if _PLACEHOLDER_PREFIX_RE.match(value):
        return True
    if _PLACEHOLDER_CONTAINS_RE.search(value):
        return True
    # çok düşük karakter çeşitliliği (örn. "aaaaaaaaaaaaaaaa", "0000000000") = placeholder
    if len(value) >= 8 and len(set(value.lower())) <= 3:
        return True
    return False


def _mask(value: str) -> str:
    """Sadece ilk 4 + son 4 karakteri göster (gitleaks/trufflehog standart pratiği) —
    tam secret hiçbir zaman çıktıya/dosyaya yazılmaz."""
    if len(value) <= 10:
        return value[:2] + "…" * 3
    return f"{value[:4]}…{value[-4:]}"


def _select_js_urls(urls: List[str], max_files: int) -> List[str]:
    out: List[str] = []
    seen = set()
    for u in urls:
        path = urlparse(u).path
        if not _JS_EXT_RE.search(path):
            continue
        if _BORING_JS_RE.search(u):
            continue
        basename = path.rsplit("/", 1)[-1]
        key = (urlparse(u).hostname or "", basename)
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out[:max_files]


def _finding(url: str, name: str, masked_value: str, severity: str) -> Dict[str, Any]:
    return {
        "title": f"Secret Sızıntısı: {name} ({urlparse(url).hostname})",
        "severity": severity,
        "description": f"{url} içinde {name} kalıbına uyan bir değer bulundu.",
        "evidence": f"Eşleşen değer (maskelenmiş): {masked_value}",
        "reproduction": url,
        "cvss": {"high": 8.2, "medium": 5.5}.get(severity, 5.0),
        "class": "secret_leak",
        "status": "unverified",
        "note": "POTANSİYEL — gerçek bir secret mı yoksa placeholder/örnek mi elle "
                "doğrula. Gerçekse bu secret'ı KULLANARAK başka bir servise istek "
                "ATMA (bu ayrı, yetkisiz bir erişim denemesi olur) — sadece "
                "sızıntının varlığını bildir, secret'ı ASLA rapor dışında paylaşma.",
    }


def _fetch_one(url: str, timeout: int, max_bytes: int):
    """Tek JS dosyasını indirir — paralel çağrılır. Başarılıysa [(url, içerik)], değilse
    []. Session worker-başına (thread-safe). Kendi exception'ını yutar."""
    import requests
    try:
        resp = requests.Session().get(url, timeout=timeout, verify=False,
                                      headers={"User-Agent": _DEFAULT_UA})
        return [(url, (resp.text or "")[:max_bytes])]
    except Exception:
        return []


def _scan_content(url: str, content: str, seen_secrets: set, findings: List[Dict[str, Any]]):
    """İndirilen içeriği secret kalıplarına karşı tarar (sıralı — `seen_secrets` dedup'ı
    deterministik kalsın diye ağdan sonra tek thread'de yapılır)."""
    for name, pattern, severity, group_idx in PATTERNS:
        for m in pattern.finditer(content):
            value = m.group(group_idx) if group_idx else m.group(0)
            if _is_placeholder(value):
                continue
            masked = _mask(value)
            key = (name, masked)
            if key in seen_secrets:
                continue
            seen_secrets.add(key)
            findings.append(_finding(url, name, masked, severity))
    for m in _GENERIC_RE.finditer(content):
        keyword, value = m.group(1), m.group(2)
        if _is_placeholder(value):
            continue
        masked = _mask(value)
        key = ("generic:" + keyword.lower(), masked)
        if key in seen_secrets:
            continue
        seen_secrets.add(key)
        findings.append(_finding(url, f"Olası {keyword} (bağlamsal, servis-özel değil)",
                                 masked, "medium"))


def scan(urls: List[str], max_files: int = 40, timeout: int = 8, max_bytes: int = 2_000_000,
         concurrency: int = 20,
         scope_checker: Optional[Callable[[str], bool]] = None) -> List[Dict[str, Any]]:
    """`urls` içindeki JS dosyalarını (cap'li, dedup'lı, 3.taraf/CDN hariç) indirip
    bilinen secret kalıplarıyla tarar. İNDİRME paralel, tarama+dedup sıralı. `requests`
    kurulu değilse ya da hiç JS dosyası yoksa boş liste döner (graceful-degrade)."""
    js_urls = _select_js_urls(urls, max_files)
    if not js_urls:
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

    # scope-gate (kapsam-dışı URL indirilmez)
    scoped = []
    for url in js_urls:
        host = urlparse(url).hostname or ""
        if scope_checker:
            try:
                if not scope_checker(host):
                    continue
            except Exception:
                continue
        scoped.append(url)

    # İndirme paralel; tarama+dedup sonra sıralı
    from .probe import parallel_collect
    fetched = parallel_collect(lambda u: _fetch_one(u, timeout, max_bytes), scoped, concurrency)
    findings: List[Dict[str, Any]] = []
    seen_secrets: set = set()
    for url, content in fetched:
        _scan_content(url, content, seen_secrets, findings)
    return findings
