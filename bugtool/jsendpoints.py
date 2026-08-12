"""JS endpoint madenciliği — JS bundle'larından gizli path/endpoint çıkarımı (linkfinder-native).

NEDEN: modern SPA/JS-ağırlıklı hedeflerde asıl saldırı yüzeyi HTML'de linklenmiş sayfalar
değil, JS bundle'ının içine gömülü API çağrılarıdır (`fetch("/api/internal/...")`, route
tabloları, `axios.post("/v2/users/{id}/...")`). subfinder/katana/gau bunları göremez.
`secrets_scan` JS'i zaten indirip secret arıyor ama içindeki ENDPOINT'leri çıkarmıyordu —
bu modül o boşluğu kapatır: çıkarılan endpoint'ler recon'un `urls` listesine eklenir →
triage + --active (fuzzer/api_probe) onları otomatik test eder.

YÖNTEM:
  1. Toplanan URL'lerden .js/.mjs olanları seç (3.taraf/CDN hariç — `secrets_scan` filtresi).
  2. İndir (cap'li, paralel), içeriği tırnaklı path / mutlak URL desenleriyle tara.
  3. Statik varlık / gürültü elensin; path'ler JS dosyasının origin'ine göre mutlaklaştırılsın.
  4. Scope-gate (kapsam-dışı host'a ait endpoint atılır) + dedup + cap.

Tamamen pasif/GET-only: sadece zaten public servis edilen JS'i indirir, hiçbir endpoint'e
istek ATMAZ (test --active fuzzer'ın işi, o scope-gated/opt-in). `requests` yoksa boş döner.
"""
import re
from typing import Callable, List, Optional
from urllib.parse import urljoin, urlparse

from .secrets_scan import _select_js_urls   # aynı JS-seçim/CDN-filtre mantığı (tek kaynak)

_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 bugtool")

# Tırnak (' " `) içinde, `/` ile başlayan path — fetch("/api/x")/url:"/v1/y" vb. yakalar.
# Karakter sınıfı bilinçli dar: boşluk/`${`/`<` içeren template-literal & regex parçalarını
# eler (FP azaltır). Protocol-relative `//host` ayrı ele alınır (dışlanır — 3.taraf CDN).
_PATH_RE = re.compile(r"""['"`](/[A-Za-z0-9_\-./]{1,150}(?:\?[A-Za-z0-9_\-./=&%]{0,150})?)['"`]""")
# Tırnak içinde mutlak http(s) URL (aynı hedefin başka host'una da işaret edebilir → scope-gate eler).
_ABS_URL_RE = re.compile(r"""['"`](https?://[A-Za-z0-9_.\-]+(?::\d+)?/[A-Za-z0-9_\-./?=&%]{0,180})['"`]""")

_STATIC_EXT_RE = re.compile(
    r"\.(?:css|js|mjs|map|woff2?|ttf|otf|eot|png|jpe?g|gif|svg|webp|ico|bmp|avif|"
    r"mp4|webm|mp3|wav|ogg|avi|mov|pdf|json|xml|txt|md)(?:$|\?)", re.I)

# Gürültü path'leri: tek segment + hiç harf yok, ya da bilinen anlamsız değerler.
_NOISE_RE = re.compile(r"^/(?:[0-9.]+|[*]+|)$")


def _is_useful_path(path: str) -> bool:
    if len(path) < 2 or path.startswith("//"):     # `//host` = protocol-relative (dış CDN)
        return False
    core = path.split("?", 1)[0]
    if _STATIC_EXT_RE.search(core):
        return False
    if _NOISE_RE.match(core):
        return False
    if not re.search(r"[A-Za-z]", core):           # en az bir harf içermeli
        return False
    return True


def _extract(content: str, origin: str, per_file_cap: int) -> List[str]:
    """Bir JS içeriğinden mutlak endpoint URL'leri çıkarır (origin: JS'in scheme://host'u)."""
    out: List[str] = []
    seen = set()
    for m in _PATH_RE.finditer(content):
        path = m.group(1)
        if not _is_useful_path(path):
            continue
        url = urljoin(origin + "/", path)
        if url not in seen:
            seen.add(url)
            out.append(url)
            if len(out) >= per_file_cap:
                return out
    for m in _ABS_URL_RE.finditer(content):
        url = m.group(1)
        p = urlparse(url).path or ""
        if not _is_useful_path(p or "/"):
            continue
        if url not in seen:
            seen.add(url)
            out.append(url)
            if len(out) >= per_file_cap:
                return out
    return out


def _fetch_one(url: str, timeout: int, max_bytes: int):
    """Tek JS dosyasını indirir — paralel çağrılır. [(url, içerik)] ya da []. Kendi
    exception'ını yutar (bir dosya patlarsa madencilik sürsün)."""
    import requests
    try:
        resp = requests.Session().get(url, timeout=timeout, verify=False,
                                      headers={"User-Agent": _DEFAULT_UA})
        return [(url, (resp.text or "")[:max_bytes])]
    except Exception:
        return []


def mine(urls: List[str], max_files: int = 40, timeout: int = 8, max_bytes: int = 2_000_000,
         concurrency: int = 20, per_file_cap: int = 300, total_cap: int = 1500,
         scope_checker: Optional[Callable[[str], bool]] = None) -> List[str]:
    """`urls` içindeki JS dosyalarını (cap'li, dedup'lı, CDN hariç) indirip endpoint çıkarır.
    Mutlak, scope-içi, tekilleştirilmiş endpoint URL listesi döner. `requests` yoksa boş döner."""
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

    # scope-gate: kapsam-dışı JS indirilmez
    scoped: List[str] = []
    for u in js_urls:
        host = urlparse(u).hostname or ""
        if scope_checker:
            try:
                if not scope_checker(host):
                    continue
            except Exception:
                continue
        scoped.append(u)

    from .probe import parallel_collect
    fetched = parallel_collect(lambda u: _fetch_one(u, timeout, max_bytes), scoped, concurrency)

    out: List[str] = []
    seen = set()
    for js_url, content in fetched:
        pr = urlparse(js_url)
        origin = f"{pr.scheme}://{pr.netloc}"
        for ep in _extract(content, origin, per_file_cap):
            if ep in seen:
                continue
            host = urlparse(ep).hostname or ""
            if not host:
                continue
            if scope_checker:
                try:
                    if not scope_checker(host):
                        continue
                except Exception:
                    continue
            seen.add(ep)
            out.append(ep)
            if len(out) >= total_cap:
                return out
    return out
