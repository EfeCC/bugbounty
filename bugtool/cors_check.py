"""CORS (Cross-Origin Resource Sharing) yanlış yapılandırma kontrolü.

Sahte bir Origin header'ı göndererek sunucunun Access-Control-Allow-Origin
cevabında bu origin'i (veya `null`'ı) YANSITIP yansıtmadığına bakar. Eğer
yansıtıyorsa VE aynı anda Access-Control-Allow-Credentials: true dönüyorsa,
herhangi bir kötü niyetli site, oturum açmış bir kullanıcının kimlik bilgileriyle
bu API'ye istek atıp cevabı okuyabilir demektir — yüksek önemde bir bulgu.

YÖNTEM (yerleşik, iyi bilinen bir teknik — PortSwigger/OWASP CORS test
metodolojisiyle doğrulandı):
  1. Rastgele/sahte bir Origin gönder → ACAO bu origin'i BİREBİR yansıtıyor mu?
  2. `Origin: null` gönder → ACAO `null` mu dönüyor? (sandboxed iframe/`data:` URL
     saldırı vektörü için kullanılabilir)
  İkisinde de: `Access-Control-Allow-Credentials: true` de EKLENMİŞSE önem YÜKSEK
  (tarayıcı credential'lı cevabı gerçekten işler); yoksa DÜŞÜK/ORTA (tarayıcı
  credential'sız cevabı script'e açar ama zaten kimliğe özel olmayan veri döner).
  `Access-Control-Allow-Origin: *` + credentials:true kombinasyonu tarayıcı
  seviyesinde zaten engellenir, o yüzden ayrıca test edilmiyor.

Tamamen pasif/düşük-riskli: host başına 1-2 GET isteği, hiçbir payload/enjeksiyon
yok — sadece bir HTTP header'ı değiştirip cevabı okumak. --active gerektirmez.
"""
import random
import string
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 bugtool")


def _random_origin() -> str:
    marker = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"https://bgtl-{marker}.example"


def _finding(base_url: str, mode: str, acao: str, creds: bool) -> Dict[str, Any]:
    severity = "high" if creds else "medium"
    impact = (" VE Access-Control-Allow-Credentials: true dönüyor — herhangi bir "
             "site, oturum açmış kullanıcı adına kimlik bilgili istek atabilir."
             if creds else " (Access-Control-Allow-Credentials yok/false — risk daha düşük, "
                          "ama yine de gereksiz bir izin genişletmesi).")
    return {
        "title": f"CORS Yanlış Yapılandırma: {urlparse(base_url).hostname} ({mode} origin)",
        "severity": severity,
        "description": f"{base_url}, gönderilen '{mode}' origin'i "
                       f"Access-Control-Allow-Origin: {acao} olarak yansıtıyor{impact}",
        "evidence": f"Access-Control-Allow-Origin: {acao}"
                   + (", Access-Control-Allow-Credentials: true" if creds else ""),
        "reproduction": f'curl -i -H "Origin: {mode if mode == "null" else "https://ATTACKER.example"}" {base_url}',
        "cvss": 8.1 if creds else 5.0,
        "class": "cors_misconfig",
        "status": "unverified",
        "note": "POTANSİYEL — özellikle credentials=false ise gerçek etkiyi (bu "
                "endpoint'in hassas/kimliğe-özel veri döndürüp döndürmediğini) elle "
                "doğrula; statik/herkese-açık bir sayfada CORS'un pratik önemi azdır.",
    }


def _check_one(base_url: str, timeout: int) -> List[Dict[str, Any]]:
    """Tek host'ta CORS kontrolü (2 istek: sahte origin + null) — paralel çağrılır.
    Session worker-başına (thread-safe). Kendi exception'ını yutar."""
    import requests
    session = requests.Session()
    base = base_url.rstrip("/")
    found: List[Dict[str, Any]] = []

    # Test 1: rastgele/sahte origin yansıtılıyor mu?
    fake_origin = _random_origin()
    try:
        resp = session.get(base, timeout=timeout, verify=False, allow_redirects=False,
                           headers={"User-Agent": _DEFAULT_UA, "Origin": fake_origin})
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == fake_origin:
            creds = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
            found.append(_finding(base, "rastgele", acao, creds))
    except Exception:
        pass

    # Test 2: null origin whitelist'te mi?
    try:
        resp2 = session.get(base, timeout=timeout, verify=False, allow_redirects=False,
                            headers={"User-Agent": _DEFAULT_UA, "Origin": "null"})
        acao2 = resp2.headers.get("Access-Control-Allow-Origin", "")
        if acao2 == "null":
            creds2 = resp2.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
            found.append(_finding(base, "null", acao2, creds2))
    except Exception:
        pass
    return found


def check(live_hosts: List[str], max_hosts: int = 60, timeout: int = 8,
         concurrency: int = 20,
         scope_checker: Optional[Callable[[str], bool]] = None) -> List[Dict[str, Any]]:
    """Her canlı host'a sahte bir Origin ile istek atar, yansıma + credentials
    kombinasyonunu kontrol eder. Host'lar PARALEL kontrol edilir. `requests` kurulu
    değilse boş liste döner (graceful-degrade)."""
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
    """Host-bazlı dedup + scope-gate + cap (kapsam-dışı host paralel katmana gitmez)."""
    out: List[str] = []
    seen = set()
    for base_url in live_hosts:
        if len(out) >= max_hosts:
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
