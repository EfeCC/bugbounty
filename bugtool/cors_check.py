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
  Bulgu YALNIZCA reflection'a EK OLARAK `Access-Control-Allow-Credentials: true` de
  dönüyorsa üretilir (severity=high). Gerekçe: credential yansıması olmadan bir
  saldırgan endpoint'i sadece credential'SIZ okuyabilir — bu da internetteki herkesin
  zaten görebildiği public cevaptır, ek etki yoktur. Bu yüzden "origin/null yansıyor
  ama ACAC yok" TEK BAŞINA RAPORLANMAZ; aksi halde `null`'ı jenerik yansıtan her CDN
  edge'i (ör. Akamai preflight) false-positive üretir. `Access-Control-Allow-Origin: *`
  + credentials:true kombinasyonu tarayıcı seviyesinde zaten engellenir, o yüzden
  ayrıca test edilmiyor.

  İSTİSNA (bilerek kapsanmıyor): erişimi ağ konumuyla (IP/intranet/VPN) kısıtlanmış bir
  kaynakta credential'sız reflection da hassas veri sızdırabilir; tarayıcı bunu otomatik
  ayırt edemediğinden burada ele alınmıyor — böyle bir hedefi elle değerlendir.

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


def _finding(base_url: str, mode: str, acao: str) -> Dict[str, Any]:
    """Yalnızca reflection + `Access-Control-Allow-Credentials: true` BİRLİKTE
    doğrulandığında üretilir (bkz. _check_one) — gerçekten sömürülebilir CORS misconfig.
    Credential yansıması olmadan reflection etkisiz sayılır ve bulgu ÜRETİLMEZ."""
    vector = ("sandboxed iframe / `data:` URL (origin=null)" if mode == "null"
              else "herhangi bir kötü niyetli origin")
    return {
        "title": f"CORS Yanlış Yapılandırma: {urlparse(base_url).hostname} "
                 f"({mode} origin + credentials)",
        "severity": "high",
        "description": f"{base_url}, gönderilen '{mode}' origin'ini "
                       f"Access-Control-Allow-Origin: {acao} olarak yansıtıyor VE "
                       f"Access-Control-Allow-Credentials: true dönüyor — {vector} üzerinden, "
                       f"oturum açmış bir kullanıcının kimlik bilgileriyle bu endpoint'e istek "
                       f"atıp cevabı okuyabilir.",
        "evidence": f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: true",
        "reproduction": f'curl -i -H "Origin: {"null" if mode == "null" else "https://ATTACKER.example"}" {base_url}',
        "cvss": 8.1,
        "class": "cors_misconfig",
        "status": "unverified",
        "note": "POTANSİYEL — bu endpoint'in gerçekten kimliğe-özel/hassas veri döndürdüğünü "
                "elle doğrula; statik/herkese-açık bir cevapta CORS'un pratik etkisi azdır.",
    }


def _check_one(base_url: str, timeout: int) -> List[Dict[str, Any]]:
    """Tek host'ta CORS kontrolü (2 istek: sahte origin + null) — paralel çağrılır.
    Session worker-başına (thread-safe). Kendi exception'ını yutar."""
    import requests
    session = requests.Session()
    base = base_url.rstrip("/")
    found: List[Dict[str, Any]] = []

    # Sömürülebilirlik için İKİSİ de şart: origin YANSIMASI + Access-Control-Allow-
    # Credentials:true. Credential yansıması yoksa saldırgan yalnızca credential'SIZ
    # (public) cevabı okuyabilir → gerçek etki yok, bulgu ÜRETME (false-positive kaynağı).

    # Test 1: rastgele/sahte origin yansıyor + credential'lı mı?
    fake_origin = _random_origin()
    try:
        resp = session.get(base, timeout=timeout, verify=False, allow_redirects=False,
                           headers={"User-Agent": _DEFAULT_UA, "Origin": fake_origin})
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        creds = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
        if acao == fake_origin and creds:
            found.append(_finding(base, "rastgele", acao))
    except Exception:
        pass

    # Test 2: null origin whitelist'te + credential'lı mı?
    try:
        resp2 = session.get(base, timeout=timeout, verify=False, allow_redirects=False,
                            headers={"User-Agent": _DEFAULT_UA, "Origin": "null"})
        acao2 = resp2.headers.get("Access-Control-Allow-Origin", "")
        creds2 = resp2.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
        if acao2 == "null" and creds2:
            found.append(_finding(base, "null", acao2))
    except Exception:
        pass
    return found


def check(live_hosts: List[str], max_hosts: int = 60, timeout: int = 8,
         concurrency: int = 20,
         scope_checker: Optional[Callable[[str], bool]] = None,
         on_finding: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[Dict[str, Any]]:
    """Her canlı host'a sahte bir Origin ile istek atar, yansıma + credentials
    kombinasyonunu kontrol eder. Host'lar PARALEL kontrol edilir. `on_finding` verilirse
    her bulgu BULUNDUĞU AN çağrılır (canlı çıktı). `requests` kurulu değilse boş döner."""
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
    return parallel_collect(lambda b: _check_one(b, timeout), targets, concurrency,
                            on_result=on_finding)


def check_urls(urls: List[str], max_urls: int = 120, timeout: int = 8,
               concurrency: int = 20,
               scope_checker: Optional[Callable[[str], bool]] = None,
               on_finding: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[Dict[str, Any]]:
    """`check`'ten farkı: host kökü değil, VERİLEN TAM URL'leri (genelde `/api/...` veri
    endpoint'leri) test eder — asıl sömürülebilir CORS bunlardadır, host kökünde değil.
    URL bazında (host+path) dedup edilir (host bazında DEĞİL), böylece aynı host'un birden
    çok endpoint'i test edilir. `max_urls <= 0` → cap yok. Scope-gate + `requests` graceful-degrade."""
    if not urls:
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

    targets: List[str] = []
    seen = set()
    for u in urls:
        if max_urls > 0 and len(targets) >= max_urls:
            break
        base = (u or "").split("#", 1)[0].rstrip("/")
        if not base or base in seen:
            continue
        seen.add(base)
        host = urlparse(base).hostname or ""
        if not host:
            continue
        if scope_checker:
            try:
                if not scope_checker(host):
                    continue
            except Exception:
                continue
        targets.append(base)

    from .probe import parallel_collect
    return parallel_collect(lambda b: _check_one(b, timeout), targets, concurrency,
                            on_result=on_finding)


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
