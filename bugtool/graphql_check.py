"""GraphQL introspection kontrolü — açık introspection tüm API şemasını (tipler, sorgular,
MUTASYONLAR, alan adları) ifşa eder. Bug bounty'de sık ve yüksek-değerli: production'da
introspection açık kalması yaygın bir misconfig'tir ve gizli mutation/alan yüzeyini açar.

YÖNTEM: yaygın GraphQL yollarına (+ keşfedilen graphql URL'lerine) TEK bir introspection
sorgusu (`{__schema{queryType{name}}}`) POST eder. Cevapta `__schema`/`queryType` dönerse
introspection AÇIK demektir → bulgu. Sorgu SALT-OKUMA (introspection), hiçbir mutation
çalıştırmaz — non-destructive.

git_check/cors_check ile aynı desen: scope-gated, paralel, `requests` yoksa graceful-degrade.
NOT: GET-query fuzzer bunu göremez (path-tabanlı + POST-body), o yüzden ayrı native modül.
"""
import json
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 bugtool")

# Yaygın GraphQL uç noktaları (host başına denenir) — bilinçli kısa (istek sayısı sınırlı).
_COMMON_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphiql"]

# Keşfedilen URL'ler arasında graphql endpoint imzası.
_GQL_URL_RE = re.compile(r"/(?:graphql|graphiql|gql)(?:/|$|\?)", re.I)

# Minimal introspection sorgusu — açıksa `__schema.queryType.name` döner.
_INTROSPECTION = {"query": "query{__schema{queryType{name}}}"}


def _looks_introspectable(status: int, body: str) -> bool:
    if status != 200 or not body:
        return False
    if '"__schema"' not in body or '"queryType"' not in body:
        return False
    # JSON olarak data.__schema gerçekten var mı (sağlam teyit; string tesadüfünü eler).
    try:
        doc = json.loads(body)
    except ValueError:
        return False
    data = doc.get("data") if isinstance(doc, dict) else None
    return isinstance(data, dict) and isinstance(data.get("__schema"), dict)


def _finding(url: str) -> Dict[str, Any]:
    return {
        "title": f"GraphQL Introspection Açık: {urlparse(url).hostname}",
        "severity": "medium",
        "description": f"{url} introspection sorgusuna tam şema (tipler/sorgular/mutasyonlar) "
                       f"döndürüyor — gizli alan ve mutation yüzeyi ifşa oluyor.",
        "evidence": f"{url} → introspection cevabında data.__schema.queryType mevcut",
        "reproduction": (f"curl -s {url} -H 'Content-Type: application/json' "
                         f"--data '{json.dumps(_INTROSPECTION)}'"),
        "cvss": 5.3,
        "class": "graphql_introspection",
        "status": "unverified",
        "note": "POTANSİYEL — tam introspection sorgusuyla şemayı çıkar, gizli mutation'ları "
                "(hesap/rol/ödeme) incele. Sadece introspection oku; mutation ÇALIŞTIRMA.",
    }


def _check_one(url: str, timeout: int) -> List[Dict[str, Any]]:
    """Tek URL'e introspection POST'u — paralel çağrılır. Session worker-başına (thread-safe).
    Kendi exception'ını yutar."""
    import requests
    try:
        resp = requests.Session().post(
            url, json=_INTROSPECTION, timeout=timeout, verify=False,
            headers={"User-Agent": _DEFAULT_UA, "Content-Type": "application/json"},
            allow_redirects=False)
    except Exception:
        return []
    if _looks_introspectable(resp.status_code, resp.text or ""):
        return [_finding(url)]
    return []


def check(live_hosts: List[str], urls: Optional[List[str]] = None, max_hosts: int = 120,
          timeout: int = 8, concurrency: int = 20,
          scope_checker: Optional[Callable[[str], bool]] = None,
          on_finding: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[Dict[str, Any]]:
    """Yaygın GraphQL yollarında (+ keşfedilen graphql URL'lerinde) introspection dener.
    Aday URL'ler PARALEL kontrol edilir. `on_finding` verilirse her bulgu BULUNDUĞU AN
    çağrılır (canlı çıktı). `requests` yoksa boş liste döner (graceful-degrade)."""
    if not live_hosts and not urls:
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

    candidates: List[str] = []
    seen = set()
    # 1) Keşfedilen graphql URL'leri (path'i graphql/gql olan) — en yüksek isabet.
    for u in (urls or []):
        base = (u or "").split("#", 1)[0].split("?", 1)[0].rstrip("/")
        if base and _GQL_URL_RE.search(urlparse(base).path or "") and base not in seen:
            seen.add(base)
            candidates.append(base)
    # 2) Önceliklendirilmiş host'ların yaygın yolları (host bazında, cap'li).
    host_count = 0
    seen_hosts = set()
    for host_url in (live_hosts or []):
        h = urlparse(host_url).hostname or ""
        if not h or h in seen_hosts:
            continue
        seen_hosts.add(h)
        if max_hosts > 0 and host_count >= max_hosts:
            break
        host_count += 1
        base = host_url.rstrip("/")
        for p in _COMMON_PATHS:
            cand = base + p
            if cand not in seen:
                seen.add(cand)
                candidates.append(cand)

    # scope-gate
    scoped: List[str] = []
    for url in candidates:
        host = urlparse(url).hostname or ""
        if not host:
            continue
        if scope_checker:
            try:
                if not scope_checker(host):
                    continue
            except Exception:
                continue
        scoped.append(url)

    from .probe import parallel_collect
    return parallel_collect(lambda u: _check_one(u, timeout), scoped, concurrency,
                            on_result=on_finding)
