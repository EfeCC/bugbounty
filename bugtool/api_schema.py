"""Swagger/OpenAPI şema keşfi ve ayrıştırma — API'nin TAM endpoint haritasını çıkarır.

Bug bounty'de swagger.json/openapi.yaml gibi API şema dosyaları bulunursa, bunlar
genelde dokümante edilmemiş/linklenmemiş onlarca endpoint'i tek seferde ifşa eder.
Bu modül önce bilinen konumlarda + keşfedilen URL'ler arasında şema dosyasını arar,
sonra Swagger 2.0 VE OpenAPI 3.x formatlarını (path/method/parametre/body şeması)
ayrıştırıp fuzzer'ın anlayacağı hedef listesine çevirir — body parametreleri dahil
(bkz. fuzzer.py'deki POST/JSON gövdesi fuzzing desteği).

`$ref` (Swagger `#/definitions/X`, OpenAPI `#/components/schemas/X`) bir seviye
çözülür — çoğu gerçek dünya şeması property'leri doğrudan değil `$ref` ile
tanımladığı için bu olmadan body parametrelerinin çoğu kaçırılırdı.

Tamamen pasif/düşük-riskli: şema dosyasını bir tarayıcının indireceği gibi indirir,
hiçbir API endpoint'ine istek ATMAZ — sadece haritayı çıkarır. --active gerektirmez
(çıkardığı hedefler ayrı bir adımda --active fuzzer'a beslenir, o taraf zaten
scope-gated/opt-in).
"""
import json
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from .payloads import hints_for_param

_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 bugtool")

# En yaygın konumlar — bilinçli olarak kısa tutuldu (host başına istek sayısını
# sınırlamak için); daha geniş bir liste isteyen config'ten ekleyebilir.
_COMMON_PATHS = [
    "/swagger.json", "/v2/api-docs", "/v3/api-docs", "/openapi.json",
    "/api-docs", "/swagger/v1/swagger.json",
]
_SCHEMA_URL_RE = re.compile(r"(?i)(swagger|openapi|api-docs)[^/]*\.(?:json|ya?ml)(?:\?|$)")
_METHODS = ("get", "post", "put", "patch", "delete")


def _looks_like_schema(doc: Any) -> bool:
    return isinstance(doc, dict) and "paths" in doc and ("swagger" in doc or "openapi" in doc)


def _resolve_ref(root: Dict[str, Any], ref: str) -> Dict[str, Any]:
    """`#/a/b/c` formatlı bir JSON pointer'ı (Swagger/OpenAPI `$ref`) çözer."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    node: Any = root
    for part in ref[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            return {}
        node = node[part]
    return node if isinstance(node, dict) else {}


def _schema_props(root: Dict[str, Any], node: Dict[str, Any], depth: int = 0) -> List[str]:
    """Bir schema objesinden property adlarını çıkarır; `$ref`'i (en fazla 3 seviye,
    döngüsel referanslara karşı) çözer."""
    if depth > 3 or not isinstance(node, dict):
        return []
    if "$ref" in node:
        return _schema_props(root, _resolve_ref(root, node["$ref"]), depth + 1)
    props = node.get("properties")
    if isinstance(props, dict):
        return list(props.keys())
    # allOf: birden fazla alt-şemanın birleşimi — hepsinin property'lerini topla
    if isinstance(node.get("allOf"), list):
        out: List[str] = []
        for sub in node["allOf"]:
            out.extend(_schema_props(root, sub, depth + 1))
        return out
    return []


def _extract_targets(schema: Dict[str, Any], base_url: str) -> List[Dict[str, Any]]:
    """Ayrıştırılmış bir Swagger/OpenAPI dokümanından fuzzer hedef listesi üretir."""
    targets: List[Dict[str, Any]] = []
    paths = schema.get("paths")
    if not isinstance(paths, dict):
        return targets
    base_path = str(schema.get("basePath", "") or "") if "swagger" in schema else ""

    for path_template, item in paths.items():
        if not isinstance(item, dict) or not isinstance(path_template, str):
            continue
        # path parametrelerini yer tutucuyla doldur: /users/{id} -> /users/1
        concrete_path = re.sub(r"\{[^}/]+\}", "1", path_template)
        full_url = base_url.rstrip("/") + base_path + concrete_path
        shared_params = item.get("parameters") if isinstance(item.get("parameters"), list) else []

        for method in _METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            query_params: Dict[str, List[str]] = {}
            body_params: Dict[str, List[str]] = {}

            op_params = op.get("parameters") if isinstance(op.get("parameters"), list) else []
            for p in list(shared_params) + list(op_params):
                if not isinstance(p, dict):
                    continue
                loc, name = p.get("in"), p.get("name")
                if not name:
                    continue
                if loc == "query":
                    query_params[name] = hints_for_param(name)
                elif loc == "body":  # Swagger 2.0
                    for prop in _schema_props(schema, p.get("schema") or {}):
                        body_params[prop] = hints_for_param(prop)

            # OpenAPI 3.x: requestBody.content['application/json'].schema
            req_body = op.get("requestBody")
            if isinstance(req_body, dict):
                content = req_body.get("content") or {}
                json_content = content.get("application/json") or {}
                for prop in _schema_props(schema, json_content.get("schema") or {}):
                    body_params[prop] = hints_for_param(prop)

            if not query_params and not body_params:
                continue
            target: Dict[str, Any] = {"url": full_url, "method": method.upper(),
                                      "params": query_params}
            if body_params and method in ("post", "put", "patch"):
                target["body_params"] = body_params
                target["body_template"] = {k: "1" for k in body_params}
            targets.append(target)
    return targets


def _fetch_one(url: str, timeout: int):
    """Tek aday şema URL'ini indirir — paralel çağrılır. 200 ise [(url, metin)], değilse
    []. Session worker-başına (thread-safe). Kendi exception'ını yutar."""
    import requests
    try:
        resp = requests.Session().get(url, timeout=timeout, verify=False,
                                      headers={"User-Agent": _DEFAULT_UA})
        if resp.status_code != 200:
            return []
        return [(url, resp.text or "")]
    except Exception:
        return []


def discover(live_hosts: List[str], urls: List[str], max_hosts: int = 15, timeout: int = 8,
            concurrency: int = 20,
            scope_checker: Optional[Callable[[str], bool]] = None) -> List[Dict[str, Any]]:
    """Bilinen konumlarda + keşfedilen URL'ler arasında swagger/openapi şema dosyası
    arar; bulursa indirip ayrıştırır, fuzzer hedef listesi (query+body parametreli)
    döner. İNDİRME paralel, ayrıştırma sıralı (fingerprint dedup deterministik). `requests`
    kurulu değilse boş liste döner (graceful-degrade)."""
    targets: List[Dict[str, Any]] = []
    try:
        import requests  # noqa: F401
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            pass
    except ImportError:
        return targets

    candidates: List[str] = []
    seen_hosts_for_common = set()
    for u in urls or []:
        if _SCHEMA_URL_RE.search(u) and u not in candidates:
            candidates.append(u)
    for host in (live_hosts or [])[:max_hosts]:
        h = urlparse(host).hostname or ""
        if not h or h in seen_hosts_for_common:
            continue
        seen_hosts_for_common.add(h)
        base = host.rstrip("/")
        for p in _COMMON_PATHS:
            candidates.append(base + p)

    # scope-gate (kapsam-dışı aday indirilmez)
    scoped = []
    for url in candidates:
        host = urlparse(url).hostname or ""
        if scope_checker:
            try:
                if not scope_checker(host):
                    continue
            except Exception:
                continue
        scoped.append(url)

    # İndirme paralel; ayrıştırma+dedup sonra sıralı
    from .probe import parallel_collect
    fetched = parallel_collect(lambda u: _fetch_one(u, timeout), scoped, concurrency)
    seen_docs = set()  # aynı şemayı birden fazla konumda bulursak tekrar parse etme
    for url, text in fetched:
        try:
            doc = json.loads(text)
        except ValueError:
            try:
                import yaml
                doc = yaml.safe_load(text)
            except Exception:
                continue
        if not _looks_like_schema(doc):
            continue
        fingerprint = str(doc.get("info", {}).get("title", "")) + str(len(doc.get("paths", {})))
        if fingerprint in seen_docs:
            continue
        seen_docs.add(fingerprint)
        host = urlparse(url).hostname or ""
        base_url = f"{urlparse(url).scheme}://{host}"
        targets.extend(_extract_targets(doc, base_url))
    return targets
