"""API-probe — path-tabanlı REST/JSON endpoint'lerini aktif test eder.

NEDEN: query-param fuzzer'ı (fuzzer.py) yalnızca `?param=` olan URL'leri test eder.
Modern SPA/API hedeflerinde ise saldırı yüzeyi path-tabanlı endpoint'lerdir
(`/api/storage-providers`, `/api/otp/verify`, `/api/user-invite`…) — bunların hiçbiri
query parametresi taşımaz, bu yüzden eski akışta HİÇ test edilmiyordu. Bu modül o boşluğu
kapatır.

NE YAPAR (iki şey, ikisi de non-destructive):
  1. Metot/yetki haritası — her endpoint'e OPTIONS + GET atıp:
       - hangi HTTP metotlarının desteklendiğini (OPTIONS `Allow` başlığı) ÖĞRENİR
         (metotları GÖNDERMEDEN — yan etki yok),
       - yetkisiz (kimliksiz) GET'in ne döndürdüğünü haritalar.
     Hassas-isimli bir endpoint kimliksiz 2xx dönerse → POTANSİYEL broken-access-control.
  2. OOB/SSRF probu — URL-çeken isimli endpoint'lere (oauth/callback/test-connection/
     webhook…) collaborator token'lı probe gömer (kör SSRF). GET-query her url-çekene;
     POST-JSON yalnızca bağlantı-test edici + yıkıcı-OLMAYAN endpoint'lere.

GÜVENLİK ÇERÇEVESİ (fuzzer.py ile aynı DNA):
  - SCOPE-GATED: her istek öncesi host scope_checker'dan geçer; kapsam-dışı = istek yok.
  - NON-DESTRUCTIVE: haritalama SADECE OPTIONS+GET (okuma). `invite/send/trigger/delete/
    revert/cancel/restore…` gibi yan-etkili isimlere ASLA otomatik POST atılmaz.
  - RATE-LIMITED + CAP: `delay` + `max_requests` ile blast-radius sınırlı.
  - requests yoksa kendini devre dışı bırakır (graceful-degrade), asla çökmez.
"""

import json
import re
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse, urlencode

_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 bugtool")

# Hassas-isimli endpoint: kimliksiz 2xx dönerse yüksek sinyal (broken access control).
_SENSITIVE_RE = re.compile(
    r"(admin|internal|backup|restore|snapshot|storage|credential|secret|token|"
    r"user|invite|tenant|licen[cs]e|billing|payment|invoice|oauth|sso|config|"
    r"setting|key|password|otp|repositor|installation|integration|provider|policy)", re.I)

# URL-çeken (fetch/redirect/connect) endpoint — kör SSRF/redirect adayı.
_URL_FETCH_RE = re.compile(
    r"(oauth|callback|authorize|webhook|connect|test-connection|import|fetch|proxy|"
    r"sso|redirect|remote|integration|preview|link|url)", re.I)

# POST-JSON OOB SADECE bunlara: bağlantı-test edici, semantik olarak dışa-bağlanmak için
# VAR olan endpoint'ler — collaborator'a bağlanmaları non-destructive (hedef verisine zarar
# vermez). Genel POST fuzzing YOK.
_CONN_TESTER_RE = re.compile(
    r"(test-connection|callback|authorize|webhook|/connect|oauth)", re.I)

# ASLA otomatik POST atma — ismi yan-etki/yıkım ima eden endpoint'ler.
_DESTRUCTIVE_RE = re.compile(
    r"(invite|send|trigger|delete|remove|revert|cancel|restore|create|update|reset|"
    r"disable|enable|execute|run|pay|charge|refund|revoke|rotate|purge|drop|wipe|"
    r"deploy|provision|rollback|terminate|destroy|migrate|import|upload)", re.I)

# IDOR/BOLA sezgisi: path'in SON sayısal segmenti (/users/42 → 42). Bunu komşu ID'lerle
# değiştirip kimliksiz erişim deneriz.
_NUM_SEG_RE = re.compile(r"(?<=/)(\d{1,12})(?=/|$)")

# POST-JSON OOB body'sinde denenecek yaygın URL alan adları (hepsi aynı token'a gider).
_URL_BODY_FIELDS = ["url", "uri", "endpoint", "target", "host", "callback", "callbackUrl",
                    "callback_url", "webhook", "webhookUrl", "redirectUri", "redirect_uri",
                    "link", "remote", "server", "address"]

# GET-query OOB'de denenecek yaygın URL parametre adları.
_URL_QUERY_PARAMS = ["url", "uri", "next", "redirect", "redirect_uri", "callback",
                     "target", "dest", "u", "link"]


class ApiProbe:
    """Scope-gated, non-destructive path-tabanlı API endpoint prober'ı."""

    def __init__(self, scope_checker: Optional[Callable[[str], bool]] = None,
                 delay: float = 0.0, max_requests: int = 500, timeout: int = 10,
                 headers: Optional[Dict[str, str]] = None, verify_tls: bool = False,
                 block_threshold: int = 8, oob_post: bool = True, idor: bool = True):
        self.scope_checker = scope_checker
        self.delay = float(delay)
        self.max_requests = int(max_requests)
        self.timeout = int(timeout)
        self.headers = {"User-Agent": _DEFAULT_UA, **(headers or {})}
        self.verify_tls = verify_tls
        self.oob_post = bool(oob_post)     # POST-JSON OOB probu açık mı (bağlantı-test edici allowlist)
        self.idor = bool(idor)             # IDOR/BOLA sezgisi (komşu ID ile kimliksiz erişim) açık mı
        self.block_threshold = int(block_threshold)
        self._consecutive_blocked = 0
        self.backoff_triggered = False
        self._sent = 0
        self._session = None
        try:
            import requests
            self._session = requests.Session()
            if not self.verify_tls:
                try:
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                except ImportError:
                    pass
            self.available = True
        except ImportError:
            self.available = False

    @classmethod
    def from_config(cls, cfg: Dict[str, Any], scope_checker=None) -> "ApiProbe":
        fc = (cfg or {}).get("fuzz", {}) or {}
        return cls(
            scope_checker=scope_checker,
            delay=float(fc.get("delay", 0.0)),
            max_requests=int(fc.get("max_requests", 500)),
            timeout=int(fc.get("timeout", 10)),
            verify_tls=bool(fc.get("verify_tls", False)),
            block_threshold=int(fc.get("block_threshold", 8)),
            oob_post=bool(fc.get("api_oob_post", True)),
            idor=bool(fc.get("api_idor", True)),
        )

    def _in_scope(self, url: str) -> bool:
        host = urlparse(url).hostname or ""
        if not self.scope_checker:
            return True
        try:
            return bool(self.scope_checker(host))
        except Exception:
            return False

    # ── Ana giriş ─────────────────────────────────────────────────────────────
    def probe(self, endpoints: List[Dict[str, str]], oob=None,
              on_finding: Optional[Callable[[Dict], None]] = None,
              on_progress: Optional[Callable[[int, int, int, int], None]] = None
              ) -> Dict[str, Any]:
        """endpoints: [{"url":..., "path":...}] (triage.api_endpoints). `oob` verilirse
        (OobManager) URL-çeken endpoint'lere kör SSRF probu gömer. Döner:
        {"findings": [...], "method_map": [{url, get_status, allow, note}], "oob_planted": n}."""
        findings: List[Dict[str, Any]] = []
        method_map: List[Dict[str, Any]] = []
        oob_planted = 0
        if not self.available:
            return {"findings": findings, "method_map": method_map, "oob_planted": oob_planted}
        total = len(endpoints)
        for i, ep in enumerate(endpoints, 1):
            if self._sent >= self.max_requests:
                break
            if self._consecutive_blocked >= self.block_threshold:
                self.backoff_triggered = True
                break
            url = ep.get("url", "")
            if not url or not self._in_scope(url):
                if on_progress:
                    on_progress(i, total, self._sent, len(findings))
                continue
            row, finds = self._map_endpoint(url)
            if row:
                method_map.append(row)
            if self.idor:
                finds = finds + self._probe_idor(url)
            for f in finds:
                findings.append(f)
                if on_finding:
                    on_finding(f)
            if oob is not None:
                oob_planted += self._plant_ssrf(url, oob)
            if on_progress:
                on_progress(i, total, self._sent, len(findings))
        return {"findings": findings, "method_map": method_map, "oob_planted": oob_planted}

    # ── Metot/yetki haritası (OPTIONS + GET, non-destructive) ─────────────────
    def _map_endpoint(self, url: str) -> tuple:
        """OPTIONS ile desteklenen metotları öğren (göndermeden), GET ile yetki-durumunu
        haritala. Döner: (method_map_row | None, findings)."""
        findings: List[Dict[str, Any]] = []
        allow = ""
        opt = self._request("OPTIONS", url)
        if opt is not None:
            allow = opt["headers"].get("allow", "") or opt["headers"].get("access-control-allow-methods", "")
        get = self._request("GET", url)
        if get is None:
            return ({"url": url, "get_status": None, "allow": allow, "note": "istek başarısız"}, findings)

        status = get["status"]
        note = ""
        sensitive = bool(_SENSITIVE_RE.search(urlparse(url).path or ""))
        # Kimliksiz 2xx + hassas isim → POTANSİYEL broken access control.
        if 200 <= status < 300 and sensitive:
            note = "kimliksiz 2xx (hassas endpoint)"
            findings.append(self._finding(
                "broken_access_control", url, "GET", status,
                f"Hassas endpoint kimlik doğrulama olmadan {status} döndü — "
                f"yetkisiz veri erişimi olabilir (body {get['length']}B)",
                severity="high", confidence="low"))
        elif 200 <= status < 300:
            note = "kimliksiz 2xx"
        elif status in (401, 403):
            note = "yetki gerekli"
        elif status == 405:
            note = "GET kapalı (yazma endpoint'i olabilir)"
        elif 500 <= status < 600:
            note = f"sunucu hatası {status}"
            findings.append(self._finding(
                "server_error", url, "GET", status,
                f"Endpoint {status} döndü — beklenmeyen girdi/işleme hatası olabilir, "
                f"manuel incele", severity="low", confidence="low"))
        else:
            note = f"HTTP {status}"
        return ({"url": url, "get_status": status, "allow": allow.strip(), "note": note}, findings)

    # ── IDOR / BOLA sezgisi (komşu ID ile kimliksiz erişim) ───────────────────
    def _probe_idor(self, url: str) -> List[Dict[str, Any]]:
        """Path'in son sayısal segmentini (/users/42) komşu ID'lerle değiştirip KİMLİKSİZ
        erişim dener. Orijinal + en az bir komşu ID 200 dönüyor VE gövdeleri BİRBİRİNDEN
        farklıysa → farklı nesnelere yetkisiz erişim = POTANSİYEL IDOR/BOLA.

        FP azaltma: yalnızca hassas-isimli path'lerde çalışır (public katalog /products/1
        gibi yerlerde farklı nesne dönmesi normaldir); ve komşu cevap orijinalle AYNI
        gövdedeyse (statik/aynı) sayılmaz. Sadece GET — non-destructive."""
        path = urlparse(url).path or ""
        if not _SENSITIVE_RE.search(path):
            return []
        matches = list(_NUM_SEG_RE.finditer(path))
        if not matches:
            return []
        m = matches[-1]                       # son sayısal segment
        try:
            orig_id = int(m.group(1))
        except ValueError:
            return []
        if self._sent >= self.max_requests:
            return []
        base = self._request("GET", url)
        if base is None or not (200 <= base["status"] < 300) or base["length"] < 8:
            return []                          # kimliksiz zaten erişilemiyorsa IDOR yok
        base_body = base["body"]
        # Komşu ID'ler (negatif/again kaçın): orig-1, orig+1, yoksa orig+2
        alt_ids = [i for i in (orig_id - 1, orig_id + 1, orig_id + 2) if i >= 0 and i != orig_id]
        for alt in alt_ids[:2]:
            if self._sent >= self.max_requests:
                break
            alt_path = path[:m.start(1)] + str(alt) + path[m.end(1):]
            alt_url = urlparse(url)._replace(path=alt_path).geturl()
            r = self._request("GET", alt_url)
            if r is None or not (200 <= r["status"] < 300) or r["length"] < 8:
                continue
            # Farklı nesne mi? (aynı gövde = statik/aynı kayıt → IDOR değil)
            if r["body"] != base_body and abs(r["length"] - base["length"]) >= 0:
                return [self._finding(
                    "idor_bola", url, "GET", r["status"],
                    f"Hassas endpoint'te ID değiştirildi ({orig_id}→{alt}); ikisi de kimliksiz "
                    f"2xx VE farklı gövde döndü ({base['length']}B vs {r['length']}B) — "
                    f"yetkisiz nesne erişimi (IDOR/BOLA) olabilir",
                    severity="high", confidence="low")]
        return []

    # ── OOB / SSRF prob ekimi ─────────────────────────────────────────────────
    def _plant_ssrf(self, url: str, oob) -> int:
        """URL-çeken isimli endpoint'e kör SSRF probu göm. GET-query her url-çekene;
        POST-JSON yalnızca bağlantı-test edici + yıkıcı-OLMAYAN endpoint'e. Ekilen sayı döner."""
        path = urlparse(url).path or ""
        if not _URL_FETCH_RE.search(path):
            return 0
        planted = 0
        tmpls = oob.templates().get("blind_ssrf", [])
        if not tmpls:
            return 0
        tmpl = tmpls[0]     # "http://{H}/" — bütçe için sınıf başına 1 şablon
        # 1) GET-query probu (okuma, güvenli): yaygın URL parametre adlarına token göm.
        for pname in _URL_QUERY_PARAMS:
            if self._sent >= self.max_requests:
                return planted
            _token, payload = oob.plant("blind_ssrf", url, f"query:{pname}", tmpl)
            self._request("GET", url, params={pname: payload})
            planted += 1
        # 2) POST-JSON probu — SADECE bağlantı-test edici + yıkıcı OLMAYAN endpoint.
        if (self.oob_post and _CONN_TESTER_RE.search(path)
                and not _DESTRUCTIVE_RE.search(path)):
            if self._sent < self.max_requests:
                _token, payload = oob.plant("blind_ssrf", url, "body:url", tmpl)
                body = {f: payload for f in _URL_BODY_FIELDS}
                self._request("POST", url, json_body=body)
                planted += 1
        return planted

    def _finding(self, cls, url, method, status, evidence,
                 severity="medium", confidence="low") -> Dict[str, Any]:
        return {
            "class": cls,
            "severity": severity,
            "confidence": confidence,
            "verdict": "lead",             # ne fired ne inconclusive — MANUEL doğrulanacak ipucu
            "url": url,
            "param": method,               # burada param yerine HTTP metodu
            "payload": "",
            "evidence": evidence,
            "reproduction": f"{method} {url}",
            "status": "lead",
            "note": "POTANSİYEL İPUCU — otomatik doğrulanmadı, elle/Burp ile incele.",
        }

    # ── HTTP ──────────────────────────────────────────────────────────────────
    def _request(self, method: str, url: str, params: Optional[Dict] = None,
                 json_body: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
        import requests
        if self.delay:
            time.sleep(self.delay)
        self._sent += 1
        try:
            resp = self._session.request(
                method, url, headers=self.headers, params=params, json=json_body,
                timeout=self.timeout, allow_redirects=False, verify=self.verify_tls)
        except requests.exceptions.Timeout:
            return {"body": "", "headers": {}, "status": 0, "length": 0, "timed_out": True}
        except Exception:
            return None
        if resp.status_code in (403, 429):
            self._consecutive_blocked += 1
        else:
            self._consecutive_blocked = 0
        body = resp.text or ""
        return {
            "body": body,
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "status": resp.status_code,
            "length": len(body),
        }
