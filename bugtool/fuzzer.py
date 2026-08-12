"""Aktif parametre testi — bulunan parametrelere DETECTION payload'ları basıp POTANSİYEL
zafiyet adaylarını doğrular. Bug bounty (yetkili) bağlamı için tasarlandı.

GÜVENLİK ÇERÇEVESİ (bunlar aracın DNA'sı, atlanamaz):
  - SCOPE-GATED: her istekten önce host `scope_checker`'dan geçer; kapsam-dışı = hiç istek yok.
  - OPT-IN: yalnızca açıkça çağrılınca çalışır (main.py'de `--active` bayrağı).
  - NON-DESTRUCTIVE: payload'lar kanıtlama amaçlı (SLEEP/marker/aritmetik) — yıkıcı komut yok.
  - RATE-LIMITED + CAP: `delay` (istekler arası) + `max_requests` (toplam) ile blast-radius sınırlı.
  - ZAMAN-TABANLI DOĞRULAMA: SLEEP/CMDi pozitifleri ikinci istekle teyit edilir (FP azaltma).
  - Sonuçlar "POTANSİYEL, doğrulanmadı" etiketli — insan doğrulaması şart.

requests kurulu değilse araç kendini devre dışı bırakır (graceful-degrade), asla çökmez.

Bu turda düzeltilenler:
  - Timeout artık `None` dönüp sinyali silmiyor (zaman-tabanlı bulgular kaybolmuyordu).
  - `requests.Session()` yeniden kullanılıyor (TCP/TLS handshake tekrarı yok, daha hızlı
    ve hedefe daha az yük).
  - `verify_tls=False` iken urllib3'ün InsecureRequestWarning'i susturuluyor.
  - `test_all_if_no_hint` varsayılanı False oldu — ipucu bulunamayan parametrelerde
    artık TÜM sınıflar değil sadece xss/sqli/open_redirect denenir (bütçe daha akıllı
    harcanır); istenirse config'ten True yapılabilir.
  - İpucu OLAN hedefler artık önce test ediliyor (bütçe tükenmeden önce en olası
    hedeflere öncelik verilir).
  - SQLi baseline karşılaştırması için `baseline_body` ctx'e ekleniyor.
"""

import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qsl, quote, urlparse, urlunparse

from . import payloads as P
from . import timing
from . import mutator

# WAF-bypass yalnızca cevap-içeriği ile tespit edilen, büyük-küçük DUYARSIZ sınıflarda
# denenir (sqli anahtar kelimeleri / ssti aritmetiği). LFI dosya yolu büyük-küçük duyarlı
# olduğu için (case_toggle /etc/passwd'i bozar) dışarıda bırakılır.
_BYPASS_CLASSES = ("sqli", "ssti")

_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 bugtool")

# xss/sqli/open_redirect ucuz + yüksek değerli → ipucu olmasa da her parametrede denenir
_ALWAYS = ["xss", "sqli", "open_redirect"]

_SEVERITY = {
    "sqli": "high", "lfi": "high", "cmdi": "critical", "ssti": "critical",
    "ssrf": "high", "xss": "medium", "open_redirect": "medium", "crlf": "medium",
}


class ParamFuzzer:
    """Scope-gated aktif parametre fuzzer'ı (detection payload'ları)."""

    def __init__(self, scope_checker: Optional[Callable[[str], bool]] = None,
                 delay: float = 0.0, max_requests: int = 500, timeout: int = 10,
                 classes: Optional[List[str]] = None, headers: Optional[Dict[str, str]] = None,
                 verify_tls: bool = False, test_all_if_no_hint: bool = False,
                 block_threshold: int = 8, ladder_doses: Optional[List[float]] = None,
                 ladder_rounds: int = 2, waf_mutations_cap: int = 6):
        self.scope_checker = scope_checker
        self.delay = float(delay)
        self.max_requests = int(max_requests)
        self.timeout = int(timeout)
        self.classes = classes or P.ALL_CLASSES
        self.headers = {"User-Agent": _DEFAULT_UA, **(headers or {})}
        self.verify_tls = verify_tls
        self.test_all_if_no_hint = test_all_if_no_hint
        # Timing-ladder (doz-yanıt) — ucuz probe şüpheli olunca doz merdiveniyle doğrula
        self.ladder_doses = ladder_doses or timing.DEFAULT_DOSES
        self.ladder_rounds = int(ladder_rounds)
        self.waf_mutations_cap = int(waf_mutations_cap)   # WAF-bypass'ta denenecek max mutasyon
        # DÜZELTME (bu turda eklendi): hedef art arda 403/429 dönmeye başlarsa
        # (WAF/rate-limit tetiklendi demektir) taramayı erken durdurur — hem
        # bütçeyi boşa harcamaz hem hedefe karşı daha kibar davranır.
        self.block_threshold = int(block_threshold)
        self._consecutive_blocked = 0
        self.backoff_triggered = False
        self._sent = 0
        self._session = None
        try:
            import requests
            self._session = requests.Session()
            if not self.verify_tls:
                # verify=False her istekte InsecureRequestWarning basardı — binlerce
                # istekte konsolu boğar. TLS doğrulaması bilinçli olarak kapalı zaten,
                # uyarıyı burada bir kez susturmak yeterli.
                try:
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                except ImportError:
                    pass
            self.available = True
        except ImportError:
            self.available = False

    @classmethod
    def from_config(cls, cfg: Dict[str, Any], scope_checker=None) -> "ParamFuzzer":
        fc = (cfg or {}).get("fuzz", {}) or {}
        return cls(
            scope_checker=scope_checker,
            delay=float(fc.get("delay", 0.0)),
            max_requests=int(fc.get("max_requests", 500)),
            timeout=int(fc.get("timeout", 10)),
            classes=fc.get("classes") or None,
            verify_tls=bool(fc.get("verify_tls", False)),
            test_all_if_no_hint=bool(fc.get("test_all_if_no_hint", False)),
            block_threshold=int(fc.get("block_threshold", 8)),
            ladder_doses=fc.get("ladder_doses") or None,
            ladder_rounds=int(fc.get("ladder_rounds", 2)),
            waf_mutations_cap=int(fc.get("waf_mutations_cap", 6)),
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
    def fuzz_targets(self, param_targets: List[Dict[str, Any]],
                     on_finding: Optional[Callable[[Dict], None]] = None,
                     on_progress: Optional[Callable[[int, int, int, int], None]] = None
                     ) -> List[Dict[str, Any]]:
        """triage.param_targets listesini test eder. POTANSİYEL bulgu listesi döner.
        `on_progress(index, total, sent, nfindings)` her endpoint sonrası çağrılır (canlı sayaç).

        İpucu bulunan hedefler ÖNCE test edilir (bütçe sınırlıyken en olası hedeflere
        öncelik verir); orijinal keşif sırası ikincil anahtar olarak korunur."""
        findings: List[Dict[str, Any]] = []
        if not self.available:
            return findings
        ordered = sorted(enumerate(param_targets),
                         key=lambda item: (0 if self._has_hint(item[1]) else 1, item[0]))
        total = len(ordered)
        for i, (_orig_idx, target) in enumerate(ordered, 1):
            if self._sent >= self.max_requests:
                break
            if self._consecutive_blocked >= self.block_threshold:
                # Hedef art arda 403/429 dönüyor — muhtemelen WAF/rate-limit'e
                # çarptık. Devam etmek bütçeyi boşa harcar ve hedefe karşı kaba
                # olur; taramayı burada durduruyoruz.
                self.backoff_triggered = True
                break
            url = target.get("url", "")
            if not url or not self._in_scope(url):
                if on_progress:
                    on_progress(i, total, self._sent, len(findings))
                continue
            baseline = self._request(url)
            if baseline is None:
                if on_progress:
                    on_progress(i, total, self._sent, len(findings))
                continue
            for param, hinted in (target.get("params") or {}).items():
                classes = self._classes_for(hinted)
                for finding in self._test_param(url, param, classes, baseline):
                    findings.append(finding)
                    if on_finding:
                        on_finding(finding)
                    if self._sent >= self.max_requests:
                        return findings
            if on_progress:
                on_progress(i, total, self._sent, len(findings))
        return findings

    @staticmethod
    def _has_hint(target: Dict[str, Any]) -> bool:
        return any(hinted for hinted in (target.get("params") or {}).values())

    # ── POST/JSON body fuzzing (api_schema body_params) ───────────────────────
    def fuzz_body_targets(self, targets: List[Dict[str, Any]],
                          on_finding: Optional[Callable[[Dict], None]] = None,
                          on_progress: Optional[Callable[[int, int, int, int], None]] = None
                          ) -> List[Dict[str, Any]]:
        """api_schema hedeflerini (POST/PUT/PATCH + body_params) JSON gövdesine detection
        payload'ları basarak test eder. Query fuzzer'ıyla AYNI detektörleri/payload'ları
        kullanır ama enjeksiyonu JSON body alanına yapar. Aynı bütçeyi (`max_requests`,
        backoff) paylaşır. POTANSİYEL bulgu listesi döner."""
        findings: List[Dict[str, Any]] = []
        if not self.available:
            return findings
        ordered = sorted(enumerate(targets),
                         key=lambda item: (0 if self._has_body_hint(item[1]) else 1, item[0]))
        total = len(ordered)
        for i, (_idx, t) in enumerate(ordered, 1):
            if self._sent >= self.max_requests:
                break
            if self._consecutive_blocked >= self.block_threshold:
                self.backoff_triggered = True
                break
            url = t.get("url", "")
            method = (t.get("method") or "POST").upper()
            body_params = t.get("body_params") or {}
            template = dict(t.get("body_template") or {k: "1" for k in body_params})
            if not url or not body_params or not self._in_scope(url):
                if on_progress:
                    on_progress(i, total, self._sent, len(findings))
                continue
            baseline = self._request_body(method, url, template)
            if baseline is None:
                if on_progress:
                    on_progress(i, total, self._sent, len(findings))
                continue
            for param, hinted in body_params.items():
                classes = self._classes_for(hinted)
                for finding in self._test_body_param(url, method, param, template, classes, baseline):
                    findings.append(finding)
                    if on_finding:
                        on_finding(finding)
                    if self._sent >= self.max_requests:
                        return findings
            if on_progress:
                on_progress(i, total, self._sent, len(findings))
        return findings

    @staticmethod
    def _has_body_hint(target: Dict[str, Any]) -> bool:
        return any(hinted for hinted in (target.get("body_params") or {}).values())

    def _test_body_param(self, url: str, method: str, param: str, template: Dict[str, Any],
                         classes: List[str], baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Tek body parametresi × sınıflar — query `_test_param`'ın body karşılığı
        (detektörler/payload'lar ortak; istek JSON gövdeyle POST/PUT/PATCH)."""
        out: List[Dict[str, Any]] = []
        for cls in classes:
            spec = P.CLASSES.get(cls)
            if not spec:
                continue
            for meta in spec["payloads"]:
                if self._sent >= self.max_requests:
                    return out
                if self._consecutive_blocked >= self.block_threshold:
                    self.backoff_triggered = True
                    return out
                marker = P.make_marker()
                payload = P.render_payload(meta["p"], marker)
                resp = self._request_body(method, url, self._build_body(template, param, payload),
                                          marker=marker)
                if resp is None:
                    continue
                resp["baseline_elapsed"] = baseline["elapsed"]
                resp["baseline_body"] = baseline.get("body", "")
                evidence = spec["detect"](resp, meta)
                if not evidence:
                    continue
                verdict = "fired"
                if meta.get("t") == "time":
                    lv, slope = self._timing_ladder_body(url, method, param, meta["p"],
                                                         template, baseline)
                    if lv == timing.NOT_FIRED:
                        continue
                    verdict = "fired" if lv == timing.FIRED else "inconclusive"
                    evidence += f" · doz-yanıt eğimi={slope:.2f} ({lv})"
                f = self._finding(cls, url, param, payload, evidence, meta, verdict)
                f["method"] = method
                f["location"] = "body"
                f["reproduction"] = (f"{method} {url}  (JSON body alanı '{param}' = payload; "
                                     f"Content-Type: application/json)")
                out.append(f)
                break   # sınıf başına ilk kanıt yeter
        return out

    def _timing_ladder_body(self, url: str, method: str, param: str, template_payload: str,
                            template_body: Dict[str, Any], baseline: Dict[str, Any]) -> tuple:
        """Body enjeksiyonu için doz merdiveni (query `_timing_ladder`'ın karşılığı)."""
        measurements: Dict[float, List[float]] = {}
        for dose in self.ladder_doses:
            times: List[float] = []
            for _ in range(self.ladder_rounds):
                if self._sent >= self.max_requests:
                    return timing.NOT_FIRED, 0.0
                marker = P.make_marker()
                payload = P.render_payload(template_payload, marker, sleep=dose)
                resp = self._request_body(method, url, self._build_body(template_body, param, payload),
                                          marker=marker)
                if resp is not None:
                    times.append(resp["elapsed"])
            if times:
                measurements[dose] = times
        return timing.evaluate_ladder(list(self.ladder_doses), measurements)

    @staticmethod
    def _build_body(template: Dict[str, Any], param: str, payload: str) -> Dict[str, Any]:
        """Body şablonunu kopyalar ve hedef alanı payload ile değiştirir (diğerleri korunur)."""
        body = dict(template or {})
        body[param] = payload
        return body

    # ── OOB / OAST prob ekimi (kör zafiyetler) ────────────────────────────────
    def plant_oob(self, param_targets: List[Dict[str, Any]], oob,
                  on_progress: Optional[Callable[[int, int, int, int], None]] = None) -> int:
        """Her parametreye korele OOB payload'ları (kör SSRF/CMDi/XSS) gömer ve
        `oob.probes`'a kaydeder. Callback'ler ASENKRON — burada doğrulama YOK, sadece
        ekim; doğrulama sonra collaborator + `oob.correlate` ile. Ekilen prob sayısını döner.
        Scope-gated: kapsam-dışı host'a hiç prob gitmez."""
        if not self.available:
            return 0
        planted = 0
        templates = oob.templates()
        total = len(param_targets)
        for i, target in enumerate(param_targets, 1):
            url = target.get("url", "")
            if url and self._in_scope(url):
                for param in (target.get("params") or {}):
                    for cls, tmpls in templates.items():
                        for tmpl in tmpls[:2]:      # sınıf başına en çok 2 (bütçe)
                            if self._sent >= self.max_requests:
                                return planted
                            _token, payload = oob.plant(cls, url, param, tmpl)
                            self._request(self._build_url(url, param, payload))
                            planted += 1
            if on_progress:
                on_progress(i, total, self._sent, planted)
        return planted

    def _classes_for(self, hinted: List[str]) -> List[str]:
        wanted = set(hinted or []) | set(_ALWAYS)
        if not hinted and self.test_all_if_no_hint:
            wanted = set(self.classes)
        return [c for c in self.classes if c in wanted]

    # ── Tek parametre × sınıflar ─────────────────────────────────────────────
    def _test_param(self, url: str, param: str, classes: List[str],
                    baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for cls in classes:
            spec = P.CLASSES.get(cls)
            if not spec:
                continue
            for meta in spec["payloads"]:
                if self._sent >= self.max_requests:
                    return out
                if self._consecutive_blocked >= self.block_threshold:
                    self.backoff_triggered = True
                    return out
                marker = P.make_marker()
                payload = P.render_payload(meta["p"], marker)
                test_url = self._build_url(url, param, payload)
                resp = self._request(test_url, marker=marker)
                if resp is None:
                    continue
                resp["baseline_elapsed"] = baseline["elapsed"]
                resp["baseline_body"] = baseline.get("body", "")
                evidence = spec["detect"](resp, meta)
                if not evidence:
                    # POZİTİF KONTROL: kanonik payload WAF'a takıldıysa, mutasyonlarla
                    # atlatmayı dene (yalnızca içerik-tabanlı, case-duyarsız sınıflarda).
                    if (cls in _BYPASS_CLASSES and meta.get("t") != "time"
                            and mutator.is_waf_blocked(resp["status"], resp["body"])):
                        bypass = self._try_waf_bypass(url, param, cls, spec, meta, payload, baseline)
                        if bypass:
                            out.append(bypass)
                            break
                    continue
                verdict = "fired"
                # Zaman-tabanlı pozitifi TEK istekle değil, doz merdiveniyle (dose-response)
                # doğrula → ağ gürültüsü kaynaklı FP'yi ele, üç-durumlu verdict üret.
                if meta.get("t") == "time":
                    lv, slope = self._timing_ladder(url, param, meta["p"], baseline)
                    if lv == timing.NOT_FIRED:
                        continue
                    verdict = "fired" if lv == timing.FIRED else "inconclusive"
                    evidence += f" · doz-yanıt eğimi={slope:.2f} ({lv})"
                out.append(self._finding(cls, url, param, payload, evidence, meta, verdict))
                break   # sınıf başına ilk kanıt yeter — istek şişmesini önle
        return out

    def _timing_ladder(self, url: str, param: str, template: str,
                       baseline: Dict[str, Any]) -> tuple:
        """Doz merdivenini (sleep 0/2/4/6s × N tur) yollar, doz-yanıt verdict'i döner.
        Ucuz probe zaten 'yavaş' bulduktan SONRA çağrılır → maliyeti sadece şüpheli
        adaylarda öder. Döner: (timing verdict, eğim)."""
        measurements: Dict[float, List[float]] = {}
        for dose in self.ladder_doses:
            times: List[float] = []
            for _ in range(self.ladder_rounds):
                if self._sent >= self.max_requests:
                    return timing.NOT_FIRED, 0.0
                marker = P.make_marker()
                payload = P.render_payload(template, marker, sleep=dose)
                resp = self._request(self._build_url(url, param, payload), marker=marker)
                if resp is not None:
                    times.append(resp["elapsed"])
            if times:
                measurements[dose] = times
        return timing.evaluate_ladder(list(self.ladder_doses), measurements)

    def _try_waf_bypass(self, url, param, cls, spec, meta, canonical, baseline):
        """Kanonik payload WAF'a takıldı → mutasyonlarını dene. Bir mutasyon BLOKLANMADAN
        geçer VE aynı detektör ateşlerse → WAF-bypass + altta yatan zafiyet bulgusu.
        (Pozitif kontrol: kanonik bloğu çağıran zaten gördü, burada sadece 'geçen mutasyon'u arıyoruz.)"""
        for name, mutated in mutator.mutations(canonical)[: self.waf_mutations_cap]:
            if self._sent >= self.max_requests:
                return None
            resp = self._request(self._build_url(url, param, mutated))
            if resp is None or mutator.is_waf_blocked(resp["status"], resp["body"]):
                continue
            resp["baseline_elapsed"] = baseline["elapsed"]
            resp["baseline_body"] = baseline.get("body", "")
            evidence = spec["detect"](resp, meta)
            if evidence:
                f = self._finding(cls, url, param, mutated,
                                  f"WAF atlatıldı ({name}) → {evidence}", meta)
                f["waf_bypass"] = name
                f["note"] = ("POTANSİYEL — kanonik payload WAF'a takıldı, '" + name +
                             "' mutasyonu geçti. Manuel doğrula.")
                return f
        return None

    def _finding(self, cls, url, param, payload, evidence, meta, verdict="fired") -> Dict[str, Any]:
        conf = "high" if meta.get("t") in ("time", "error") or cls in ("lfi", "ssti") else "medium"
        if verdict == "inconclusive":
            conf = "low"
        return {
            "class": cls,
            "severity": _SEVERITY.get(cls, "medium"),
            "confidence": conf,
            "verdict": verdict,               # fired | inconclusive (üç-durumlu oracle)
            "url": url,
            "param": param,
            "payload": payload,
            "evidence": evidence,
            "reproduction": self._build_url(url, param, payload),
            "status": "unverified" if verdict == "fired" else "inconclusive",
            "note": ("POTANSİYEL — otomatik tespit, manuel doğrulama şart." if verdict == "fired"
                     else "BELİRSİZ (INCONCLUSIVE) — sinyal var ama kanıt zayıf, ÖNCELİKLE elle bak."),
        }

    # ── HTTP ──────────────────────────────────────────────────────────────────
    def _request(self, url: str, marker: str = "") -> Optional[Dict[str, Any]]:
        import requests
        if self.delay:
            time.sleep(self.delay)
        self._sent += 1
        t0 = time.time()
        try:
            resp = self._session.get(url, headers=self.headers, timeout=self.timeout,
                                     allow_redirects=False, verify=self.verify_tls)
        except requests.exceptions.Timeout:
            # Timeout, zaman-tabanlı payload'lar için GÜÇLÜ bir sinyal olabilir (istek
            # gecikmeden değil, tamamen zaman aşımına uğramaktan geliyor olabilir).
            # Eskiden burada sessizce None dönülüp sinyal tamamen kayboluyordu.
            return {"body": "", "headers": {}, "status": 0, "elapsed": float(self.timeout),
                    "baseline_elapsed": 0.0, "baseline_body": "", "marker": marker,
                    "timed_out": True}
        except Exception:
            return None
        elapsed = time.time() - t0
        # 403/429 art arda geldiğinde WAF/rate-limit'e çarpmış olabiliriz —
        # sayacı burada güncelle, çağıran taraf (fuzz_targets/_test_param)
        # eşiği aşınca taramayı erken durdurur.
        if resp.status_code in (403, 429):
            self._consecutive_blocked += 1
        else:
            self._consecutive_blocked = 0
        return {
            "body": resp.text or "",
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "status": resp.status_code,
            "elapsed": elapsed,
            "baseline_elapsed": 0.0,
            "baseline_body": "",
            "marker": marker,
        }

    def _request_body(self, method: str, url: str, body: Dict[str, Any],
                      marker: str = "") -> Optional[Dict[str, Any]]:
        """`_request`'in JSON-body karşılığı: method + JSON gövdeyle istek atar, aynı ctx
        sözlüğünü döner (detektörler için body/headers/status/elapsed/baseline_*)."""
        import requests
        if self.delay:
            time.sleep(self.delay)
        self._sent += 1
        t0 = time.time()
        try:
            resp = self._session.request(method, url, headers=self.headers, json=body,
                                         timeout=self.timeout, allow_redirects=False,
                                         verify=self.verify_tls)
        except requests.exceptions.Timeout:
            return {"body": "", "headers": {}, "status": 0, "elapsed": float(self.timeout),
                    "baseline_elapsed": 0.0, "baseline_body": "", "marker": marker,
                    "timed_out": True}
        except Exception:
            return None
        elapsed = time.time() - t0
        if resp.status_code in (403, 429):
            self._consecutive_blocked += 1
        else:
            self._consecutive_blocked = 0
        return {
            "body": resp.text or "",
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "status": resp.status_code,
            "elapsed": elapsed,
            "baseline_elapsed": 0.0,
            "baseline_body": "",
            "marker": marker,
        }

    @staticmethod
    def _build_url(base_url: str, target_param: str, payload: str) -> str:
        """Hedef parametrenin değerini payload ile değiştirir; diğerleri korunur.
        `safe='%'` → önceden encode edilmiş payload'lar (%2f, %252e) bozulmaz, ham
        özel karakterler (space/<>") URL-güvenli hale gelir (çift-encode yok)."""
        pr = urlparse(base_url)
        pairs = parse_qsl(pr.query, keep_blank_values=True)
        rebuilt = []
        replaced = False
        for k, v in pairs:
            if k == target_param:
                v = quote(payload, safe="%")
                replaced = True
            else:
                v = quote(v, safe="%")
            rebuilt.append(f"{k}={v}")
        if not replaced:  # parametre yoksa ekle
            rebuilt.append(f"{target_param}={quote(payload, safe='%')}")
        return urlunparse(pr._replace(query="&".join(rebuilt)))
