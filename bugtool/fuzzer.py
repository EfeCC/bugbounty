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
"""

import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qsl, quote, urlparse, urlunparse

from . import payloads as P

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
                 verify_tls: bool = False, test_all_if_no_hint: bool = True):
        self.scope_checker = scope_checker
        self.delay = float(delay)
        self.max_requests = int(max_requests)
        self.timeout = int(timeout)
        self.classes = classes or P.ALL_CLASSES
        self.headers = {"User-Agent": _DEFAULT_UA, **(headers or {})}
        self.verify_tls = verify_tls
        self.test_all_if_no_hint = test_all_if_no_hint
        self._sent = 0
        try:
            import requests  # noqa: F401
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
            test_all_if_no_hint=bool(fc.get("test_all_if_no_hint", True)),
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
        `on_progress(index, total, sent, nfindings)` her endpoint sonrası çağrılır (canlı sayaç)."""
        findings: List[Dict[str, Any]] = []
        if not self.available:
            return findings
        total = len(param_targets)
        for i, target in enumerate(param_targets, 1):
            if self._sent >= self.max_requests:
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
            hit = False
            for meta in spec["payloads"]:
                if self._sent >= self.max_requests:
                    return out
                marker = P.make_marker()
                payload = P.render_payload(meta["p"], marker)
                test_url = self._build_url(url, param, payload)
                resp = self._request(test_url, marker=marker)
                if resp is None:
                    continue
                resp["baseline_elapsed"] = baseline["elapsed"]
                evidence = spec["detect"](resp, meta)
                if not evidence:
                    continue
                # Zaman-tabanlı pozitifi ikinci istekle teyit et (FP azaltma)
                if meta.get("t") == "time":
                    confirm = self._request(test_url, marker=marker)
                    if confirm is None or confirm["elapsed"] < baseline["elapsed"] + P.SLEEP_THRESHOLD:
                        continue
                out.append(self._finding(cls, url, param, payload, evidence, meta))
                hit = True
                break   # sınıf başına ilk kanıt yeter — istek şişmesini önle
            if hit:
                continue
        return out

    def _finding(self, cls, url, param, payload, evidence, meta) -> Dict[str, Any]:
        conf = "high" if meta.get("t") in ("time", "error") or cls in ("lfi", "ssti") else "medium"
        return {
            "class": cls,
            "severity": _SEVERITY.get(cls, "medium"),
            "confidence": conf,
            "url": url,
            "param": param,
            "payload": payload,
            "evidence": evidence,
            "reproduction": self._build_url(url, param, payload),
            "status": "unverified",
            "note": "POTANSİYEL — otomatik tespit, manuel doğrulama şart.",
        }

    # ── HTTP ──────────────────────────────────────────────────────────────────
    def _request(self, url: str, marker: str = "") -> Optional[Dict[str, Any]]:
        import requests
        if self.delay:
            time.sleep(self.delay)
        self._sent += 1
        t0 = time.time()
        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout,
                                allow_redirects=False, verify=self.verify_tls)
        except Exception:
            return None
        elapsed = time.time() - t0
        return {
            "body": resp.text or "",
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "status": resp.status_code,
            "elapsed": elapsed,
            "baseline_elapsed": 0.0,
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
