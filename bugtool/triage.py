"""Pasif triyaj — recon artifact'lerini (urls.txt, httpx.jsonl) okuyup ilginç şeyleri
işaretler. AĞ YOK, tamamen deterministik. Amaç: yüzlerce URL/host içinden manuel/aktif
teste değecek %1'i öne çıkarmak (ve fuzzer'a hedef parametre listesi üretmek).

İşaretledikleri:
  - Tehlikeli parametreli URL'ler (id/redirect/file/q…) → hangi vuln sınıfına aday
  - İfşa olmuş hassas dosya/path (.git/.env/.bak/.sql/backup/swagger/actuator…)
  - İlginç teknoloji (WordPress/Jira/Jenkins/Tomcat… + versiyon string'i — sadece
    sunucu/altyapı tarafı; istemci kütüphaneleri hariç, aşağıya bak)
"""

import json
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .payloads import hints_for_param

# ── İfşa/hassas dosya & path imzaları ────────────────────────────────────────
# GENİŞLETİLDİ (önceki incelemede önerildi): web.config/appsettings.json (IIS/.NET),
# id_dsa/id_ecdsa/id_ed25519 + .ssh/, .npmrc/.pypirc, .git-credentials, terraform.tfstate.
_SENSITIVE_FILE_RE = re.compile(
    r"(?:/\.git(?:/|$)|/\.svn/|/\.hg/|/\.env|/\.DS_Store|/\.htaccess|/\.htpasswd|"
    r"wp-config\.php|config\.php|configuration\.php|settings\.py|web\.config|"
    r"appsettings(?:\.\w+)?\.json|"
    r"\.(?:bak|old|swp|save|orig|tmp|sql|db|sqlite|zip|tar|tar\.gz|tgz|rar|7z|log|pem|key|p12|pfx)(?:$|\?)|"
    r"/(?:backup|backups|dump|dumps|db_backup|database)\b|"
    r"id_rsa|id_dsa|id_ecdsa|id_ed25519|\.ssh/(?:authorized_keys|known_hosts)|"
    r"\.aws/credentials|\.npmrc|\.pypirc|\.git-credentials|terraform\.tfstate)", re.I)

_INTERESTING_PATH_RE = re.compile(
    r"/(?:admin|administrator|wp-admin|api(?:/v?\d+)?|graphql|graphiql|swagger|swagger-ui|"
    r"openapi|api-docs|actuator|debug|console|phpinfo|server-status|server-info|"
    r"jenkins|gitlab|phpmyadmin|adminer|\.well-known|upload|uploads|internal|"
    r"metrics|health|jmx-console|struts|cgi-bin)(?:/|$|\?)", re.I)

# İlginç/versiyonlu teknoloji sinyalleri (httpx tech alanı)
_TECH_FLAGS = ["wordpress", "joomla", "drupal", "jira", "confluence", "jenkins", "gitlab",
               "tomcat", "struts", "spring", "phpmyadmin", "adminer", "grafana", "kibana",
               "elasticsearch", "weblogic", "jboss", "coldfusion", "citrix", "fortinet"]
_VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")

# DÜZELTME (önceki incelemede bulundu): "versiyon ifşası" kontrolü eskiden httpx'in
# tech-detect ile bulduğu HER versiyonlu teknolojide tetikleniyordu (jQuery 3.6.0,
# Bootstrap 5.1.3, Google Fonts…). Bunlar neredeyse HER sitede bulunur ve CVE avcılığı
# için düşük değerlidir — triyajın "yüzlerce host içinden %1'i öne çıkar" amacını
# sulandırıyordu. Bu istemci-taraflı kütüphaneleri versiyon-ifşası kontrolünden hariç
# tutuyoruz; asıl değerli olan sunucu/altyapı yazılımının (nginx/php/tomcat/vb.) versiyonu.
_BORING_CLIENT_TECH = {
    "jquery", "jquery ui", "bootstrap", "popper.js", "popper", "font awesome",
    "fontawesome", "google font api", "google fonts", "modernizr", "moment.js",
    "lodash", "underscore.js", "react", "vue.js", "angularjs", "angular",
    "google analytics", "google tag manager", "gtag.js", "hotjar", "segment",
    "stripe.js", "recaptcha", "polyfill", "core-js", "requirejs", "htmx",
    "select2", "swiper", "slick", "animate.css", "normalize.css",
}


class Triage:
    """Pasif recon-çıktısı analizi."""

    def analyze_dir(self, session_dir: str) -> Dict[str, Any]:
        """Bir recon oturum dizinini (urls.txt + httpx.jsonl) analiz eder."""
        urls = self._read_lines(os.path.join(session_dir, "urls.txt"))
        # urls.txt boşsa livehosts'u da dene (en azından host bazlı)
        if not urls:
            urls = self._read_lines(os.path.join(session_dir, "livehosts.txt"))
        hosts = self._read_jsonl(os.path.join(session_dir, "httpx.jsonl"))
        return self.analyze(urls, hosts)

    def analyze(self, urls: List[str], httpx_hosts: Optional[List[Dict]] = None) -> Dict[str, Any]:
        param_targets = self._param_targets(urls)
        interesting = self._interesting_urls(urls)
        tech = self._tech_flags(httpx_hosts or [])
        return {
            "param_targets": param_targets,
            "interesting_urls": interesting,
            "tech": tech,
            "stats": {
                "urls": len(urls),
                "param_endpoints": len(param_targets),
                "interesting": len(interesting),
                "tech_flags": len(tech),
            },
        }

    # ── Parametreli URL'ler → vuln sınıf adayları (fuzzer hedefleri) ──────────
    def _param_targets(self, urls: List[str]) -> List[Dict[str, Any]]:
        seen_templates = set()
        out: List[Dict[str, Any]] = []
        for u in urls:
            try:
                pr = urlparse(u)
            except (ValueError, TypeError):
                continue
            if not pr.query:
                continue
            params = list(parse_qs(pr.query, keep_blank_values=True).keys())
            if not params:
                continue
            # Aynı endpoint şablonunu (host+path+param-adları) bir kez al → istek şişmesini önle
            template = (pr.hostname or "", pr.path, tuple(sorted(params)))
            if template in seen_templates:
                continue
            seen_templates.add(template)
            param_map = {p: hints_for_param(p) for p in params}
            out.append({"url": u, "params": param_map})
        return out

    # ── İfşa dosya / ilginç path ─────────────────────────────────────────────
    def _interesting_urls(self, urls: List[str]) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        seen = set()
        for u in urls:
            reason = None
            if _SENSITIVE_FILE_RE.search(u):
                reason = "İfşa/hassas dosya (config/backup/secret)"
            elif _INTERESTING_PATH_RE.search(u):
                reason = "İlginç endpoint (admin/api/graphql/actuator…)"
            if reason:
                key = urlparse(u)._replace(query="").geturl()
                if key in seen:
                    continue
                seen.add(key)
                out.append({"url": u, "reason": reason})
        return out

    # ── Teknoloji işaretleri ─────────────────────────────────────────────────
    def _tech_flags(self, hosts: List[Dict]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for h in hosts:
            techs = h.get("tech") or h.get("technologies") or []
            ws = h.get("webserver", "") or ""
            blob = " ".join(list(techs) + [ws]).lower()
            flagged = [t for t in _TECH_FLAGS if t in blob]
            # Sadece istemci-kütüphanesi OLMAYAN sinyallerde versiyon ifşasına bak.
            infra_signals = [t for t in list(techs) + [ws]
                             if t and not any(b in t.lower() for b in _BORING_CLIENT_TECH)]
            has_infra_version = bool(_VERSION_RE.search(" ".join(infra_signals)))
            if flagged or (has_infra_version and infra_signals):
                note = ("Bilinen/ilginç yazılım: " + ", ".join(flagged)) if flagged \
                       else "Versiyon ifşası (sunucu/altyapı — bilinen CVE için kontrol et)"
                out.append({
                    "url": h.get("url", ""),
                    "tech": list(techs),
                    "webserver": ws,
                    "note": note,
                })
        return out

    # ── IO ───────────────────────────────────────────────────────────────────
    @staticmethod
    def _read_lines(path: str) -> List[str]:
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return [ln.strip() for ln in f if ln.strip()]
        except OSError:
            return []

    @staticmethod
    def _read_jsonl(path: str) -> List[Dict]:
        out: List[Dict] = []
        if not os.path.exists(path):
            return out
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except (ValueError, TypeError):
                        continue
        except OSError:
            pass
        return out
