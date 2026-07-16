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

from . import artifacts
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

# ── Statik varlık uzantıları (FALSE-POSITIVE filtresi) ───────────────────────
# Bir .css/.js/font/resim dosyası enjeksiyon hedefi DEĞİLDİR: üzerindeki `?ver=`/`?v=`
# gibi cache-buster parametreleri sadece gürültü üretir (ve --active'de statik dosyaya
# boşuna xss/sqli/redirect isteği harcatır). Bu uzantılar hem parametreli-endpoint
# adaylarından hem de "ilginç path" işaretlemesinden (ör. /wp-content/uploads/x.css)
# elenir. Yol (path) üzerinde çalışır — query'deki tesadüfi ".js" ile eşleşmesin diye.
_STATIC_ASSET_RE = re.compile(
    r"\.(?:css|js|mjs|map|woff2?|ttf|otf|eot|"
    r"png|jpe?g|gif|svg|webp|ico|bmp|avif|"
    r"mp4|webm|mp3|wav|ogg|avi|mov)$", re.I)

# Cache-buster / sürüm parametreleri — hiçbir vuln sınıfına aday değil, yalnızca gürültü.
# (Statik olmayan bir endpoint üzerinde görülseler bile enjekte edilebilir değiller.)
_CACHEBUSTER_PARAMS = {"ver", "version", "v", "cache", "cachebuster", "cb",
                       "nocache", "rev", "revision", "_"}

# Path-tabanlı API endpoint imzası (query parametresi olmayan REST/JSON endpoint'leri).
# Modern SPA/API hedeflerinde asıl saldırı yüzeyi budur; query-param fuzzer'ı bunları
# göremez, o yüzden ayrı bir liste olarak çıkarılıp API-probe'a (metot/yetki + OOB) verilir.
_API_PATH_RE = re.compile(
    r"/(?:api|v\d+|graphql|graphiql|rest|internal|admin|actuator|oauth|"
    r"swagger|openapi)(?:/|$)", re.I)

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
        """Bir recon oturum dizinini analiz eder. Dosya adları `artifacts.read_path` ile
        çözülür — yeni açıklayıcı ad (05_urller.txt…) yoksa eski ada (urls.txt) düşer,
        böylece eski recon dizinleri de çalışmaya devam eder (geriye-uyumluluk)."""
        urls = self._read_lines(artifacts.read_path(session_dir, "urls"))
        # urls yoksa canlı host listesini de dene (en azından host bazlı)
        if not urls:
            urls = self._read_lines(artifacts.read_path(session_dir, "livehosts"))
        hosts = self._read_jsonl(artifacts.read_path(session_dir, "httpx"))
        api_targets = self._read_json_list(artifacts.read_path(session_dir, "api_schema"))
        return self.analyze(urls, hosts, api_targets)

    def analyze(self, urls: List[str], httpx_hosts: Optional[List[Dict]] = None,
               api_schema_targets: Optional[List[Dict]] = None) -> Dict[str, Any]:
        param_targets = self._param_targets(urls)
        interesting = self._interesting_urls(urls)
        api_endpoints = self._api_endpoints(urls)
        tech = self._tech_flags(httpx_hosts or [])
        api_schema_targets = api_schema_targets or []
        return {
            "param_targets": param_targets,
            "interesting_urls": interesting,
            "api_endpoints": api_endpoints,
            "tech": tech,
            "api_schema_targets": api_schema_targets,
            "stats": {
                "urls": len(urls),
                "param_endpoints": len(param_targets),
                "interesting": len(interesting),
                "api_endpoints": len(api_endpoints),
                "tech_flags": len(tech),
                "api_schema_endpoints": len(api_schema_targets),
            },
        }

    # ── Path-tabanlı API endpoint'leri (API-probe hedefleri) ──────────────────
    def _api_endpoints(self, urls: List[str]) -> List[Dict[str, str]]:
        """Query'siz, path-tabanlı REST/API endpoint'lerini çıkarır (metot/yetki haritası
        + OOB SSRF probu için). `_param_targets`'ten farkı: burada query parametresi
        aranmaz — endpoint'in kendisi (path) hedeftir. host+path bazında tekilleştirilir."""
        out: List[Dict[str, str]] = []
        seen = set()
        for u in urls:
            u = u.replace("&amp;", "&")
            try:
                pr = urlparse(u)
            except (ValueError, TypeError):
                continue
            path = pr.path or ""
            if _STATIC_ASSET_RE.search(path):      # statik varlık → API değil
                continue
            if not _API_PATH_RE.search(path):
                continue
            key = (pr.hostname or "", path.rstrip("/") or "/")
            if key in seen:
                continue
            seen.add(key)
            base = pr._replace(query="", fragment="").geturl()
            out.append({"url": base, "path": path})
        return out

    # ── Parametreli URL'ler → vuln sınıf adayları (fuzzer hedefleri) ──────────
    def _param_targets(self, urls: List[str]) -> List[Dict[str, Any]]:
        seen_templates = set()
        out: List[Dict[str, Any]] = []
        for u in urls:
            # `&amp;` HTML-entity artefaktı (gau/katana URL'leri HTML'den söktüğü için
            # `x=1&amp;y=2` gibi gelir) → gerçek `&`. Aksi halde parse_qs `amp;y` gibi
            # anlamsız parametre adları üretir. URL'nin kendisini normalize ediyoruz ki
            # ekranda ve (aktif testte) fuzzer'ın kurduğu istekte de tutarlı olsun.
            u = u.replace("&amp;", "&")
            try:
                pr = urlparse(u)
            except (ValueError, TypeError):
                continue
            if not pr.query:
                continue
            # Statik varlık (.css/.js/font/resim) → enjeksiyon hedefi değil, atla.
            if _STATIC_ASSET_RE.search(pr.path or ""):
                continue
            params = list(parse_qs(pr.query, keep_blank_values=True).keys())
            # Cache-buster/sürüm parametrelerini ele — hiçbir vuln sınıfına aday değiller.
            params = [p for p in params if p.lower() not in _CACHEBUSTER_PARAMS]
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
            elif _INTERESTING_PATH_RE.search(u) and not _STATIC_ASSET_RE.search(urlparse(u).path or ""):
                # "İlginç path" statik bir dosyaya işaret ediyorsa (ör. /wp-content/uploads/
                # x.css veya /api/static/chunks/y.js) bu bir endpoint değil, varlıktır — atla.
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

    @staticmethod
    def _read_json_list(path: str) -> List[Dict]:
        """Tek bir JSON dizisi içeren dosyayı okur (`api_schema_targets.json` gibi) —
        `_read_jsonl`'den farklı olarak satır-satır JSON değil, tek bir JSON array."""
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []
