"""Canlı host önceliklendirme (ranking) — cap'li aşamalar için "en umut vaadeden" sıralama.

SORUN (kullanıcı gerçek çalıştırmada fark etti): büyük hedeflerde 190-300 canlı host olur.
ffuf/katana/apischema/git/cors gibi aşamalar maliyet nedeniyle SADECE ilk N host'a bakar
(`hosts[:max_hosts]`). Ama bu "ilk N", httpx'in döndürdüğü KEYFİ sıradır — ilginçlik yoktur.
Sonuç: en değerli host'lar (api./admin./staging., 200 dönen, ilginç tech) kaçırılıp
CDN/redirect/park sayfalarına bütçe harcanır.

ÇÖZÜM: canlı host'ları bir "ilginçlik" skoruyla sırala; cap'li aşamalar bu sıralı listenin
BAŞINI alsın. Böylece "ilk 10" hâlâ 10'dur ama artık EN DEĞERLİ 10'dur.

Tamamen deterministik, ağ YOK, saf-Python. Skor girdileri httpx çıktısından gelir
(status/title/tech/webserver) + subdomain adı sinyalleri. Eşit skorlu host'lar httpx'in
orijinal sırasını korur (kararlı/stable sıralama).
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

# Subdomain adı sinyalleri — bir label bunlardan biriyse host büyük olasılıkla ilginçtir
# (yönetim/geliştirme/iç servis/ödeme/veri katmanı). Bug bounty'de asıl getirili yüzey.
_INTERESTING_LABELS = {
    "api", "admin", "administrator", "dev", "devel", "test", "testing", "staging",
    "stage", "stg", "uat", "sandbox", "sbx", "qa", "preprod", "pre", "beta", "demo",
    "internal", "intra", "corp", "private", "priv", "git", "gitlab", "jenkins", "ci",
    "cd", "grafana", "kibana", "prometheus", "jira", "confluence", "dashboard",
    "portal", "panel", "console", "manage", "mgmt", "vpn", "backup", "backups",
    "old", "legacy", "secret", "vault", "auth", "sso", "oauth", "idp", "gateway",
    "gw", "db", "database", "phpmyadmin", "adminer", "monitor", "monitoring", "status",
    "debug", "proxy", "storage", "files", "upload", "uploads", "payment", "pay",
    "billing", "invoice", "webhook", "hook", "graphql", "rest", "service", "svc",
    "micro", "k8s", "kube", "kubernetes", "docker", "registry", "s3", "minio",
}

# Boş/gürültü sinyalleri — bir label bunlardan biriyse host büyük olasılıkla statik/CDN
# içeriktir (enjeksiyon/panel yüzeyi düşük). Skor düşürülür ki cap'li aşamalar bunlara
# bütçe harcamasın. NOT: `www` bilerek DIŞARIDA — genelde ana uygulamadır, nötr say.
_BORING_LABELS = {
    "cdn", "static", "assets", "asset", "img", "imgs", "image", "images", "media",
    "fonts", "font", "cache", "cdn1", "cdn2", "video", "videos", "download",
    "downloads", "mx", "mx1", "mx2", "smtp", "imap", "pop", "ns", "ns1", "ns2",
    "dns", "autodiscover", "autoconfig", "lyncdiscover", "sip", "email",
}

# İlginç sunucu/altyapı/uygulama teknolojileri (httpx tech/webserver alanı) — bilinen
# CVE/panel yüzeyi taşırlar. İstemci-taraflı kütüphaneler (jQuery/React…) bilerek yok.
_INTERESTING_TECH = {
    "jira", "confluence", "jenkins", "gitlab", "tomcat", "struts", "spring",
    "spring boot", "phpmyadmin", "adminer", "grafana", "kibana", "elasticsearch",
    "weblogic", "jboss", "coldfusion", "citrix", "fortinet", "wordpress", "drupal",
    "joomla", "kubernetes", "django", "laravel", "symfony", "actuator", "swagger",
    "gitea", "sonarqube", "nexus", "artifactory", "rabbitmq", "kong", "traefik",
}

_TITLE_BOOST_RE = re.compile(
    r"(log[\s\-]?in|sign[\s\-]?in|admin|dashboard|panel|console|api\b|"
    r"index of|error|exception|stack ?trace|whitelabel|debug|phpinfo|"
    r"swagger|graphql|jenkins|grafana|kibana|gitlab|jira|actuator)", re.I)

_TITLE_PENALTY_RE = re.compile(
    r"(for sale|is for sale|parked|coming soon|under construction|default page|"
    r"welcome to nginx|apache2? .*default|account suspended|domain (?:for sale|expired)|"
    r"page not found|404 not found)", re.I)


def _subdomain_labels(hostname: str) -> List[str]:
    """Registrable domain'i (son iki label — kabaca) çıkarıp subdomain label'larını döner.
    `api.example.com` → ['api'], `cdn.assets.example.com` → ['cdn','assets'],
    `example.com` → []. co.uk gibi çok-parçalı TLD'lerde kaba kalır ama sıralama için yeter."""
    h = (hostname or "").lower().strip(".")
    if not h:
        return []
    parts = h.split(".")
    return parts[:-2] if len(parts) > 2 else []


def _status_score(status: Any) -> float:
    """HTTP status'e göre puan: 2xx en yüksek (canlı içerik), 401/403 yüksek (korumalı =
    ilginç), 5xx orta (hata sızıntısı), 3xx düşük (çoğu kanonik/park yönlendirmesi)."""
    try:
        s = int(status)
    except (ValueError, TypeError):
        return 1.0
    if 200 <= s < 300:
        return 5.0
    if s in (401, 403):
        return 4.0
    if s == 405:
        return 2.0
    if 500 <= s < 600:
        return 3.0
    if 300 <= s < 400:
        return 0.0
    return 1.0


def _hostname_score(hostname: str) -> float:
    score = 0.0
    for lbl in _subdomain_labels(hostname):
        if lbl in _INTERESTING_LABELS:
            score += 4.0
        if lbl in _BORING_LABELS:
            score -= 4.0
    return score


def score_host(host: Dict[str, Any], domain: str = "") -> float:
    """Tek bir httpx host kaydını (url/status/title/tech/webserver) skorla. Yüksek = daha
    umut vaadeden (önce taranmalı). Saf/deterministik."""
    url = host.get("url", "") or ""
    hostname = urlparse(url).hostname or ""
    score = 0.0
    st = host.get("status")
    score += _status_score(st)
    score += _hostname_score(hostname)

    tech_blob = " ".join([str(t) for t in (host.get("tech") or [])]
                         + [str(host.get("webserver", "") or "")]).lower()
    if any(t in tech_blob for t in _INTERESTING_TECH):
        score += 2.0

    title = host.get("title", "") or ""
    if _TITLE_BOOST_RE.search(title):
        score += 2.0
    if _TITLE_PENALTY_RE.search(title):
        score -= 3.0
    # Boş title + yönlendirme = büyük olasılıkla park/edge host → biraz düşür.
    if not title and _status_score(st) <= 0.0:
        score -= 1.0
    # apex (ana domain) genelde asıl uygulamadır → küçük artı.
    if domain and hostname == domain:
        score += 1.0
    return score


def rank(live_hosts: List[Dict[str, Any]], domain: str = "") -> List[str]:
    """httpx host kayıtlarını (dict listesi) ilginçlik skoruyla sırala; URL listesi döner
    (en umut vaadeden önce). Eşit skorda orijinal (httpx) sıra korunur — kararlı sıralama.
    URL'ler tekilleştirilir."""
    indexed = list(enumerate(live_hosts))
    indexed.sort(key=lambda pair: (-score_host(pair[1], domain), pair[0]))
    out: List[str] = []
    seen = set()
    for _, h in indexed:
        u = h.get("url", "") or ""
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def rank_urls(urls: List[str], domain: str = "") -> List[str]:
    """Yalnızca URL string'i elde varken (httpx boş → yedek yol) sıralama: sadece hostname
    sinyalleri kullanılır (status/title/tech yok). Kararlı + tekilleştirilmiş."""
    indexed = list(enumerate(urls))

    def _sc(u: str) -> float:
        hn = urlparse(u).hostname or ""
        return _hostname_score(hn) + (1.0 if (domain and hn == domain) else 0.0)

    indexed.sort(key=lambda pair: (-_sc(pair[1]), pair[0]))
    out: List[str] = []
    seen = set()
    for _, u in indexed:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out
