"""Subdomain takeover tespiti — dangling CNAME kayıtlarının, sahiplenilmemiş üçüncü
taraf servislere (GitHub Pages, S3, Heroku, vb.) işaret edip etmediğini kontrol eder.

YÖNTEM:
  1. dnsx ile her subdomain'in CNAME'ini al.
  2. Bilinen "sahiplenilebilir" servis CNAME kalıplarından biriyle eşleşiyorsa
     (genelde küçük bir alt küme) SADECE o adaylara tek bir GET isteği at.
  3. Cevapta o servise özgü "kayıt/uygulama/bucket bulunamadı" imzası var mı bak.

Bu PASİF/DÜŞÜK-RİSKLİ bir kontrol: hiçbir kaynağı claim etmeye ÇALIŞMAZ, hiçbir
saldırı payload'ı göndermez — sadece normal bir tarayıcının yapacağı GET isteğini
atar (httpx'in zaten her host'a yaptığı probe'la aynı doğada). Bu yüzden --active
bayrağı gerektirmez, her recon'da çalışır — ama yine de scope_checker'dan geçer,
kapsam-dışı bir host'a asla istek gitmez.

Fingerprint veritabanı: EdOverflow/can-i-take-over-xyz projesinden türetilen,
küratörlü ~18 servislik bir alt küme (tam liste 100+ servis içerir ve sürekli
güncellenir — genişletmek istersen o depoya bak). Sağlayıcılar zaman zaman kendi
"bulunamadı" sayfalarını değiştirir; bir eşleşme her zaman POTANSİYEL'dir.

ÖNEMLİ (bu vuln sınıfına özgü ekstra uyarı): bir eşleşme bulduğunda kaynağı
ASLA KENDİN CLAIM ETME (GitHub Pages sitesi açma, S3 bucket'ı oluşturma, Heroku
app'i kaydetme vb.) — bu, tespiti kanıtlamaktan çıkıp gerçek bir devralmaya
dönüşür ve çoğu bug bounty programının kurallarına aykırıdır. Sadece CNAME +
HTTP imzasını kanıt olarak raporla.
"""
import re
import tempfile
import os
from typing import Any, Callable, Dict, List, Optional

from .shell import have, run

_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 bugtool")

# can-i-take-over-xyz'den türetilmiş, küratörlü alt küme.
# Genişletmek için: https://github.com/EdOverflow/can-i-take-over-xyz
FINGERPRINTS: List[Dict[str, Any]] = [
    {"service": "GitHub Pages", "cname": ["github.io"],
     "fingerprint": "There isn't a GitHub Pages site here"},
    {"service": "AWS S3", "cname": ["s3.amazonaws.com", "s3-website", "s3.dualstack"],
     "fingerprint": "The specified bucket does not exist"},
    {"service": "Heroku", "cname": ["herokuapp.com", "herokudns.com", "herokussl.com"],
     "fingerprint": "No such app"},
    {"service": "Fastly", "cname": ["fastly.net"],
     "fingerprint": "Fastly error: unknown domain"},
    {"service": "Shopify", "cname": ["myshopify.com"],
     "fingerprint": "Sorry, this shop is currently unavailable"},
    {"service": "Pantheon", "cname": ["pantheonsite.io"],
     "fingerprint": "The gods are wise"},
    {"service": "Freshdesk/Freshservice", "cname": ["freshdesk.com", "freshservice.com"],
     "fingerprint": "Maybe this is still fresh!"},
    {"service": "UserVoice", "cname": ["uservoice.com"],
     "fingerprint": "This UserVoice subdomain is currently available!"},
    {"service": "Pingdom", "cname": ["pingdom.com", "stats.pingdom.com"],
     "fingerprint": "Sorry, couldn't find the status page"},
    {"service": "Statuspage (Atlassian)", "cname": ["statuspage.io"],
     "fingerprint": "You are being redirected"},
    {"service": "Azure (Web App/Cloud Service)",
     "cname": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net"],
     "fingerprint": "404 Web Site not found"},
    {"service": "Zendesk", "cname": ["zendesk.com"],
     "fingerprint": "Help Center Closed"},
    {"service": "Unbounce", "cname": ["unbouncepages.com"],
     "fingerprint": "The requested URL was not found on this server"},
    {"service": "Netlify", "cname": ["netlify.app", "netlify.com"],
     "fingerprint": "Not Found - Request ID"},
    {"service": "Bitbucket", "cname": ["bitbucket.io"],
     "fingerprint": "Repository not found"},
    {"service": "WordPress.com", "cname": ["wordpress.com"],
     "fingerprint": "Do you want to register"},
    {"service": "Tumblr", "cname": ["tumblr.com"],
     "fingerprint": "Whatever you were looking for doesn't currently exist"},
    {"service": "Cargo Collective", "cname": ["cargocollective.com"],
     "fingerprint": "404 Not Found"},
]


def _parse_cname_output(stdout: str) -> Dict[str, str]:
    """`dnsx -cname -resp -silent` çıktısını (satır formatı: `host [cname]`)
    {host: cname} sözlüğüne çevirir."""
    out: Dict[str, str] = {}
    pattern = re.compile(r"^(\S+)\s+\[(.*?)\]\s*$")
    for line in (stdout or "").splitlines():
        m = pattern.match(line.strip())
        if not m:
            continue
        host = m.group(1).strip().lower()
        cname = m.group(2).strip().lower().rstrip(".")
        if host and cname:
            out[host] = cname
    return out


def _match_service(cname: str) -> Optional[Dict[str, Any]]:
    for entry in FINGERPRINTS:
        if any(pat in cname for pat in entry["cname"]):
            return entry
    return None


def _finding(host: str, cname: str, service: Dict[str, Any], verified: bool,
            evidence: str) -> Dict[str, Any]:
    return {
        "title": f"Subdomain Takeover: {service['service']} ({host})",
        "severity": "high" if verified else "medium",
        "description": f"{host} → CNAME {cname}, {service['service']}'e işaret ediyor.",
        "evidence": evidence,
        "reproduction": f"dig CNAME {host}   /   curl -i https://{host}/",
        "cvss": 8.6 if verified else 5.5,
        "class": "subdomain_takeover",
        "status": "unverified",
        "note": "POTANSİYEL — kaynağın gerçekten sahipsiz olduğunu elle doğrula. "
                "ASLA kendin claim etme/kayıt açma (bu artık gerçek bir devralma "
                "olur, çoğu programın kurallarına aykırı); sadece bulguyu bildir.",
    }


def check(subdomains: List[str], timeout: int = 600,
         scope_checker: Optional[Callable[[str], bool]] = None,
         on_finding: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[Dict[str, Any]]:
    """`subdomains` listesindeki her host için CNAME'e bakar, bilinen bir
    "sahiplenilebilir" servise işaret edenleri tek bir GET isteğiyle doğrulamaya
    çalışır. dnsx yoksa ya da hiçbir aday bulunmazsa boş liste döner (graceful).

    NOT: `subdomains` — dnsx'in A-record çözümlemesinden GEÇMİŞ ("resolved") liste
    değil, subfinder/crt.sh'nin bulduğu TÜM isim listesi olmalı. Çünkü klasik
    dangling-CNAME durumunda subdomain'in CNAME kaydı vardır ama A-record zinciri
    çözülmeyebilir (NXDOMAIN) — sadece "resolved" listesini kullansaydık tam da bu
    en klasik takeover durumunu kaçırırdık."""
    findings: List[Dict[str, Any]] = []

    def _add(f):
        findings.append(f)
        if on_finding:
            try:
                on_finding(f)
            except Exception:
                pass

    if not subdomains or not have("dnsx"):
        return findings

    fd, subs_path = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(subdomains))
        r = run(f"dnsx -l {subs_path} -cname -resp -silent", timeout=timeout)
    finally:
        try:
            os.unlink(subs_path)
        except OSError:
            pass

    cname_map = _parse_cname_output(r.get("stdout", ""))
    candidates = []
    for host, cname in cname_map.items():
        if scope_checker:
            try:
                if not scope_checker(host):
                    continue
            except Exception:
                continue
        service = _match_service(cname)
        if service:
            candidates.append((host, cname, service))
    if not candidates:
        return findings

    try:
        import requests
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            pass
    except ImportError:
        # requests yoksa CNAME eşleşmelerini "doğrulanmamış aday" olarak yine de
        # bildir — HTTP doğrulaması yapılamadı ama CNAME kalıbı tek başına da
        # düşük-güvenli bir sinyaldir, tamamen atmaktansa düşük güvenle bildirmek
        # daha iyi (kullanıcı elle kontrol edebilir).
        for host, cname, service in candidates:
            _add(_finding(host, cname, service, verified=False,
                          evidence="CNAME eşleşti, HTTP doğrulaması yapılamadı "
                                   "('requests' kurulu değil)"))
        return findings

    session = requests.Session()
    for host, cname, service in candidates:
        body = ""
        for scheme in ("https", "http"):
            try:
                resp = session.get(f"{scheme}://{host}/", headers={"User-Agent": _DEFAULT_UA},
                                   timeout=10, allow_redirects=True, verify=False)
                body = resp.text or ""
                break
            except Exception:
                continue
        if body and service["fingerprint"].lower() in body.lower():
            _add(_finding(host, cname, service, verified=True,
                          evidence=f"HTTP cevabında '{service['fingerprint']}' imzası bulundu"))
        # imza bulunamadıysa bulgu ÜRETME — CNAME eşleşmesi tek başına yeterli
        # kanıt değil (kaynak muhtemelen hâlâ aktif/sahipli), burada eleniyor.
    return findings
