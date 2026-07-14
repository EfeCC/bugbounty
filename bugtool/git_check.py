"""Git exposure doğrulama — `/.git/HEAD` gerçekten erişilebilir mi kontrol eder.

`triage.py` zaten `.git` gibi yolları URL string'inde REGEX ile "ilginç" işaretliyor
(ağ isteği yok, salt pasif). Ama bir URL'in path'inde `/.git/` geçmesi, o kaynağın
GERÇEKTEN sunucu tarafından servis edildiği anlamına gelmez. Bu modül farkı kapatıyor:
her canlı host için `/.git/HEAD`'i GERÇEKTEN indirip içeriğin gerçek bir git HEAD
dosyasına benzeyip benzemediğini doğruluyor.

Neden önemli: `/.git/` klasörü kazara (ör. deploy script'i `.git`'i de kopyalarsa)
web sunucusunda erişilebilir kalırsa, git-dumper gibi araçlarla TÜM proje geçmişi
(genelde eski secret'lar/yorumlar/silinen dosyalar dahil) indirilebilir — bu yüzden
bug bounty'de genelde yüksek/kritik sayılır ve kanıtlaması tek istekle mümkündür.

Tamamen pasif/düşük-riskli: tek bir GET isteği (bir tarayıcının zaten yapacağı kadar
zararsız), hiçbir şeyi indirmeye/klonlamaya ÇALIŞMAZ. --active gerektirmez.
"""
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 bugtool")

_HEAD_REF_RE = re.compile(r"^ref:\s*refs/", re.I)
_HEAD_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.I)


def _looks_like_git_head(body: str) -> bool:
    """Gerçek bir `.git/HEAD` dosyası ya `ref: refs/heads/<dal>` içerir ya da
    (detached HEAD durumunda) tek başına 40 karakterlik bir hex commit SHA'sıdır."""
    stripped = (body or "").strip()
    if not stripped:
        return False
    first_line = stripped.splitlines()[0].strip()
    return bool(_HEAD_REF_RE.match(first_line) or _HEAD_SHA_RE.match(first_line))


def _finding(base_url: str) -> Dict[str, Any]:
    return {
        "title": f"Git Deposu İfşası: {urlparse(base_url).hostname}",
        "severity": "high",
        "description": f"{base_url}/.git/HEAD gerçek bir git HEAD dosyası gibi görünüyor "
                       f"— .git dizini muhtemelen (kısmen ya da tamamen) erişilebilir.",
        "evidence": f"{base_url}/.git/HEAD 200 döndü ve geçerli bir git ref/SHA içeriyor",
        "reproduction": f"curl {base_url}/.git/HEAD   (tam depo için: git-dumper {base_url}/.git/ ./dump)",
        "cvss": 8.6,
        "class": "git_exposure",
        "status": "unverified",
        "note": "POTANSİYEL — .git'in gerçekten TAM klonlanabilir olduğunu (sadece HEAD "
                "değil, .git/config ve objects/ da erişilebilir mi) elle doğrula. "
                "Doğrularken bile depoyu TAMAMEN indirip yerelde saklama — bulguyu "
                "kanıtlamak için birkaç dosyanın erişilebilir olduğunu göstermek yeter.",
    }


def check(live_hosts: List[str], max_hosts: int = 60, timeout: int = 10,
         scope_checker: Optional[Callable[[str], bool]] = None) -> List[Dict[str, Any]]:
    """Her canlı host için `/.git/HEAD`'i indirir, içerik gerçekten bir git HEAD
    dosyasına benziyorsa bulgu üretir. `requests` kurulu değilse ya da hiç canlı
    host yoksa boş liste döner (graceful-degrade)."""
    findings: List[Dict[str, Any]] = []
    if not live_hosts:
        return findings
    try:
        import requests
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            pass
    except ImportError:
        return findings

    session = requests.Session()
    checked_hosts = set()
    count = 0
    for base_url in live_hosts:
        if count >= max_hosts:
            break
        host = urlparse(base_url).hostname or ""
        if not host or host in checked_hosts:
            continue
        checked_hosts.add(host)
        if scope_checker:
            try:
                if not scope_checker(host):
                    continue
            except Exception:
                continue
        count += 1
        base = base_url.rstrip("/")
        try:
            resp = session.get(f"{base}/.git/HEAD", timeout=timeout, verify=False,
                               headers={"User-Agent": _DEFAULT_UA}, allow_redirects=False)
        except Exception:
            continue
        ctype = (resp.headers.get("content-type") or "").lower()
        # content-type html içeriyorsa muhtemelen bir 200-döndüren özel hata sayfasıdır
        # (SPA yönlendirmesi vb.) — gerçek .git/HEAD asla html olmaz, ek FP koruması.
        if resp.status_code == 200 and "html" not in ctype and _looks_like_git_head(resp.text or ""):
            findings.append(_finding(base))
    return findings
