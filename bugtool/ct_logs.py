"""Certificate Transparency (crt.sh) — pasif subdomain kaynağı.

Sertifika şeffaflığı (CT) logları herkese açık, RFC 6962 ile zorunlu kılınmış
kayıtlardır: bir domain/subdomain için TLS sertifikası verildiğinde bu logda
görünür. subfinder'ın kaçırdığı bazı subdomain'leri (özellikle YENİ verilmiş
sertifikalar, henüz hiçbir yerde linklenmemiş) yakalayabilir — `monitor.py`'nin
"yeni asset'te ilk ol" amacına birebir hizmet eder. Bazı güvenlik ekipleri "yeni
sertifika = yeni saldırı yüzeyi" sinyalini tam olarak bu şekilde izler.

Tamamen pasif: hedefin kendi altyapısına hiçbir istek gitmez, sadece üçüncü taraf
bir kayıt (crt.sh) sorgulanır. Ağ isteği için `requests` gerekir; kurulu değilse ya
da crt.sh yanıt vermezse sessizce boş liste döner (graceful-degrade) — pipeline'ı
asla durdurmaz. crt.sh ücretsiz/topluluk kaynaklı bir servistir, bazen yavaş ya da
geçici olarak erişilemez olabilir; bu normaldir, tek seferlik sorgu olduğu için
hedefe ekstra yük bindirmez.
"""
import json
from typing import List


def requests_available() -> bool:
    """`requests` kurulu mu? DÜZELTME: eskiden crt.sh'den sonuç gelmeyince ("gerçekten
    boş sonuç" ile "'requests' hiç kurulu değil") tek, belirsiz bir mesaj basılıyordu
    ("requests kurulu değil OLABİLİR"). Çağıran taraf (webrecon.py) artık bu fonksiyonla
    gerçek sebebi ayırt edip doğru mesajı basabilir."""
    try:
        import requests  # noqa: F401
        return True
    except ImportError:
        return False


def fetch_subdomains(domain: str, timeout: int = 30) -> List[str]:
    """crt.sh'den `domain` için bilinen tüm subdomain adaylarını çeker (geçmiş/güncel
    sertifika kayıtlarından). Wildcard (*.) önekleri temizlenir, sonuç sıralı/dedup'lı
    döner. Herhangi bir hata durumunda (ağ, format, timeout) boş liste döner."""
    try:
        import requests
    except ImportError:
        return []
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=timeout,
                            headers={"User-Agent": "bugtool-ct-recon"})
        if resp.status_code != 200 or not resp.text.strip():
            return []
        try:
            certs = resp.json()
        except ValueError:
            # crt.sh bazen ardışık JSON objelerini virgülsüz/dizisiz döndürür
            # (bilinen bir tuhaflık) — "}{" -> "},{" çevirip diziye sarmayı dene.
            certs = json.loads("[{}]".format(resp.text.replace("}{", "},{")))
    except Exception:
        return []

    subs = set()
    for cert in certs or []:
        if not isinstance(cert, dict):
            continue
        name_value = cert.get("name_value") or ""
        for line in name_value.split("\n"):
            s = line.strip().lower()
            if s.startswith("*."):
                s = s[2:]
            if s and "@" not in s and " " not in s and "." in s:
                subs.add(s)
    return sorted(subs)
