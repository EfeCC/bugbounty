"""WAF-bypass payload mutator — DELTA-engine'in mutator-katalog fikrinden uyarlandı.

Kanonik bir payload'ı, ANLAMINI KORUYAN sistematik dönüşümlerle çeşitlendirir (encoding /
inline yorum / whitespace / case). Amaç: imza-tabanlı bir WAF kanonik formu yakalıyorsa,
sunucunun yine de aynı şekilde çözümlediği bir varyantla filtreyi atlatmak.

KRİTİK — "pozitif kontrol" disiplini (DELTA I8): bir WAF-bypass'ı ancak
  (a) KANONİK payload WAF tarafından ENGELLENDİ  VE
  (b) MUTASYON GEÇTİ (bloklanmadı) + aynı detektör ateşledi
ise raporla. Yoksa "bypass buldum" demek yanlış-pozitiftir — belki ortada WAF bile yoktu.
Bu kapı `fuzzer.py`'de uygulanır; burası sadece dönüşümleri + WAF-cevabı sınıflandırmayı sağlar.

Saf string işleme, ağ YOK, deterministik.
"""

import re
from typing import List, Tuple
from urllib.parse import quote

# ── WAF blok sinyalleri (cevabı "engellendi" diye sınıflandırma) ─────────────
_WAF_STATUS = {403, 406, 429, 501, 503}
_WAF_BODY_RE = re.compile(
    r"(attention required|cloudflare|access denied|web application firewall|"
    r"mod_?security|not acceptable|request (?:blocked|rejected|denied)|blocked by|"
    r"incident id|akamai|imperva|incapsula|sucuri|\bwaf\b|malicious|"
    r"suspicious activity|has been blocked)", re.I)


def is_waf_blocked(status: int, body: str) -> bool:
    """Cevap bir WAF/filtre bloğu gibi mi görünüyor? (status VEYA gövde imzası)."""
    if status in _WAF_STATUS:
        return True
    return bool(_WAF_BODY_RE.search(body or ""))


# ── Dönüşümler (hepsi anlamı korur: sunucu decode edince aynı etki) ──────────
def _url_encode(p: str) -> str:
    return quote(p, safe="")


def _double_url_encode(p: str) -> str:
    return quote(quote(p, safe=""), safe="")


def _inline_comment(p: str) -> str:
    """SQL bağlamı: boşlukları `/**/` ile değiştir (sunucu aynı sorguyu görür,
    boşluk-tabanlı imzalar şaşar). Boşluk yoksa değişmez."""
    return p.replace(" ", "/**/")


def _whitespace_tab(p: str) -> str:
    """Boşlukları tab (%09) ile değiştir — bazı WAF'lar sadece 0x20'yi sayar."""
    return p.replace(" ", "\t")


def _case_toggle(p: str) -> str:
    """Harfleri dönüşümlü büyük/küçük yap (SQL/HTML anahtar kelimeleri büyük-küçük
    duyarsız; imza-tabanlı eşleşme şaşar). NOT: büyük-küçük DUYARLI bağlamlarda
    (LFI dosya yolu gibi) kullanılmamalı — çağıran sınıf bazında karar verir."""
    out = []
    upper = True
    for ch in p:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    return "".join(out)


# Sıra = deneme önceliği (ucuz/yüksek-getirili önce). (isim, fn)
_TRANSFORMS = [
    ("double_url_encode", _double_url_encode),
    ("inline_comment", _inline_comment),
    ("case_toggle", _case_toggle),
    ("whitespace_tab", _whitespace_tab),
    ("url_encode", _url_encode),
]


def mutations(payload: str) -> List[Tuple[str, str]]:
    """Payload'ın (isim, mutasyon) varyantlarını döner. No-op'lar (payload'ı
    değiştirmeyenler) ve tekrarlar elenir → boşa istek harcanmaz."""
    out: List[Tuple[str, str]] = []
    seen = {payload}
    for name, fn in _TRANSFORMS:
        try:
            variant = fn(payload)
        except Exception:
            continue
        if variant and variant not in seen:
            seen.add(variant)
            out.append((name, variant))
    return out
