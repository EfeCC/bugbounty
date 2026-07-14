"""Zaman-tabanlı zafiyet tespiti için DOZ-YANIT (dose-response) analizi.

DELTA-engine'in "timing ladder" fikrinden uyarlandı. Sorun: tek bir `sleep(6)` yollayıp
"yavaş mı?" diye bakmak ağ gürültüsüne (jitter, GC, rate-limit) çok açık — yanlış-pozitif
üretir. Çözüm: bir DOZ MERDİVENİ yolla (`sleep 0/2/4/6s`, her doz birkaç tur) ve yanıt
süresinin doz'la **DOĞRUSAL** artıp artmadığına bak:
  - gerçek enjeksiyon → süre ≈ sabit_gecikme + doz  → eğim ≈ 1, monoton artış
  - rastgele gecikme → temiz bir doğru ÇİZEMEZ → elenir

Üç durumlu oracle (DELTA I6 — "probably" temsil edilemez):
  FIRED         : temiz doğrusal doz-yanıt (eğim ≈1, monoton, yeterli yayılım) → otomatik-kanıt
  INCONCLUSIVE  : bir eğilim var ama gürültülü → İNSANA devret ("şüpheli, elle bak")
  NOT_FIRED     : sinyal yok → düş

Saf istatistik, ağ YOK, deterministik → kolay/hızlı test edilir.
"""

from typing import Dict, List, Tuple

FIRED = "fired"
INCONCLUSIVE = "inconclusive"
NOT_FIRED = "not_fired"

# Varsayılan doz merdiveni (saniye). 0 = kontrol (payload'sız gecikme = sabit taban).
DEFAULT_DOSES: List[float] = [0.0, 2.0, 4.0, 6.0]

# Eğim (saniye-efekt / saniye-doz). Gerçek enjeksiyonda her +1s uyku ≈ +1s yanıt → eğim ~1.
_SLOPE_MIN = 0.55
_SLOPE_MAX = 1.6
_SLOPE_WEAK = 0.30           # INCONCLUSIVE için asgari pozitif eğim
# Toplam yayılım (en yüksek doz efekti − en düşük doz efekti). Doğrusal yükseldiyse
# ~max_doz kadar olmalı; gürültüyü elemek için bir taban şart.
_SPREAD_MIN = 3.0            # FIRED için (6s merdivende ~yarısı)
_SPREAD_WEAK = 1.2          # INCONCLUSIVE için


def _median(xs: List[float]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def _slope(xs: List[float], ys: List[float]) -> float:
    """En küçük kareler eğimi (ys ~ a + slope*xs)."""
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    return num / den if den else 0.0


def _monotone_nondecreasing(ys: List[float], tol: float = 0.35) -> bool:
    """Efektler (küçük bir tolerans dahilinde) azalmıyor mu?"""
    return all(ys[i] <= ys[i + 1] + tol for i in range(len(ys) - 1))


def evaluate_ladder(doses: List[float],
                    measurements: Dict[float, List[float]]) -> Tuple[str, float]:
    """Bir doz merdiveni ölçümünü üç durumlu verdict'e çevirir.

    `measurements`: {doz(sn): [ölçülen yanıt süresi(sn), ...]} — her doz için birkaç tur.
    Her doz için MEDYAN alınır (aykırı değere dayanıklı), sonra medyan-efektlerin doz'a
    karşı en küçük kareler eğimi ve monotonluğu değerlendirilir.

    Döner: (verdict, eğim).
    """
    doses = sorted(doses)
    if len(doses) < 3 or any(d not in measurements or not measurements[d] for d in doses):
        return NOT_FIRED, 0.0

    effects = [_median(measurements[d]) for d in doses]
    slope = _slope(doses, effects)
    spread = effects[-1] - effects[0]
    monotone = _monotone_nondecreasing(effects)

    if monotone and _SLOPE_MIN <= slope <= _SLOPE_MAX and spread >= _SPREAD_MIN:
        return FIRED, slope
    if slope >= _SLOPE_WEAK and spread >= _SPREAD_WEAK:
        return INCONCLUSIVE, slope
    return NOT_FIRED, slope
