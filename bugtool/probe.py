"""Per-host paralel prob yardımcısı — 'her canlı host'a bir istek' yapan modüllerin
(git_check / cors_check / secrets_scan / api_schema) ortak eşzamanlılık katmanı.

SORUN (kullanıcı gerçek çalıştırmada fark etti): çok sayıda canlı subdomain varken bu
kontroller host host, TEK TEK (sıralı) yapılıyordu ve her istek büyük pipeline
timeout'unu (600s) miras alıyordu → güvenlik duvarı arkasındaki/yavaş birkaç host
dakikalarca donmaya yol açıyordu.

ÇÖZÜM: kısa per-request timeout (çağıran taraf verir) + SINIRLI thread havuzuyla paralel
prob. Böylece 60 host tek tek dakikalarca değil, aynı anda ~20'şer saniyeler içinde biter.
Scope-gating değişmez — kapsam-dışı host'lar bu katmana HİÇ gönderilmez (çağıran taraf
listeyi önceden filtreler).
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, List


def parallel_collect(func: Callable[[Any], List[Any]], items: List[Any],
                     concurrency: int = 20) -> List[Any]:
    """`func`'ı `items` üzerinde paralel çalıştırır ve döndürdüğü LİSTELERİ düzleştirip
    birleştirir. Her `func(item)` çağrısı 0+ öğeli bir liste dönmeli (tek host birden çok
    bulgu üretebilir; hiç üretmezse boş liste). `func` kendi exception'ını YUTMALI — bir
    prob patlarsa diğerleri sürsün, tüm tarama çökmesin.

    `concurrency <= 1` ise sıralı çalışır (test/deterministik davranış için)."""
    items = list(items)
    if not items:
        return []
    workers = max(1, min(int(concurrency), len(items)))
    out: List[Any] = []
    if workers == 1:
        for item in items:
            out.extend(func(item) or [])
        return out
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for result in ex.map(func, items):
            out.extend(result or [])
    return out
