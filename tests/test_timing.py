"""Doz-yanıt (timing ladder) analizi — üç durumlu oracle testleri (saf matematik, ağ yok)."""

import bugtool.timing as T


def test_clean_linear_fires():
    # Efekt ≈ 0.1 + doz → eğim 1.0, monoton, geniş yayılım → FIRED
    doses = [0.0, 2.0, 4.0, 6.0]
    meas = {d: [0.1 + d, 0.12 + d] for d in doses}
    verdict, slope = T.evaluate_ladder(doses, meas)
    assert verdict == T.FIRED
    assert 0.9 <= slope <= 1.1


def test_flat_not_fired():
    # Doz artıyor ama süre sabit (enjeksiyon yok) → NOT_FIRED
    doses = [0.0, 2.0, 4.0, 6.0]
    meas = {d: [0.1, 0.11, 0.09] for d in doses}
    verdict, _ = T.evaluate_ladder(doses, meas)
    assert verdict == T.NOT_FIRED


def test_weak_noisy_inconclusive():
    # Pozitif eğilim var ama zayıf (eğim ~0.4, band dışı) → INCONCLUSIVE
    doses = [0.0, 2.0, 4.0, 6.0]
    meas = {0.0: [0.1], 2.0: [0.9], 4.0: [1.7], 6.0: [2.5]}   # eğim ~0.4
    verdict, slope = T.evaluate_ladder(doses, meas)
    assert verdict == T.INCONCLUSIVE
    assert slope < T._SLOPE_MIN


def test_non_monotone_not_clean():
    # Süre doz'la düzgün artmıyor (yukarı-aşağı) → FIRED olmamalı
    doses = [0.0, 2.0, 4.0, 6.0]
    meas = {0.0: [0.1], 2.0: [6.0], 4.0: [0.2], 6.0: [5.5]}
    verdict, _ = T.evaluate_ladder(doses, meas)
    assert verdict != T.FIRED


def test_median_robust_to_outlier():
    # Tek bir aykırı ölçüm (jitter) medyanla elenir → hâlâ FIRED
    doses = [0.0, 2.0, 4.0, 6.0]
    meas = {0.0: [0.1, 0.1, 9.9], 2.0: [2.1, 2.1, 2.0],
            4.0: [4.1, 4.0, 4.1], 6.0: [6.1, 6.0, 6.1]}
    verdict, _ = T.evaluate_ladder(doses, meas)
    assert verdict == T.FIRED


def test_missing_dose_not_fired():
    # Bir doz ölçülememişse (istek düştü) güvenli tarafta NOT_FIRED
    doses = [0.0, 2.0, 4.0, 6.0]
    meas = {0.0: [0.1], 2.0: [2.1], 4.0: [4.1]}   # 6.0 eksik
    verdict, _ = T.evaluate_ladder(doses, meas)
    assert verdict == T.NOT_FIRED
