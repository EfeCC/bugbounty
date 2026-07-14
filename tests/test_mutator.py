"""WAF-bypass mutator — dönüşümler + WAF-cevabı sınıflandırma (saf string, ağ yok)."""

import bugtool.mutator as M


def test_is_waf_blocked_status():
    assert M.is_waf_blocked(403, "")
    assert M.is_waf_blocked(429, "")
    assert not M.is_waf_blocked(200, "normal page")


def test_is_waf_blocked_body_signature():
    assert M.is_waf_blocked(200, "Attention Required! | Cloudflare")
    assert M.is_waf_blocked(200, "Access Denied - your request has been blocked")
    assert not M.is_waf_blocked(200, "welcome to my normal website")


def test_mutations_produce_variants():
    muts = dict(M.mutations("' OR SLEEP(6)"))
    # boşluk içeren SQL payload'ı → inline_comment + case_toggle + encode üretmeli
    assert "inline_comment" in muts
    assert muts["inline_comment"] == "'/**/OR/**/SLEEP(6)"
    assert "double_url_encode" in muts
    # case_toggle harfleri dönüşümlü büyütür
    assert muts["case_toggle"] != "' OR SLEEP(6)"


def test_mutations_dedup_and_no_noop():
    # değişmeyen dönüşümler (boşluksuz payload'da inline_comment) elenir
    muts = M.mutations("'")
    variants = [v for _, v in muts]
    assert "'" not in variants                 # no-op (kendisi) yok
    assert len(variants) == len(set(variants))  # tekrar yok
    assert muts                                # en az bir encode varyantı var


def test_double_encode_differs_from_single():
    muts = dict(M.mutations("<x>"))
    assert muts["url_encode"] != muts["double_url_encode"]
