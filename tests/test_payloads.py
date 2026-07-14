"""payload arsenali — render, param-hint ve detektör testleri (ağ yok)."""

import bugtool.payloads as P


def test_render_payload():
    out = P.render_payload("x={M} sleep {S}", "bgtlABC")
    assert "bgtlABC" in out
    assert str(P.SLEEP_SECONDS) in out
    assert "{M}" not in out and "{S}" not in out


def test_hints_for_param():
    assert "sqli" in P.hints_for_param("id")
    assert "open_redirect" in P.hints_for_param("redirect")
    assert "lfi" in P.hints_for_param("file")
    assert "xss" in P.hints_for_param("q")
    assert P.hints_for_param("zzz_unknown_9") == []


def _ctx(body="", headers=None, elapsed=0.1, baseline=0.1, marker="bgtl123456"):
    return {"body": body, "headers": headers or {}, "status": 200,
            "elapsed": elapsed, "baseline_elapsed": baseline, "marker": marker}


def test_detect_sqli_error():
    det = P.CLASSES["sqli"]["detect"]
    ctx = _ctx(body="You have an error in your SQL syntax; check the MySQL server manual")
    assert det(ctx, {"p": "'", "t": "error"})


def test_detect_sqli_time():
    det = P.CLASSES["sqli"]["detect"]
    ctx = _ctx(body="ok", elapsed=6.3, baseline=0.2)
    assert det(ctx, {"p": "' OR SLEEP(6)-- -", "t": "time"})
    # gecikme yoksa pozitif olmamalı
    assert not det(_ctx(body="ok", elapsed=0.3, baseline=0.2), {"p": "x", "t": "time"})


def test_detect_lfi():
    det = P.CLASSES["lfi"]["detect"]
    assert det(_ctx(body="root:x:0:0:root:/root:/bin/bash"), {"p": "/etc/passwd", "t": "marker"})
    assert det(_ctx(body="[fonts]\n[extensions]"), {"p": "win.ini", "t": "marker"})
    assert not det(_ctx(body="normal page"), {"p": "x", "t": "marker"})


def test_detect_ssti():
    det = P.CLASSES["ssti"]["detect"]
    meta = {"p": "{{%d*%d}}" % (P.SSTI_A, P.SSTI_B), "t": "probe"}
    assert det(_ctx(body=f"result is {P.SSTI_RESULT} done"), meta)
    # ham ifade yansımışsa (değerlendirilmemişse) pozitif olmamalı
    assert not det(_ctx(body=meta["p"]), meta)


def test_detect_open_redirect():
    det = P.CLASSES["open_redirect"]["detect"]
    ctx = _ctx(headers={"location": f"https://{P.REDIRECT_HOST}/"})
    assert det(ctx, {"p": "x", "t": "redir"})
    assert not det(_ctx(headers={"location": "https://safe.example.com/"}), {"p": "x", "t": "redir"})


def test_detect_xss_reflection():
    det = P.CLASSES["xss"]["detect"]
    m = "bgtlaa11bb"
    body = f"<html> hello <svg/onload=alert({m})> world</html>"
    assert det(_ctx(body=body, marker=m), {"p": "x", "t": "reflect"})
    # encode edilmiş (güvenli) yansıma → pozitif olmamalı
    safe = f"&lt;svg/onload=alert({m})&gt;"
    assert not det(_ctx(body=safe, marker=m), {"p": "x", "t": "reflect"})


def test_detect_crlf():
    det = P.CLASSES["crlf"]["detect"]
    m = "bgtlcc22dd"
    assert det(_ctx(headers={"bgtl-test": m}, marker=m), {"p": "x", "t": "marker"})


def test_detect_cmdi_time():
    det = P.CLASSES["cmdi"]["detect"]
    assert det(_ctx(elapsed=6.1, baseline=0.1), {"p": ";sleep 6", "t": "time"})
    assert not det(_ctx(elapsed=0.2, baseline=0.1), {"p": ";sleep 6", "t": "time"})


def test_detect_ssrf():
    det = P.CLASSES["ssrf"]["detect"]
    assert det(_ctx(body="ami-id: ami-0abc123"), {"p": "x", "t": "probe"})
    assert not det(_ctx(body="normal"), {"p": "x", "t": "probe"})


def test_detect_ssrf_no_false_positive_on_ail():
    # Regresyon: eski listede "ail=1" imzası vardı → "email=1" gibi alakasız
    # metinde yanlış pozitif üretiyordu. Kaldırıldı.
    det = P.CLASSES["ssrf"]["detect"]
    assert not det(_ctx(body="user email=1 confirmed"), {"p": "x", "t": "probe"})
    assert det(_ctx(body="instance-id: i-0abc"), {"p": "x", "t": "probe"})


def test_all_classes_have_payloads_and_detect():
    for cls, spec in P.CLASSES.items():
        assert spec["payloads"], cls
        assert callable(spec["detect"]), cls
        assert spec["hints"], cls
