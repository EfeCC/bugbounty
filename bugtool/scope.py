"""Kapsam (scope) kontrolü — bug bounty program scope'unu (domain wildcard + CIDR)
yönetir. Bağımsız modül, herhangi bir framework'e bağlı değil.

Desteklenen scope girdisi biçimleri:
  - `example.com`      → SADECE apex eşleşir (subdomain için `*.` gerekir)
  - `*.example.com`    → apex + TÜM subdomain eşleşir (bug bounty scope standardı)
  - `203.0.113.0/24`   → CIDR (IP aralığı)
  - `203.0.113.5`      → birebir IP/string
"""

import ipaddress
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse


def host_only(value: str) -> str:
    """URL/port/scheme kırpar → çıplak host (küçük harf, sondaki nokta temizlenir)."""
    v = (value or "").strip().lower()
    if "://" in v:
        v = urlparse(v).hostname or v
    v = v.split("/")[0].split(":")[0]
    return v.rstrip(".")


def target_matches(target: str, scope_entry: str) -> bool:
    """Hedefin bir scope girdisiyle eşleşip eşleşmediğini kontrol eder.
    Destekler: birebir string, CIDR (IP aralığı), domain wildcard (`*.example.com`)."""
    if not target or not scope_entry:
        return False
    if target == scope_entry:
        return True
    try:
        network = ipaddress.ip_network(scope_entry, strict=False)
        target_ip = ipaddress.ip_address(target)
        return target_ip in network
    except (ValueError, TypeError):
        pass
    t = host_only(target)
    e = scope_entry.strip().lower().rstrip(".")
    if e.startswith("*."):
        base = e[2:]
        return t == base or t.endswith("." + base)
    return t == e


def load_scope_file(path: str) -> Tuple[List[str], List[str]]:
    """Scope dosyasını (allowed, excluded) listelerine ayrıştırır.
    Yorumlar (#) ve boş satırlar atlanır; `!` ön eki = kapsam-dışı.
    Dosya yoksa boş listeler döner (graceful-degrade)."""
    import os
    allowed: List[str] = []
    excluded: List[str] = []
    if not path or not os.path.exists(path):
        return allowed, excluded
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s.startswith("!"):
                    excluded.append(s[1:].strip())
                else:
                    allowed.append(s)
    except OSError:
        pass
    return allowed, excluded


class ScopeChecker:
    """Bir scope dosyasına (+ opsiyonel ek allowed/excluded liste) göre hedef kontrolü yapar."""

    def __init__(self, scope_file: Optional[str] = None,
                 allowed: Optional[List[str]] = None,
                 excluded: Optional[List[str]] = None):
        file_allowed, file_excluded = load_scope_file(scope_file) if scope_file else ([], [])
        self.allowed = list(allowed or []) + file_allowed
        self.excluded = list(excluded or []) + file_excluded

    def is_in_scope(self, target: str) -> bool:
        if not self.excluded and not self.allowed:
            return True  # scope tanımlı değilse her şey geçerli
        for exc in self.excluded:
            if target_matches(target, exc):
                return False
        if self.allowed:
            return any(target_matches(target, alw) for alw in self.allowed)
        return True
