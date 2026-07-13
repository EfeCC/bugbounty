"""AssetMonitor — bug bounty yeni-asset takibi (deterministik diff, LLM'siz).

Bir scope için webrecon çıktısını baseline'a alır ve önceki baseline'la karşılaştırıp
**yeni** subdomain / canlı host / endpoint / nuclei bulgusu listesi üretir. Bug bounty'de
asıl edge budur: yeni çıkan asset'te ilk olmak. Saf-Python, ek bağımlılık yok — cron/systemd
ile periyodik çalıştırılabilir.

Baseline düzeni: `<baseline_dir>/<safe_scope>/<timestamp>.json` (arşiv) + `latest.json`.
"""

import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional


class AssetMonitor:
    """Bir scope için asset baseline'larını yönetir ve yeni-asset diff'i üretir."""

    def __init__(self, scope: str, baseline_dir: str = "recon"):
        self.scope = scope
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", scope).strip("_") or "scope"
        self.dir = os.path.join(baseline_dir, safe)
        os.makedirs(self.dir, exist_ok=True)

    def snapshot(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """webrecon çıktısını stabil (sıralı, dedup) bir baseline snapshot'ına çevirir."""
        live = sorted({h.get("url", "") for h in (parsed.get("live_hosts") or []) if h.get("url")})
        return {
            "scope": self.scope,
            "timestamp": datetime.now().isoformat(),
            "subdomains": sorted(set(parsed.get("subdomains", []) or [])),
            "live_hosts": live,
            "endpoints": sorted(set(parsed.get("discovered_endpoints", []) or [])),
            "findings": sorted({f.get("title", "") for f in (parsed.get("findings") or []) if f.get("title")}),
        }

    def load_latest(self) -> Optional[Dict[str, Any]]:
        p = os.path.join(self.dir, "latest.json")
        if not os.path.exists(p):
            return None
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def load_history(self) -> List[str]:
        try:
            files = [f for f in os.listdir(self.dir) if f.endswith(".json") and f != "latest.json"]
        except OSError:
            return []
        return [os.path.join(self.dir, f) for f in sorted(files)]

    def save(self, snapshot: Dict[str, Any]) -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        archive = os.path.join(self.dir, f"{ts}.json")
        for path in (archive, os.path.join(self.dir, "latest.json")):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2, ensure_ascii=False)
        return archive

    @staticmethod
    def diff(old: Optional[Dict[str, Any]], new: Dict[str, Any]) -> Dict[str, List[str]]:
        """new − old: her kategoride yalnızca YENİ (önceden olmayan) öğeler."""
        old = old or {}

        def _new(key: str) -> List[str]:
            return sorted(set(new.get(key, []) or []) - set(old.get(key, []) or []))

        return {
            "new_subdomains": _new("subdomains"),
            "new_live_hosts": _new("live_hosts"),
            "new_endpoints": _new("endpoints"),
            "new_findings": _new("findings"),
        }

    @staticmethod
    def has_changes(delta: Dict[str, List[str]]) -> bool:
        return any(delta.get(k) for k in
                   ("new_subdomains", "new_live_hosts", "new_endpoints", "new_findings"))

    def notify_webhook(self, delta: Dict[str, List[str]], webhook_url: str,
                       fmt: str = "generic") -> Dict[str, Any]:
        """Yeni asset'leri bir webhook'a bildirir (Slack/Teams/generic JSON). Bağımsız —
        harici entegrasyon çerçevesine bağlı değil. requests yoksa/istek başarısızsa
        graceful no-op döner."""
        if not self.has_changes(delta) or not webhook_url:
            return {}
        lines = []
        for key, label in (("new_live_hosts", "Yeni canlı host"),
                           ("new_subdomains", "Yeni subdomain"),
                           ("new_endpoints", "Yeni endpoint"),
                           ("new_findings", "Yeni nuclei bulgusu")):
            for item in delta.get(key, []):
                lines.append(f"{label}: {item}")
        text = f"[bugtool monitor] {self.scope} — {len(lines)} yeni asset/bulgu\n" + "\n".join(lines)
        try:
            import requests
        except ImportError:
            return {"success": False, "error": "requests kurulu değil"}
        if fmt == "slack":
            payload = {"text": text}
        elif fmt == "teams":
            payload = {"text": text}
        else:
            payload = {"scope": self.scope, "delta": delta, "text": text}
        try:
            resp = requests.post(webhook_url, json=payload, timeout=15)
            return {"success": resp.status_code < 300, "status_code": resp.status_code}
        except Exception as e:
            return {"success": False, "error": str(e)}
