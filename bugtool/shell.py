"""Küçük subprocess yardımcı katmanı — bugtool'un tüm dış komutları buradan geçer.

PentestAgent'teki BaseTool.run_command'a benzer ama bağımsız: hiçbir framework'e
bağlı değil, tek başına import edilebilir.

Binary çakışma sorunu (ör. Kali'de Python httpx ↔ ProjectDiscovery httpx):
  config.yaml → binaries bölümünden Go binary'sinin tam yolunu vererek çözülebilir.
  `set_binary_paths({"httpx": "/root/go/bin/httpx"})` → `have("httpx")` ve
  `run("httpx -l ...")` otomatik olarak doğru binary'yi kullanır.
"""

import os
import shutil
import subprocess
from typing import Dict, Optional


# ── Binary yol registry'si ─────────────────────────────────────────────────────
# config.yaml → binaries bölümünden dolduruluyor (main.py'de set_binary_paths çağrılır).
# Kayıtlı olmayan binary'ler için orijinal ad kullanılır (PATH'te aranır).
_BINARY_PATHS: Dict[str, str] = {}


def set_binary_paths(paths: Dict[str, str]):
    """Config'ten gelen binary yol eşleştirmelerini kaydet.
    Örnek: {"httpx": "/root/go/bin/httpx"} → `have("httpx")` ve `run("httpx ...")`
    artık o yolu kullanır."""
    _BINARY_PATHS.update({k.lower().strip(): v.strip()
                          for k, v in (paths or {}).items() if v and v.strip()})


def resolve(binary: str) -> str:
    """Binary adını registry'den çözümle; kayıtlı değilse (ya da boşsa) orijinal adı döner."""
    return _BINARY_PATHS.get(binary.lower().strip()) or binary


def have(binary: str) -> bool:
    """Binary PATH'te (ya da registry'de tanımlı yolda) var mı? (graceful-degrade kararı için)"""
    resolved = resolve(binary)
    return shutil.which(resolved) is not None


def detect_httpx_conflict() -> Optional[str]:
    """Kali'de sık rastlanan Python httpx ↔ ProjectDiscovery httpx çakışmasını tespit eder.

    ProjectDiscovery httpx `-version` flagiyle çalıştırıldığında 'projectdiscovery'
    kelimesini içerir. Python httpx ise `httpx [OPTIONS] URL` sözdizimini gösterir.

    Çakışma varsa uyarı mesajı döner; yoksa None.
    """
    if "httpx" in _BINARY_PATHS:
        return None  # kullanıcı zaten override etmiş
    path = shutil.which("httpx")
    if not path:
        return None  # hiç kurulu değil — sorun yok, aşama atlanır
    try:
        result = subprocess.run(
            [path, "-version"], capture_output=True, text=True,
            timeout=5, encoding="utf-8", errors="replace",
        )
        output = ((result.stdout or "") + (result.stderr or "")).lower()
        if "projectdiscovery" in output or "current" in output:
            return None  # doğru httpx (ProjectDiscovery)
    except Exception:
        pass
    return (
        f"⚠️  HTTPX ÇAKIŞMASI: PATH'teki httpx ({path}) ProjectDiscovery sürümü DEĞİL "
        f"(muhtemelen Python httpx CLI).\n"
        f"   Çözüm: config.yaml → binaries.httpx'e Go binary'sinin tam yolunu yaz.\n"
        f"   Örnek: binaries:\n"
        f"            httpx: /root/go/bin/httpx\n"
        f"   Ya da: pip3 uninstall httpx  (Python httpx CLI'ı kaldır)"
    )


def run(command: str, timeout: int = 300, quiet: bool = True,
        env: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    """Komutu shell üzerinden çalıştırır; asla exception fırlatmaz (timeout/hata dahil).

    Komutun ilk kelimesi (binary adı) registry'den çözümlenir — config.yaml'da
    özel yol tanımlıysa otomatik kullanılır."""
    # İlk token'ı (binary adı) resolve et
    parts = command.split(None, 1)
    if parts:
        resolved = resolve(parts[0])
        command = resolved + (" " + parts[1] if len(parts) > 1 else "")

    if not quiet:
        print(f"  $ {command[:160]}")
    run_env = {**os.environ, **env} if env else None
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace", env=run_env,
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
            "command": command,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "stdout": "", "stderr": f"timeout ({timeout}s)",
                "return_code": -1, "command": command}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e),
                "return_code": -1, "command": command}
