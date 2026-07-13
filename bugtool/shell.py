"""Küçük subprocess yardımcı katmanı — bugtool'un tüm dış komutları buradan geçer.

PentestAgent'teki BaseTool.run_command'a benzer ama bağımsız: hiçbir framework'e
bağlı değil, tek başına import edilebilir.
"""

import os
import shutil
import subprocess
from typing import Dict, Optional


def have(binary: str) -> bool:
    """Binary PATH'te var mı? (graceful-degrade kararı için)"""
    return shutil.which(binary) is not None


def run(command: str, timeout: int = 300, quiet: bool = True,
        env: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    """Komutu shell üzerinden çalıştırır; asla exception fırlatmaz (timeout/hata dahil)."""
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
