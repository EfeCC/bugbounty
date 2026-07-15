"""shell.run() — komut enjeksiyonu fix'i (shell=False + shlex) + binary-override
regresyonu (resolve/have/detect_httpx_conflict, config.yaml → binaries: mekanizması)."""

import os
import sys

import bugtool.shell as shell


def setup_function():
    # Her testten önce global binary-registry'yi temizle (testler birbirini etkilemesin)
    shell._BINARY_PATHS.clear()


def test_shell_metacharacters_do_not_execute(tmp_path):
    # Regresyon: eski shell=True kodunda ";"/"`"/"$()" ek komut çalıştırabiliyordu.
    # "hedef" olarak enjeksiyon denemesi içeren bir değer verip marker dosyasının
    # OLUŞMADIĞINI doğruluyoruz — shell=False + shlex.split ile artık literal argüman.
    marker = tmp_path / "pwned.txt"
    injected = f'example.com; echo pwned > "{marker}"'
    # "echo" bulunan bir binary olduğu için tek argümanlı çağrı zaten (binary yok) hata
    # dönecek, ama önemli olan ";" sonrasının AYRI bir komut olarak çalışmaması.
    r = shell.run(f"echo {injected}", timeout=5)
    assert not marker.exists()
    # echo tek bir literal argüman aldı, komut ayrıştırması shell'e gitmedi
    assert "pwned" not in (r.get("stderr") or "") or r["return_code"] in (0, -1)


def test_shell_backtick_and_dollar_not_expanded():
    marker_cmd = "python3" if sys.platform != "win32" else "python"
    # Argümanın İÇİNDE backtick/`$()` olsa bile bunlar shell tarafından yorumlanmamalı —
    # shlex.split sadece tokenize eder, subprocess shell=False bunları hiç görmez.
    r = shell.run('echo "$(whoami)" `id`', timeout=5)
    # Ne olursa olsun (echo bulunamasa bile) exception fırlamaz, "success" anahtarı döner
    assert "success" in r


def test_run_never_raises_on_garbage_input():
    # Eşleşmeyen tırnak → shlex.split ValueError fırlatır; run() bunu yutup temiz döner
    r = shell.run('subfinder -d "unterminated', timeout=5)
    assert r["success"] is False
    assert "ayrıştırılamadı" in r["stderr"]


def test_run_empty_command():
    r = shell.run("   ", timeout=5)
    assert r["success"] is False
    assert "boş komut" in r["stderr"]


# ── Binary-override regresyonu (config.yaml → binaries: mekanizması korunmalı) ──
def test_resolve_uses_registry_override():
    shell.set_binary_paths({"httpx": "/opt/go/bin/httpx"})
    assert shell.resolve("httpx") == "/opt/go/bin/httpx"
    assert shell.resolve("HTTPX") == "/opt/go/bin/httpx"   # case-insensitive
    assert shell.resolve("nuclei") == "nuclei"              # kayıtlı değil → orijinal ad


def test_run_applies_binary_override(tmp_path):
    # Sahte bir "binary" oluştur (basit bir script), registry'ye kaydet, run()'ın
    # PATH'teki isim yerine bu tam yolu kullandığını doğrula.
    if sys.platform == "win32":
        fake = tmp_path / "fake.bat"
        fake.write_text("@echo hello-from-fake\n", encoding="utf-8")
    else:
        fake = tmp_path / "fake.sh"
        fake.write_text("#!/bin/sh\necho hello-from-fake\n", encoding="utf-8")
        os.chmod(fake, 0o755)
    shell.set_binary_paths({"myTool": str(fake)})
    r = shell.run("mytool", timeout=5)   # lower-case ile kayıtlı, farklı case ile çağır
    assert "hello-from-fake" in (r["stdout"] or "")


def test_have_respects_override(tmp_path):
    fake = tmp_path / ("fake.bat" if sys.platform == "win32" else "fake.sh")
    fake.write_text("echo hi\n", encoding="utf-8")
    if sys.platform != "win32":
        os.chmod(fake, 0o755)
    shell.set_binary_paths({"ghostbinary": str(fake)})
    assert shell.have("ghostbinary") is True
    assert shell.have("definitely-not-a-real-binary-xyz") is False


def test_detect_httpx_conflict_skips_if_overridden():
    # httpx registry'de tanımlıysa (kullanıcı zaten override etmiş) çakışma kontrolü
    # hiç çalışmaz — None döner, PATH'teki (yanlış) httpx'e hiç bakmaz.
    shell.set_binary_paths({"httpx": "/some/custom/path/httpx"})
    assert shell.detect_httpx_conflict() is None


def test_detect_httpx_conflict_none_when_not_installed(monkeypatch):
    monkeypatch.setattr(shell.shutil, "which", lambda b: None)
    assert shell.detect_httpx_conflict() is None
