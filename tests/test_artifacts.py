"""Artifact isim haritası testleri — yeni açıklayıcı adlar + geriye-uyumlu okuma.

Kritik: eski recon dizinleri (düz İngilizce adlı: urls.txt, httpx.jsonl…) `read_path` ile
hâlâ okunabilmeli, yoksa `triage --active --dir <eski>` kırılır."""

import os

from bugtool import artifacts


def test_out_path_uses_new_descriptive_name(tmp_path):
    p = artifacts.out_path(str(tmp_path), "urls")
    assert os.path.basename(p) == "05_urller.txt"
    assert os.path.basename(artifacts.out_path(str(tmp_path), "subdomains")) == "01_subdomainler.txt"
    assert os.path.basename(artifacts.out_path(str(tmp_path), "httpx")) == "04_web_servisleri.jsonl"


def test_read_path_prefers_new_name(tmp_path):
    new = os.path.join(str(tmp_path), "05_urller.txt")
    open(new, "w").close()
    assert artifacts.read_path(str(tmp_path), "urls") == new


def test_read_path_falls_back_to_legacy(tmp_path):
    # Sadece ESKİ ad var (eski recon dizini) → read_path onu bulmalı.
    legacy = os.path.join(str(tmp_path), "urls.txt")
    open(legacy, "w").close()
    assert artifacts.read_path(str(tmp_path), "urls") == legacy


def test_read_path_new_wins_over_legacy(tmp_path):
    # İkisi de varsa yeni ad kazanır.
    new = os.path.join(str(tmp_path), "05_urller.txt")
    legacy = os.path.join(str(tmp_path), "urls.txt")
    open(new, "w").close()
    open(legacy, "w").close()
    assert artifacts.read_path(str(tmp_path), "urls") == new


def test_read_path_missing_returns_new_name(tmp_path):
    # Hiçbiri yoksa yazma/okuma tutarlılığı için YENİ ad döner.
    assert artifacts.read_path(str(tmp_path), "urls").endswith("05_urller.txt")


def test_triage_reads_legacy_dir(tmp_path):
    """Uçtan uca: eski adlı urls.txt olan bir dizin triage tarafından okunabilmeli."""
    from bugtool.triage import Triage
    (tmp_path / "urls.txt").write_text(
        "https://t.example.com/api/storage-providers\n"
        "https://t.example.com/?id=1\n", encoding="utf-8")
    result = Triage().analyze_dir(str(tmp_path))
    assert result["stats"]["urls"] == 2
    assert result["stats"]["api_endpoints"] == 1     # /api/storage-providers
