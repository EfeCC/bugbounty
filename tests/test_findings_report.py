"""Bulgu kategori dosyaları — artifacts.write_findings_files + finding_category testleri."""

import json
import os

from bugtool import artifacts


def _f(cls, title="t", sev="high"):
    return {"class": cls, "title": title, "severity": sev, "evidence": "e"}


def test_finding_category_mapping():
    assert artifacts.finding_category(_f("secret_leak")) == "secret_sizintisi"
    assert artifacts.finding_category(_f("cors_misconfig")) == "cors"
    assert artifacts.finding_category(_f("env_exposure")) == "ifsa_misconfig"
    assert artifacts.finding_category(_f("spring_actuator_env")) == "ifsa_misconfig"
    assert artifacts.finding_category(_f("subdomain_takeover")) == "takeover"
    assert artifacts.finding_category(_f("idor_bola")) == "idor"
    # bilinmeyen sınıf → kendi adıyla dosyalanır (aktif-test sınıfları)
    assert artifacts.finding_category(_f("xss")) == "xss"
    assert artifacts.finding_category(_f("sqli")) == "sqli"
    # nuclei title'dan tanınır
    assert artifacts.finding_category({"title": "Nuclei: exposed-git", "class": ""}) == "nuclei"
    # class yok → diger
    assert artifacts.finding_category({"title": "x"}) == "diger"


def test_write_findings_files_groups_by_category(tmp_path):
    findings = [_f("secret_leak"), _f("cors_misconfig"), _f("env_exposure"),
                _f("xss"), _f("env_exposure")]
    artifacts.write_findings_files(str(tmp_path), findings)
    bdir = tmp_path / "bulgular"
    assert (bdir / "secret_sizintisi.jsonl").exists()
    assert (bdir / "cors.jsonl").exists()
    assert (bdir / "ifsa_misconfig.jsonl").exists()
    assert (bdir / "xss.jsonl").exists()
    assert (bdir / "_TUMU.json").exists()
    # ifsa_misconfig 2 env bulgusu içermeli (satır başına bir JSON)
    lines = (bdir / "ifsa_misconfig.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["class"] == "env_exposure"
    # _TUMU hepsini içerir
    tumu = json.loads((bdir / "_TUMU.json").read_text(encoding="utf-8"))
    assert len(tumu["findings"]) == 5


def test_write_findings_files_merges_not_overwrites(tmp_path):
    # recon fazı yazar, sonra aktif test fazı EKLER (üzerine ezmez).
    artifacts.write_findings_files(str(tmp_path), [_f("cors_misconfig")])          # recon
    artifacts.write_findings_files(str(tmp_path), [_f("xss"), _f("idor_bola")])    # aktif
    bdir = tmp_path / "bulgular"
    assert (bdir / "cors.jsonl").exists()      # recon bulgusu KAYBOLMADI
    assert (bdir / "xss.jsonl").exists()
    assert (bdir / "idor.jsonl").exists()
    tumu = json.loads((bdir / "_TUMU.json").read_text(encoding="utf-8"))
    assert len(tumu["findings"]) == 3          # birleşti


def test_write_findings_files_empty_noop(tmp_path):
    artifacts.write_findings_files(str(tmp_path), [])
    assert not (tmp_path / "bulgular").exists()
