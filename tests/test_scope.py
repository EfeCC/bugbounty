"""Kapsam (scope) eşleştirme testleri — domain wildcard + CIDR + scope dosyası."""

import pytest

from bugtool.scope import (ScopeChecker, auto_scope_entry, host_only,
                           load_scope_file, target_matches)


def test_has_real_scope():
    # Boş → gerçek kapsam yok (aktif test sert durmalı)
    assert not ScopeChecker().has_real_scope()
    # allowed veya excluded doluysa gerçek kapsam var
    assert ScopeChecker(allowed=["example.com"]).has_real_scope()
    assert ScopeChecker(excluded=["admin.example.com"]).has_real_scope()


@pytest.mark.parametrize("target,entry,expected", [
    ("api.example.com", "*.example.com", True),
    ("deep.sub.example.com", "*.example.com", True),
    ("example.com", "*.example.com", True),
    ("example.com.evil.com", "*.example.com", False),
    ("notexample.com", "*.example.com", False),
    ("example.com", "example.com", True),
    ("api.example.com", "example.com", False),
    ("API.Example.com", "*.example.com", True),
    ("https://api.example.com/x", "*.example.com", True),
    ("api.example.com:8443", "*.example.com", True),
    ("10.0.0.5", "10.0.0.0/24", True),
    ("10.0.1.5", "10.0.0.0/24", False),
    ("192.168.1.1", "192.168.1.1", True),
])
def test_target_matches(target, entry, expected):
    assert target_matches(target, entry) is expected


def test_target_matches_empty():
    assert target_matches("", "*.example.com") is False
    assert target_matches("example.com", "") is False


def test_host_only():
    assert host_only("https://api.example.com/x") == "api.example.com"
    assert host_only("API.Example.com:443") == "api.example.com"
    assert host_only("example.com.") == "example.com"


def test_load_scope_file(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("# yorum\n*.example.com\n\n!admin.example.com\n", encoding="utf-8")
    allowed, excluded = load_scope_file(str(scope))
    assert allowed == ["*.example.com"]
    assert excluded == ["admin.example.com"]


def test_load_scope_file_missing_is_graceful(tmp_path):
    allowed, excluded = load_scope_file(str(tmp_path / "yok.txt"))
    assert allowed == [] and excluded == []


def test_load_scope_file_inline_comment_stripped(tmp_path):
    # Regresyon: satır-içi yorum ("!host  # not") yorum dahil excluded'a girmemeli —
    # aksi halde hiçbir gerçek host o string'e eşit olamayacağı için yasak hiç tetiklenmez.
    scope = tmp_path / "scope.txt"
    scope.write_text(
        "*.example.com  # ana kapsam\n"
        "!admin.example.com  # buna dokunma\n"
        "api.example.com# boşluksuz yorum\n",
        encoding="utf-8")
    allowed, excluded = load_scope_file(str(scope))
    assert allowed == ["*.example.com", "api.example.com"]
    assert excluded == ["admin.example.com"]
    # Uçtan uca: gerçekten yasaklanıyor mu (ScopeChecker üzerinden)
    checker = ScopeChecker(scope_file=str(scope))
    assert checker.is_in_scope("admin.example.com") is False
    assert checker.is_in_scope("api.example.com") is True


def test_scope_checker_allowed_and_excluded(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("*.example.com\n!admin.example.com\n", encoding="utf-8")
    checker = ScopeChecker(scope_file=str(scope))
    assert checker.is_in_scope("api.example.com") is True
    assert checker.is_in_scope("example.com") is True
    assert checker.is_in_scope("admin.example.com") is False   # excluded, allowed'ı ezer
    assert checker.is_in_scope("evil.com") is False            # allowed listesinde yok


def test_scope_checker_no_scope_means_open():
    checker = ScopeChecker()
    assert checker.is_in_scope("anything.com") is True


# ── Otomatik scope (hedeften türetme) ────────────────────────────────────────
def test_auto_scope_entry_derives_wildcard():
    assert auto_scope_entry("https://staging.dashboard.gitsec.io/x") == "*.staging.dashboard.gitsec.io"
    assert auto_scope_entry("example.com") == "*.example.com"
    assert auto_scope_entry("api.example.com:8443") == "*.api.example.com"
    assert auto_scope_entry("") == ""


def test_auto_scope_entry_covers_host_and_subdomains():
    # `*.<host>` hem host'un kendisini hem subdomain'lerini kapsamalı (tek girdi yeter).
    e = auto_scope_entry("staging.gitsec.io")
    checker = ScopeChecker(allowed=[e])
    assert checker.is_in_scope("staging.gitsec.io") is True          # host'un kendisi
    assert checker.is_in_scope("api.staging.gitsec.io") is True      # subdomain
    assert checker.is_in_scope("gitsec.io") is False                 # üst apex kapsam dışı
    assert checker.is_in_scope("www.gitsec.io") is False             # kardeş (WP marketing) kapsam dışı


def test_auto_scope_exclusion_still_wins():
    # scope.txt'te `!` ile hariç tutulan host, hedeften otomatik izinli olsa bile yasak.
    checker = ScopeChecker(allowed=[auto_scope_entry("staging.gitsec.io")],
                           excluded=["admin.staging.gitsec.io"])
    assert checker.is_in_scope("api.staging.gitsec.io") is True
    assert checker.is_in_scope("admin.staging.gitsec.io") is False   # exclusion otomatik izni ezer
