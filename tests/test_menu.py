"""İnteraktif menü — parametresiz başlatınca numaralı mod menüsü çıkar (CliRunner ile)."""

from click.testing import CliRunner

import main


def test_menu_renders_and_exits_on_zero():
    result = CliRunner().invoke(main.cli, [], input="0\n")
    assert result.exit_code == 0
    assert "Mod seç" in result.output
    assert "Hunt" in result.output and "OOB" in result.output


def test_menu_invalid_then_exit():
    # geçersiz seçim (9) reddedilir, tekrar sorar → sonra 0 ile çıkış
    result = CliRunner().invoke(main.cli, [], input="9\n0\n")
    assert result.exit_code == 0
    assert "Mod seç" in result.output


def test_subcommand_still_works_without_menu():
    # alt-komut verilince menü AÇILMAZ (--help subcommand yolu)
    result = CliRunner().invoke(main.cli, ["hunt", "--help"])
    assert result.exit_code == 0
    assert "Hunt" in result.output
    assert "Mod seç" not in result.output
