"""Otomatik scope kablolaması (main._scope_checker + _endpoint_hosts) testleri.

Amaç: her yeni site için scope.txt'i elle değiştirmeden çalışmak. Hedef (ya da aktif
testte istek atılacak endpoint host'ları) `auto_from_target` açıkken otomatik izinli
sayılır; scope.txt'in `!exclusion`'ları yine önce kontrol edilir ve otomatik izni ezer.
`auto_from_target: false` ise eski katı davranış (yalnızca scope.txt/allowed) korunur."""

import main


def _cfg(auto=True, allowed=None, excluded=None):
    # scope_file=None → gerçek repo scope.txt'i yüklenmesin (test izolasyonu).
    return {"scope": {"scope_file": None, "auto_from_target": auto,
                      "allowed_targets": list(allowed or []),
                      "excluded_targets": list(excluded or [])}}


def test_auto_scope_authorizes_typed_target():
    # scope.txt/allowed boş ama auto açık → yazdığın hedef otomatik izinli.
    checker = main._scope_checker(_cfg(), extra_allowed=["*.y.com"])
    assert checker.is_in_scope("y.com") is True
    assert checker.is_in_scope("api.y.com") is True
    assert checker.is_in_scope("baska-site.com") is False   # yazmadığın host değil


def test_auto_scope_coexists_with_existing_allowlist():
    # scope.txt zaten X programını (gitsec) listeliyor; Y'yi otomatik ekleyince İKİSİ de geçerli.
    checker = main._scope_checker(_cfg(allowed=["staging.gitsec.io"]),
                                  extra_allowed=["*.y.com"])
    assert checker.is_in_scope("y.com") is True             # yeni hedef (otomatik)
    assert checker.is_in_scope("staging.gitsec.io") is True  # eski allowlist korunur


def test_auto_scope_off_no_scope_hard_stops_active():
    # auto_from_target=false + hiç scope tanımı yok → extra_allowed yok sayılır,
    # has_real_scope False → aktif test SERT DURUR (eski koruma korunur).
    checker = main._scope_checker(_cfg(auto=False), extra_allowed=["*.y.com"])
    assert checker.has_real_scope() is False


def test_auto_scope_off_respects_explicit_allowlist():
    # auto kapalıyken yalnızca scope.txt/allowed geçerli: listede olmayan hedef reddedilir.
    checker = main._scope_checker(_cfg(auto=False, allowed=["staging.gitsec.io"]),
                                  extra_allowed=["*.y.com"])
    assert checker.is_in_scope("y.com") is False            # otomatik girdi yok sayıldı
    assert checker.is_in_scope("staging.gitsec.io") is True


def test_auto_scope_exclusion_wins():
    # config excluded_targets, otomatik izni ezer (carve-out korunur).
    checker = main._scope_checker(_cfg(excluded=["admin.y.com"]),
                                  extra_allowed=["*.y.com"])
    assert checker.is_in_scope("api.y.com") is True
    assert checker.is_in_scope("admin.y.com") is False


def test_auto_scope_gives_real_scope_for_active_test():
    # Aktif test kapısı: auto + endpoint host'ları → has_real_scope True (test çalışır).
    checker = main._scope_checker(_cfg(), extra_allowed=["app.y.com"])
    assert checker.has_real_scope() is True


def test_endpoint_hosts_dedups_across_param_and_api():
    param = [{"url": "https://a.y.com/p?q=1"}, {"url": "https://a.y.com/other?z=2"}]
    api = [{"url": "https://b.y.com/api/x"}, {"url": "https://a.y.com/api/y"}]
    hosts = main._endpoint_hosts(param, api)
    assert hosts == ["a.y.com", "b.y.com"]                  # sıralı + tekil


def test_endpoint_hosts_handles_junk():
    assert main._endpoint_hosts([], []) == []
    assert main._endpoint_hosts([{"nourl": 1}], [{"url": ""}]) == []
