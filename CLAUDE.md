# CLAUDE.md — bugtool geliştirme rehberi

> Bu dosya, projeyi her seferinde baştan okumamak için var. Mimariyi, modül
> haritasını, konvansiyonları ve bilinen sorunları özetler. Geliştirme yaparken
> önce burayı oku; detay gerekirse ilgili modüle git.

## Proje nedir

`bugtool` — bug bounty **asset recon + yeni-asset izleme** aracı. **Tamamen
deterministik: hiçbir komut LLM çağırmaz.** AI yalnızca çıktıyı analiz etmek için
kullanılır (harici). Python 3 + `click` CLI. Dış recon araçlarını (subfinder, dnsx,
httpx, katana, gau, ffuf, nuclei — Go binary'leri) orkestre eder.

Dil: kod İngilizce, **yorumlar/çıktı Türkçe**. Yeni kod da bu konvansiyona uymalı.

## Çalıştırma / ortam

- Giriş noktası: `main.py` (`python main.py` → interaktif menü; alt komutlar aşağıda).
- **Araç Kali/Linux'ta çalışır** (Go binary'leri orada). Bu Windows geliştirme
  makinesinde Python kurulu DEĞİL → burada çalıştırıp test edemezsin, sadece kod yaz.
- Testler: `pytest` (20 dosya, `tests/`). `shell.run` mock'lanır → binary/ağ gerekmez.
  Ağ modülleri (ct_logs/takeover/git/cors/secrets) `requests`'i doğrudan çağırır,
  testlerde ayrıca mock'lanır. Konfig dosyası yok (pytest.ini/conftest yok) → düz `pytest`.
- Kurulum: `pip install -r requirements.txt` + `scripts/install_dependencies.sh` (binary'ler).

### CLI komutları (hepsi `main.py`'de)
| Komut | Ne yapar |
|-------|----------|
| `hunt <hedef> [--active] [--oob D]` | recon → triyaj (→ opsiyonel aktif test). En sık kullanılan. |
| `recon <hedef> [--passive]` | sadece keşif pipeline'ı |
| `triage [--dir D] [--active] [--oob D]` | mevcut recon çıktısını analiz + opsiyonel aktif test |
| `monitor <scope> [--diff-only] [--notify]` | baseline diff — yeni/kaybolan asset |
| `oob-correlate --dir D --hits F` | collaborator callback'lerini gömülü problarla eşleştir |
| `check` | bağımlılık (binary/wordlist) kontrolü |
| (argümansız) | interaktif numaralı menü (`_interactive_menu`) |

## Pipeline akışı (recon)

`WebRecon.run_pipeline()` — `bugtool/webrecon.py`. Sıra:

```
subfinder + crt.sh(ct_logs)  → subdomain listesi
  → dnsx (-wd wildcard filtre) → çözümlenen (canlı) subdomain
  → takeover                  → dangling CNAME kontrolü (bulgu)
  → httpx (-fr -favicon -cl)  → canlı web servisleri (live_hosts)
  → hostrank.rank()           → ranked_urls (ilginçlik skoru + app-dedup)  ← cap'li aşamalar bunu alır
  → git_check + cors + exposures → per-host prob (bulgu)
  → katana(aktif) + gau(--subs) + ffuf → URL/endpoint hasadı
  → jsendpoints.mine()        → JS'ten gizli endpoint çıkarımı (urls'e eklenir)
  → secrets_scan              → JS'lerde secret (bulgu)
  → api_schema                → Swagger/OpenAPI keşfi (query+body param haritası)
  → cors_check.check_urls()   → API endpoint'lerinde CORS (bulgu)
  → graphql_check             → introspection açık mı (bulgu)
  → nuclei (ranked ilk N)     → zafiyet taraması (bulgu)
```

Her aşama **binary/bağımlılık yoksa sessizce atlanır** (graceful-degrade, asla çökmez).
Aşama VARKEN çalışıp hata verirse `reporter.error()` ile yüzeye çıkar (eskiden "0 sonuç"
ile "araç kırıldı" ayrımı yoktu). Aşamalar `config → webrecon.stages` ile kapatılabilir.

`hunt`/`triage --active` sonra: `Triage.analyze_dir()` → param/API endpoint/tech triyajı →
`_run_active_test()`: **query-param fuzzer + POST/JSON body fuzzer (api_schema body_params) +
api_probe (metot/yetki + IDOR/BOLA + kör SSRF OOB)**, hepsi **opt-in + scope-gated**.

## Modül haritası (`bugtool/`)

| Modül | Rol |
|-------|-----|
| `webrecon.py` | **Ana pipeline orkestratörü**. Tüm recon aşamaları burada. |
| `hostrank.py` | **Host önceliklendirme** — canlı host'ları ilginçlik skoruyla sıralar; cap'li aşamalar (ffuf/katana/apischema/git/cors/exposures/nuclei) keyfi ilk-N yerine "en değerli N"i alır. Saf/deterministik. |
| `exposures.py` | **Native yüksek-değerli ifşa/misconfig kontrolü (nuclei'siz).** .env/actuator/phpinfo/server-status/VCS/telescope/wp-config yedeği… tek-GET + imza. `probe.py` paraleliyle HER host'ta saniyeler. |
| `jsendpoints.py` | **JS endpoint madenciliği (linkfinder-native).** JS bundle'larından gizli path/endpoint çıkarır → `urls`'e ekler (triage + --active test eder). |
| `graphql_check.py` | **GraphQL introspection** — yaygın yollarda introspection açık mı (tek okuma POST'u). |
| `shell.py` | `run()` (shell=False + shlex, komut-enjeksiyon güvenli) + binary registry + httpx-çakışma tespiti. **Tüm dış komutlar buradan geçer.** |
| `scope.py` | `ScopeChecker`, `target_matches` (wildcard/CIDR), `auto_scope_entry`, `host_only`. Scope kapısı. |
| `triage.py` | Pasif triyaj — recon artifact'lerini okur, tehlikeli param/dosya/tech işaretler. Ağ YOK. |
| `fuzzer.py` | Aktif query-param + **POST/JSON body** testi (`fuzz_body_targets`). DETECTION payload'ları (non-destructive). Scope-gated, opt-in, rate-limited. |
| `api_probe.py` | Path-tabanlı REST endpoint aktif testi (OPTIONS+GET metot/yetki + **IDOR/BOLA sezgisi** + kör SSRF OOB). |
| `payloads.py` | **Payload arsenali — TEK KAYNAK.** Sınıf başına hints/payloads/detektör. Detection-oriented. |
| `mutator.py` | WAF-bypass mutator (encode/yorum/case). "Pozitif kontrol" disiplini. |
| `timing.py` | Zaman-tabanlı zafiyet için doz-yanıt (timing ladder). FIRED/INCONCLUSIVE/NOT_FIRED. |
| `oob.py` | OOB/OAST — collaborator token'lı prob göm + `correlate()` ile kör bulgu kanıtla. |
| `probe.py` | Per-host paralel prob katmanı (git/cors/secrets/apischema ortak concurrency). |
| `git_check.py` | `/.git/HEAD` gerçekten servis ediliyor mu (aktif doğrulama). |
| `cors_check.py` | CORS misconfig — Origin yansıması + `credentials:true`. |
| `secrets_scan.py` | JS dosyalarında sızmış API key/secret (maskeli, ~25 imza). |
| `takeover.py` | Subdomain takeover — dangling CNAME → sahiplenilebilir servis imzası. |
| `ct_logs.py` | crt.sh (Certificate Transparency) pasif subdomain kaynağı. |
| `api_schema.py` | Swagger/OpenAPI şema keşfi + parse ($ref bir seviye çözülür). |
| `monitor.py` | `AssetMonitor` — baseline snapshot + diff (yeni/kaybolan asset) + webhook. |
| `reporter.py` | `NullReporter` (kütüphane/test) / `ConsoleReporter` (CLI, rich spinner). |
| `preflight.py` | Pipeline öncesi binary/wordlist kontrolü (eksikleri erken göster). |
| `artifacts.py` | **Artifact dosya adları — TEK KAYNAK.** Yeni (Türkçe numaralı) + legacy ad; geriye-uyumlu okuma. |

## Config (`config.yaml`) — önemli bölümler

- `binaries:` — binary yol override (Kali httpx-çakışması: PD Go httpx'in tam yolu).
- `scope:` — `auto_from_target: true` (hedef otomatik `*.<host>` izinli; scope.txt elle
  düzenlemeye gerek yok). `!exclusion`'lar HER ZAMAN önce kontrol edilir, otomatik izni ezer.
- `webrecon:` — recon tuning. **VDP nazik ayarları:** `rate_limit: 50`, `concurrency: 10`,
  `probe_concurrency: 8`. Host cap'leri: `ffuf_max_hosts: 10`, `katana_max_hosts: 15`,
  `apischema_max_hosts: 15`. Timeout'lar: `timeout: 600` (genel), `nuclei_timeout: 1200`,
  `ffuf_timeout: 120`, `probe_timeout: 8`. `nuclei_templates` (varsayılan yüksek-değerli set),
  `nuclei_auto_scan: false`, `nuclei_exclude_tags: "dos,fuzz,intrusive"`.
- `fuzz:` — aktif test: `max_requests: 500`, `delay: 0.3`, `classes`, `ladder_doses`, `waf_mutations_cap`.
- `monitor:` — `baseline_dir`, `webhook_url`, `webhook_format`.

## Çıktı / artifact düzeni

Her tarama → `reports/<hedef>_<ts>/`. Dosya adları `artifacts.py`'de (TEK KAYNAK):
`00_OZET.txt`, `01_subdomainler.txt`, `02_cozumlenen_dns.txt`, `03_canli_hostlar.txt`,
`04_web_servisleri.jsonl`, `05_urller.txt`, `06_api_endpointler.txt`, `07_api_sema…json`,
`08_nuclei_zafiyet.jsonl`, `09_triyaj_bulgulari.json`, `10_oob_problari.json`.
Yazma hep yeni ad (`out_path`); okuma yeni→legacy fallback (`read_path`).

## Temel prensipler (bozma)

1. **Deterministik** — kod LLM çağırmaz.
2. **Graceful-degrade** — binary/kütüphane yoksa aşama atlanır, çökme yok, kısmi sonuç döner.
3. **Scope-gated** — her aktif istek `scope_checker`'dan geçer. Hata olursa **kapsam-DIŞI** say.
4. **Opt-in aktif test** — payload testi yalnızca `--active` ile. `scope.txt`/otomatik-scope boşsa sert durur.
5. **Non-destructive** — payload'lar kanıtlama amaçlı (SLEEP/marker/aritmetik), yıkıcı komut yok.
6. **VDP-nazik** — düşük rate/concurrency + delay; `dos,fuzz,intrusive` hariç.
7. **Güvenlik: `shell.run` shell=False + shlex** — komut string'ine asla shell metakarakteri enjekte etme.
8. Yeni bulgu → `findings` listesine `{title, severity, description, evidence, ...}` şemasıyla ekle.

## Çözülmüş: büyük-hedef host seçimi (2026-08-12)

Kullanıcının işaret ettiği "mantık hataları" — büyük hedeflerde (190-300 canlı host) host
seçiminin akıllı olmaması — çözüldü:

1. **Host önceliklendirme** (`hostrank.py`): httpx sonrası `ranked_urls` hesaplanır; git/cors/
   exposures/katana/ffuf/apischema/nuclei artık `live_urls`'ın keyfi httpx sırasını değil
   bu sıralı listeyi kullanır → cap'li aşamalar en değerli host'lara harcanır.
2. **nuclei artık TÜM host'lara değil, önceliklendirilmiş ilk `nuclei_max_hosts` (varsayılan
   40) host'a** çalışır (0 = hepsi). 300 host'ta timeout'a çarpıp yarım kesilme sorunu bitti.
3. **Native `exposures.py`** (nuclei'siz): nuclei'nin en çok ürettiği tek-GET-ile-kanıtlanır
   bulgular (CORS/takeover deseninde) native imza kontrolüne çevrildi — HER host'ta, saniyeler.
   Bu, nuclei'ye olan bağımlılığı azaltır (kullanıcının asıl istediği yön).

Yeni config: `nuclei_max_hosts`, `probe_max_hosts` (git/cors/exposures cap; 0=hepsi),
`stages.exposures` (varsayılan açık). Tümü `config.yaml`'da belgeli.

## Çözülmüş: bounty kapsam genişletme (2026-08-12, 2. tur)

Kullanıcının "ne eksik/bozuk" sorusuyla çıkan 6 bug + 6 özellik çözüldü:

**Recon flag fix'leri** (`webrecon.py`): `gau --subs` (apex değil tüm subdomain arşivi),
`dnsx -wd <domain>` (wildcard DNS çöp filtresi), `httpx -fr -favicon -cl` (redirect takip
+ favicon/content-length → dedup).

**Yeni yetenekler:**
1. `hostrank.rank(dedup=True)` — favicon/başlık+len ile aynı app'in N kopyasını cap'te tek sayar.
2. `jsendpoints.py` — JS'ten gizli endpoint madenciliği → `urls`'e beslenir.
3. `cors_check.check_urls()` — CORS artık kök `/` değil gerçek `/api/...` endpoint'lerinde.
4. `graphql_check.py` — introspection açık mı.
5. `api_probe._probe_idor()` — hassas endpoint'te komşu-ID ile IDOR/BOLA sezgisi.
6. `fuzzer.fuzz_body_targets()` — api_schema body_params'a POST/JSON body fuzzing (main'de wire'lı).

### Sıradaki olası iyileştirmeler
- `exposures.py` kataloğunu genişletmek (daha çok yüksek-sinyal yol/imza).
- `hostrank` skorunu + IDOR/CORS eşiklerini gerçek çalıştırma verisiyle kalibre etmek.
- GraphQL: introspection kapalıysa field-suggestion/batching; favicon-hash → bilinen ürün/CVE eşlemesi.
- Screenshot (gowitness) ile 300 host'u görsel triyaj.
