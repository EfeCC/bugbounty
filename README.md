# bugtool

Bug bounty asset recon + yeni-asset izleme. **Tamamen deterministik** — hiçbir komut LLM
çağırmaz. AI (Windsurf/Claude/vs.) yalnızca çıktının analizinde kullanılır.

## Kurulum
```bash
pip install -r requirements.txt
./scripts/install_dependencies.sh        # subfinder/dnsx/httpx/katana/gau/nuclei
cp scope.txt.example scope.txt           # program scope'unu yaz
```

## Kullanım
```bash
python main.py hunt example.com                  # TEK KOMUT: recon → triyaj (otomatik zincir)
python main.py hunt example.com --active          #   + aktif detection payload testi (opt-in)
python main.py recon example.com                 # subdomain → httpx → ffuf → URL → nuclei
python main.py recon example.com --passive        # sadece pasif kaynaklar (crawl/ffuf kapalı)
python main.py monitor example.com                # YENİ asset diff (baseline karşılaştırma)
python main.py monitor example.com --diff-only
python main.py triage                             # PASİF triyaj: tehlikeli param/dosya/tech işaretle
python main.py triage --active                    # AKTİF: detection payload'ları (scope-içi, onay ister)
```

**`hunt`** senin istediğin uçtan-uca akış: recon (subdomain→canlılık→**içerik keşfi/ffuf**→URL→nuclei)
biter bitmez triyaj otomatik çalışır. `--active` eklersen bulunan parametreler payload'larla da
test edilir. `recon`/`triage` ayrı ayrı da kullanılabilir.

`triage --active` bulunan parametrelere **non-destructive detection payload'ları** basar
(XSS/SQLi/LFI/SSTI/open-redirect/CRLF/CMDi/SSRF) — scope-gated, rate-limited. Bulgular
`reports/<oturum>/triage_findings.json`'a POTANSİYEL olarak yazılır (manuel doğrulama şart).

Detaylı iş akışı (Windsurf ile analiz dahil): [docs/windsurf-workflow.md](docs/windsurf-workflow.md)

## Mimari
- `bugtool/scope.py` — kapsam kontrolü (domain wildcard + CIDR + scope dosyası)
- `bugtool/webrecon.py` — recon pipeline (subfinder→dnsx→httpx→katana/gau/**ffuf**→nuclei)
- `bugtool/monitor.py` — baseline diff + webhook bildirimi
- `bugtool/triage.py` — pasif çıktı analizi (tehlikeli param/dosya/tech)
- `bugtool/payloads.py` — **tek-kaynak** payload arsenali + detektörler (encode/WAF-bypass)
- `bugtool/fuzzer.py` — aktif param testi (scope-gated, non-destructive detection)
- `bugtool/shell.py` — subprocess yardımcı katmanı
- `main.py` — CLI (click)

## Güvenlik notu
Yalnızca **yetkili** hedeflerde (kendi scope.txt'in) kullan. `triage --active` aktif trafik
üretir; payload'lar zarar vermeyecek şekilde tasarlandı (SLEEP/marker/aritmetik — yıkıcı komut
yok) ama yine de yalnızca test etme yetkin olan sistemlerde çalıştır.

## Test
```bash
pip install pytest
pytest -q
```
