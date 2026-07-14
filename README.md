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
Zaman-tabanlı SQLi/CMDi doz-yanıt merdiveniyle doğrulanır (FIRED/INCONCLUSIVE), WAF'a takılan
payload'lar mutasyonla atlatılmaya çalışılır (pozitif-kontrol).

**Kör (blind) açıklar — OOB/OAST:**
```bash
python main.py hunt example.com --active --oob <senin-collaborator-domainin>
# tarama sonrası collaborator'daki callback token'larını bir dosyaya al:
python main.py oob-correlate --hits hits.txt
```
Kör SSRF/CMDi/XSS için `TOKEN.domain` gömülür; hedef o adrese istek atarsa callback gelir,
`oob-correlate` eşleştirip `confirmed_oob` bulgusu üretir. Kendi interactsh/Burp Collaborator'ını kullan.

Detaylı iş akışı (Windsurf ile analiz dahil): [docs/windsurf-workflow.md](docs/windsurf-workflow.md)

## Mimari
- `bugtool/scope.py` — kapsam kontrolü (domain wildcard + CIDR + scope dosyası, fail-closed)
- `bugtool/webrecon.py` — recon pipeline: subfinder+crt.sh→dnsx→takeover→httpx→git/cors→
  katana/gau/**ffuf**→secrets→nuclei
- `bugtool/ct_logs.py` — crt.sh pasif subdomain kaynağı
- `bugtool/takeover.py` — subdomain takeover (dangling CNAME, 18 servis)
- `bugtool/git_check.py` — `/.git/HEAD` ifşa doğrulama
- `bugtool/cors_check.py` — CORS misconfig (reflection + credentials)
- `bugtool/secrets_scan.py` — JS'te sızmış API-key (maskeli, 25 servis)
- `bugtool/monitor.py` — baseline diff (yeni + kaybolan asset) + webhook bildirimi
- `bugtool/triage.py` — pasif çıktı analizi (tehlikeli param/dosya/tech)
- `bugtool/payloads.py` — **tek-kaynak** payload arsenali + detektörler (encode/WAF-bypass)
- `bugtool/timing.py` — doz-yanıt (timing ladder) analizi + üç-durumlu oracle (FIRED/INCONCLUSIVE/NOT_FIRED)
- `bugtool/mutator.py` — WAF-bypass mutasyonları + pozitif-kontrol (kanonik bloklandı→mutasyon geçti)
- `bugtool/oob.py` — OOB/OAST: collaborator'a korele token'lı prob (kör SSRF/CMDi/XSS)
- `bugtool/fuzzer.py` — aktif param testi (scope-gated, non-destructive, 403/429 backoff)
- `bugtool/reporter.py` — canlı ilerleme (spinner + aşama sonucu)
- `bugtool/shell.py` — subprocess yardımcı katmanı
- `main.py` — CLI (click): `hunt` / `recon` / `monitor` / `triage`

## Güvenlik notu
Yalnızca **yetkili** hedeflerde (kendi scope.txt'in) kullan. `triage --active` aktif trafik
üretir; payload'lar zarar vermeyecek şekilde tasarlandı (SLEEP/marker/aritmetik — yıkıcı komut
yok) ama yine de yalnızca test etme yetkin olan sistemlerde çalıştır.

## Test
```bash
pip install pytest
pytest -q
```
