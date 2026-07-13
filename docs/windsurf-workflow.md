# Bug Bounty Workflow — bugtool + Windsurf

Bu doküman, bug bounty'yi **deterministik scriptler + AI analizi** ile yürütmenin akışını
anlatır. Temel prensip:

> **Token değil, pipeline darboğazdır.** Bir bug'ı otomasyon bulmaz; otomasyon sana *nereye
> bakacağını* söyler. Ağır işi (recon) deterministik komutlara bırak, AI'ı (Windsurf) sadece
> **triyaj, analiz ve rapor** için kullan.

## Neden bu ayrım?
- **Otomasyon = duplicate fabrikası.** Herkesin `nuclei`'si aynı düşük-asılı meyveyi bulur → dupe.
- **Gerçek para**: business-logic bug'ları (scanner bulamaz) + recon derinliği (kimsenin bulmadığı
  asset) + hız (yeni scope'ta ilk olmak). `monitor` komutu tam bu üçüncüsü için.

## 0. Kurulum (bir kez)
```bash
pip install -r requirements.txt
./scripts/install_dependencies.sh              # subfinder/dnsx/httpx/katana/gau/nuclei
./scripts/install_dependencies.sh --verify-only # neyin kurulu olduğunu gör
cp scope.txt.example scope.txt                  # program scope'unu düzenle
```
> Sınırlı kaynaklı bir VM'de çalıştırıyorsan: `config.yaml → webrecon.passive_only: true`,
> `rate_limit: 50`, `concurrency: 10`.

## 1. Recon (deterministik, LLM'siz)
```bash
python main.py recon example.com                 # subfinder→dnsx→httpx→katana+gau→nuclei
python main.py recon example.com --passive       # aktif crawl kapalı (OPSEC / sınırlı kaynak)
```
Çıktı artifact'leri: `reports/<hedef>_<ts>/`
- `subdomains.txt`, `resolved.txt`, `livehosts.txt`, `urls.txt`, `httpx.jsonl`, `nuclei.txt`

Kurulu olmayan aracın aşaması **sessizce atlanır** — araç çökmez, kısmi sonuç verir.

## 2. Yeni-asset takibi (bug bounty edge'i)
```bash
python main.py monitor example.com               # tara + önceki baseline ile diff → YENİ asset'ler
python main.py monitor example.com --diff-only    # taramadan, kayıtlı son iki baseline'ı karşılaştır
python main.py monitor example.com --notify       # config.yaml → monitor.webhook_url'e bildir
```
Baseline'lar `recon/<scope>/` altında. Cron ile günlük çalıştır → yeni subdomain çıkınca ilk sen ol:
```cron
# Her gün 07:00'de (crontab -e)
0 7 * * * cd /path/to/bugtool && /usr/bin/python3 main.py monitor example.com --notify >> recon/monitor.log 2>&1
```

## 3. Windsurf'te analiz (AI'ı BURADA kullan)
1. Windsurf'ü repo kökünde aç — `.windsurfrules` otomatik yüklenir (scope disiplini).
2. Cascade'e artifact'leri ver, örnek promptlar:
   - *"`reports/<oturum>/httpx.jsonl`'deki host'lardan hangi 15'i manuel bakmaya değer, neden?"*
   - *"`urls.txt`'te ilginç parametreli (id=, redirect=, url=, file=) endpoint'leri çıkar ve zafiyet sınıfına eşle."*
   - *"Bu endpoint için IDOR/BOLA test matrisi çıkar."*
3. Cascade her aday için `{asset, neden ilginç, test adımı, tahmini impact}` üretir (kurallarda tanımlı).

## 4. Manuel test + doğrulama (sen)
Cascade'in önceliklendirdiği adayları **elle** test et (Burp/curl/tarayıcı). bugtool sömürü
yapmaz — bu adım tamamen senin elinde.

## 5. Rapor
PoC bulunca Cascade'e: *"bunu HackerOne rapor formatında yaz (impact + adımlar + remediation)."*

## Rol dağılımı özeti
| İş | Kim | Neden |
|---|---|---|
| Subdomain/URL/nuclei recon | `recon`/`monitor` (deterministik) | Hızlı, tekrarlanabilir, token yakmaz |
| Yeni asset tespiti | `monitor` (cron) | Yeni scope'ta ilk olmak = az dupe |
| Triyaj / önceliklendirme | Windsurf (AI) | Yüzlerce host'tan ilginç %1 |
| Business-logic bug | Sen (manuel) | Scanner/AI bulamaz — asıl para burada |
| Rapor yazımı | Windsurf (AI) | Hızlı, tutarlı |
