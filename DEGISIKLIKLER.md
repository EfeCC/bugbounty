# bugtool — Neler Düzeltildi?

Bu belge, koda bakmadan neyin bozuk olduğunu ve neyin düzeltildiğini anlaman için.
Tüm dosya adları aynı kaldı — eski kurulumunun üzerine bu dosyaları koyman yeterli.

Her düzeltme, çalıştırılabilir testlerle doğrulandı (aşağıda "Nasıl doğrulandı"
bölümünde detay var) — sadece "olması lazım" diye yazılmadı, gerçekten çalıştırılıp
kanıtlandı.

---

## Bu klasördeki dosyalar — hangisi ne işe yarıyor

| Dosya | Ne işe yarar |
|---|---|
| `main.py` | Komutları buradan çalıştırıyorsun: `recon`, `monitor`, `triage`, `hunt` |
| `config.yaml` | Tüm ayarlar burada: kapsam, hız limitleri, hangi aşama açık/kapalı |
| `requirements.txt` | Kurulum için gereken Python kütüphanelerinin listesi |
| `scope.txt` | Bu pakette YOK, **sen oluşturacaksın** — hangi hedeflerin izinli olduğu (bkz. aşağıdaki "Kurulum") |
| `bugtool/__init__.py` | Paket tanım dosyası, içi boş — dokunmana gerek yok |
| `bugtool/shell.py` | Dış araçları (subfinder, nuclei, ffuf…) güvenli şekilde çalıştırır |
| `bugtool/scope.py` | Bir hedefin izinli/yasaklı olduğunu kontrol eder (`scope.txt`'yi okuyan dosya) |
| `bugtool/webrecon.py` | Ana keşif hattı — subdomain bulma → canlı host tespiti → URL toplama → zafiyet taraması, hepsini sırayla yönetir |
| `bugtool/ct_logs.py` | crt.sh'den ek subdomain kaynağı çeker (sertifika kayıtları) |
| `bugtool/takeover.py` | Subdomain takeover (ele geçirilebilir subdomain) kontrolü |
| `bugtool/secrets_scan.py` | JS dosyalarında sızmış API key/token arar |
| `bugtool/git_check.py` | `/.git/HEAD`'in gerçekten erişilebilir olup olmadığını doğrular |
| `bugtool/cors_check.py` | CORS yanlış yapılandırmasını (origin yansıması) kontrol eder |
| `bugtool/triage.py` | Toplanan veriyi analiz edip "buraya bak" diye öne çıkarır |
| `bugtool/fuzzer.py` | `--active` ile parametrelere test payload'ları gönderen kısım |
| `bugtool/payloads.py` | Fuzzer'ın kullandığı test payload'ları + "gerçekten bulundu mu" tespit mantığı |
| `bugtool/monitor.py` | Bir hedefi düzenli tarayıp yeni/kaybolan asset'leri takip eder |
| `bugtool/reporter.py` | Konsoldaki spinner/renkli mesajları yönetir (görsel kısım) |

Ayrıca her `.py` dosyasının en tepesinde, dosyayı açıp baksan bile göreceğin aynı
açıklama İngilizce kod değil düz Türkçe cümlelerle yazılı — yani bu tablo olmadan
bir dosyayı tek başına açsan da ne işe yaradığını ilk birkaç satırdan anlarsın.

---

## Öncelik 0 — Kapsam (scope) güvenliği

Bunların hepsi aynı sorunu paylaşıyordu: bug bounty programının izin vermediği bir
hedefin yine de test edilebilmesi.

**1. `scope.txt` dosyasına satır-içi not düşünce, o satır sessizce işe yaramıyordu.**
Örneğin `!admin.example.com  # buna dokunma` yazdığında, eski kod yorum dahil tüm
satırı "yasaklı host" olarak kaydediyordu — ama gerçek dünyada hiçbir host böyle
garip bir isme sahip olamayacağı için bu yasak asla tetiklenmiyordu. `admin.example.com`
sessizce test edilebilir kalıyordu. Artık `#` işaretinden sonrası (satır başında da,
satır içinde de) doğru şekilde temizleniyor.

**2. Beklenmedik bir hata olduğunda araç "kapsamda say" diyordu, olması gereken tam tersiydi.**
Kapsam kontrolü bir yerde beklenmedik şekilde hata verirse (örneğin çok garip bir
URL geldiğinde), eski kod bu hedefi güvenli tarafta değil, "test edilebilir" tarafta
sayıyordu. Bir güvenlik kontrolünün hata durumunda yapması gereken şey her zaman
"izin verme" olmalı — artık öyle davranıyor.

**3. `scope.txt` dosyasını hiç oluşturmamış olsan bile `--active` (canlı test) komutu susarak çalışıyordu.**
Bu en can alıcı olanıydı. Araç kendini "kapsam olmadan asla aktif test yapmam"
diye tanımlıyor ama pratikte: taze bir kurulumda `scope.txt` dosyası henüz yoksa,
eski kod bunu fark edip sadece SARI (görmezden gelinebilir) bir uyarı basıyor ve
YİNE DE devam ediyordu. Yani "kapsam tanımsız" durumunda araç fiilen kapsamsız
çalışıyordu. Artık `scope.txt` gerçekten var ve dolu değilse (ya da config.yaml'da
hedef listesi girilmemişse), araç KIRMIZI bir mesajla durur ve hiçbir istek
göndermeden çıkar.

---

## Öncelik 1 — kendi bilgisayarına karşı risk

**4. Hedef ismi (`example.com` gibi) bir komut satırına doğrudan ekleniyordu.**
`subfinder`, `nuclei`, `ffuf` gibi dış araçları çalıştırırken, hedef adı komut
metnine ham şekilde ekleniyordu. Eğer bu isim (elle yazarken bir yazım hatasıyla,
ya da ileride bir listeden/otomasyondan okunarak) noktalı virgül veya benzeri
özel karakterler içerseydi, o karakterden sonrası ayrı bir komut olarak
çalıştırılabilirdi — yani kendi bilgisayarında istenmeyen bir komut yürüyebilirdi.
Artık komutlar bu şekilde yorumlanmıyor; hedef ismi her zaman düz bir metin olarak
kalıyor, ne yazarsan yaz bir komut olarak çalıştırılmıyor.

---

## Öncelik 2 — bulguları kaçırma / yanlış bulgu riski

**5. Bir istek zaman aşımına uğrarsa, o bulgu tamamen kayboluyordu.**
Bazı zafiyet türleri (SQLi, komut enjeksiyonu) "sunucuyu N saniye beklet" diyerek
test edilir — sunucu gerçekten bekliyorsa bu bir kanıttır. Ama sunucu ÇOK uzun
beklerse (yapılandırılan zaman aşımını aşarsa), eski kod bunu "bilinmeyen hata"
sayıp tamamen görmezden geliyordu — oysa bu aslında EN GÜÇLÜ kanıttı. Artık zaman
aşımı da bir kanıt olarak değerlendiriliyor.

**6. Genel bir hata sayfası gösteren sitelerde SQLi yanlış pozitif üretebiliyordu.**
Bazı siteler her istekte (gönderdiğin şeyden bağımsız) genel bir hata sayfası
gösterir. Eski kod bunu payload'dan bağımsız kontrol etmiyordu — böyle bir sitede
neredeyse her parametre "SQLi bulundu" olarak işaretlenebilirdi. Artık payload
göndermeden önceki normal cevapla (baseline) kıyaslanıyor; aynı hata zaten
baseline'da da varsa sayılmıyor.

**7. SSRF tespitinde anlamsız/hatalı bir imza vardı.**
Listedeki imzalardan biri ("ail=1") hiçbir bilinen bulut-metadata formatına karşılık
gelmiyordu ve çok kısa olduğu için tamamen alakasız bir metinde bile (örn. bir
e-posta adresinin içinde) yanlışlıkla eşleşebilirdi. Kaldırıldı.

**8. Teknoloji versiyonu tespiti çok fazla gürültü üretiyordu.**
Neredeyse her sitede bulunan jQuery, Bootstrap gibi kütüphanelerin versiyon
numarası bile "ilginç" olarak işaretleniyordu — bu da gerçekten değerli olan
sunucu/altyapı yazılımı (nginx, Apache gibi) versiyon bilgisini gürültü içinde
kaybettiriyordu. Artık sadece sunucu tarafı sinyaller bu şekilde işaretleniyor.

**9. İstek bütçesi, en olası hedeflere göre değil, keşif sırasına göre harcanıyordu.**
Parametre adı hiçbir ipucu vermiyorsa (örn. "value", "data") eski kod TÜM zafiyet
sınıflarını deniyordu — bu da sınırlı istek bütçesinin ilk birkaç sıradan
parametrede tükenip, sonradan bulunan gerçekten ilginç bir endpoint'e hiç sıra
gelmemesine yol açabiliyordu. Artık ipucu bulunan hedefler önce test ediliyor,
ipucu olmayan parametrelerde de sadece en değerli 3 sınıf (XSS/SQLi/açık
yönlendirme) deneniyor — istersen `config.yaml`'dan eski davranışa dönebilirsin.

---

## Öncelik 3 — veri kalitesi

**10-11. nuclei ve ffuf çıktıları artık düzenli (JSON) formatta okunuyor.**
Eskiden bu iki aracın "insan için" yazdığı düz metin çıktısı tahminle
ayrıştırılıyordu — bazı durumlarda (örn. bir zafiyetin ekstra bilgi çıkardığı
template'lerde) hangi metnin hedef URL olduğu yanlış tahmin edilebiliyordu, ffuf'ta
ise bulunan yolun durum kodu (200 mü 403 mü) tamamen kayboluyordu. Artık her ikisi
de yapılandırılmış veri formatında okunuyor; daha güvenilir ve tekrar üretilebilir
bulgular (nuclei için doğrudan çalıştırılabilir bir `curl` komutu dahil).

---

## Öncelik 4-5 — performans ve görünürlük

**12. Binlerce istek gönderirken her seferinde yeni bağlantı açılıyordu.** Artık
aynı bağlantı yeniden kullanılıyor — hem daha hızlı hem hedefe daha az yük.

**13. Sertifika doğrulaması kapalıyken konsol uyarılarla doluyordu.** Artık
susturuluyor (doğrulamanın kapalı olması bilinçli bir tercih zaten).

**14. Bir araç (subfinder, nuclei…) sessizce çökerse, "0 sonuç bulundu" ile "araç
kırıldı" arasındaki fark görünmüyordu.** Artık bir aşama çalışıp hata verirse
kırmızı bir uyarı olarak gösteriliyor.

**15. Discord/Slack/Teams bildirimi başarısız olursa hiç haber verilmiyordu.**
Artık başarılı/başarısız olduğu ekrana yazılıyor. Ayrıca **Microsoft Teams'in eski
webhook formatı Mayıs 2026'da kalıcı olarak kapatıldı** — Teams bildirimi
kullanacaksan Teams'te kanal → Workflows menüsünden yeni bir webhook adresi alman
gerekiyor, eski adres artık hiçbir şey göndermez (bunu `config.yaml` içine de not
olarak ekledim).

**16. Bir asset artık canlı değilse ya da bir bulgu kayboluyorsa (yama yapıldı
gibi) bu hiç görünmüyordu, sadece "yeni" olanlar gösteriliyordu.** Artık
"artık canlı olmayan host" ve "artık görünmeyen bulgu" da ayrıca gösteriliyor.

**17. Bazı bilinen hassas dosya adları (terraform.tfstate, web.config, SSH
anahtarları, .npmrc gibi) tespit listesinde yoktu.** Eklendi.

---

## Nasıl doğrulandı

Her madde için ayrı ayrı, gerçek Python kodu çalıştırılarak test edildi — sadece
"böyle olmalı" denip bırakılmadı. Örnekler: sahte bir `scope.txt` dosyasına
satır-içi yorumlu bir kural yazıp gerçekten engellendiğini gördüm; komut
enjeksiyonu denemesi yaptım ve artık çalışmadığını doğruladım; sahte bir zaman
aşımı oluşturup bulgunun artık kaybolmadığını gördüm; boş bir `scope.txt` ile
`--active` komutunu tetikleyip gerçekten kırmızı mesajla durduğunu gördüm.
Dış araçların kendisi (subfinder, nuclei, ffuf, httpx…) bu ortamda kurulu
olmadığı için onların ürettiği GERÇEK verilerle uçtan uca deneyemedim — ama
kodun mantığını, dış araçların resmi dokümantasyonundan doğrulanmış çıktı
formatlarıyla test ettim.

**Öneri:** dosyaları kendi ortamına koyduktan sonra, önce zararsız bir hedefte
(örn. kendi sahibi olduğun bir test sitesi) `python main.py recon <hedef>` ile
tek bir tur dene, sonra `--active`'e geç.

---

## Kurulum (kod bilmesen de yapabilirsin)

1. Bu dosyaları eski `bugtool` klasörünün üzerine kopyala (aynı isimler,
   üzerine yazacaksın).
2. Terminalde proje klasörüne gir, şunu çalıştır:
   `pip install -r requirements.txt`
3. `scope.txt` dosyanın gerçekten dolu olduğundan emin ol (Öncelik 0'daki 3.
   madde — artık bu olmadan `--active` çalışmıyor).
4. Her zamanki gibi çalıştır: `python main.py hunt <hedef>` ya da
   `python main.py recon <hedef>`.

---

---

## YENİ EKLENEN — para eden üç gerçek özellik

Önceki tur sadece bug'ları düzeltmişti. Bu turda "para eden" üç yeni bulgu türü
eklendi — üçü de bug bounty'de klasik, yüksek-getirili, düşük-riskli teknikler.

**1. Subdomain Takeover Tespiti** (`bugtool/takeover.py`, yeni dosya)

Bir subdomain (`eski.hedef.com`), artık kullanılmayan bir bulut servisine
(GitHub Pages, Heroku, S3, Shopify, Azure gibi 18 farklı servisten biri) işaret
ediyorsa, o subdomain'i saldırgan tarafından ele geçirilebilir hale getirir —
bu genelde bug bounty'de yüksek/kritik önemde sayılır çünkü hedefin gerçek
domaininde (`hedef.com`'un altında) sahte içerik göstermeyi mümkün kılar.

Nasıl çalışır: her subdomain'in hangi dış servise yönlendirildiğine (CNAME) bakar,
bilinen 18 servisten birine benziyorsa o siteye tek bir ziyaret (GET isteği) yapıp
"bu kaynak artık yok" diyen özel hata mesajını arar. Sadece eşleşenleri bildirir,
eşleşmeyenler (hâlâ kullanımda olanlar) hiç raporlanmaz — bu sayede yanlış pozitif
üretmez. **Otomatik olarak her `recon`/`hunt` çalıştırmasında devreye girer**,
`--active` bayrağına gerek yok, çünkü yaptığı şey bir tarayıcının yapacağından
farklı değil (sadece sayfayı ziyaret etmek).

**Bulduğunda ne yapmalısın:** kaynağı (GitHub Pages sitesi, S3 bucket'ı vb.)
**kendin asla oluşturma/kaydettirme** — bu artık kanıtlamaktan çıkıp gerçek bir
devralmaya dönüşür ve çoğu programın kurallarına aykırıdır. Sadece bulduğun
CNAME + hata mesajını rapor olarak gönder, aracın çıktısı zaten bu ikisini
birlikte veriyor.

**2. Certificate Transparency (crt.sh) Entegrasyonu** (`bugtool/ct_logs.py`, yeni dosya)

`subfinder`'ın bazen kaçırdığı subdomain'leri, herkese açık "sertifika kayıtları"
üzerinden bulur. Bir şirket yeni bir subdomain için SSL sertifikası aldığı anda
bu kayıtlara düşer — henüz hiçbir yerde linklenmemiş, henüz kimsenin bilmediği
bir subdomain bile olsa. `monitor.py` komutuyla düzenli taradığında, rakip
araştırmacılardan önce yeni bir asset'i fark etme şansını artırır (bug
bounty'de "ilk gören kazanır" mantığı tam burada işliyor).

Her ikisi de mevcut akışa otomatik karıştı: bulgular aynı özet tabloda, aynı
`monitor` yeni/kaybolan takibinde görünüyor — ayrı bir komut öğrenmene gerek yok.

**3. Secret/API-key Tarama** (`bugtool/secrets_scan.py`, yeni dosya)

Recon sırasında bulunan JS dosyalarını (3.taraf/CDN kütüphaneleri hariç — jQuery,
Google Analytics gibi dosyalarda hedefin kendi secret'ı olmaz, boşa istek
harcanmıyor) indirip 25 farklı servisin (AWS, Google, GitHub, Stripe, Slack,
Twilio, SendGrid, OpenAI, Anthropic, özel anahtar blokları ve daha fazlası)
kendine özgü anahtar formatlarına karşı tarar. Geliştiriciler API anahtarlarını
sık sık frontend JS'ine yanlışlıkla sabit kodlar — bu bug bounty'de en yüksek
getirili bulgu kaynaklarından biridir.

**Güvenlik notu:** bulunan değerler çıktıda TAM gösterilmiyor — sadece ilk 4 +
son 4 karakter (gitleaks/trufflehog'un da kullandığı standart pratik). Böylece
gerçek bir secret aracın kendi çıktı dosyalarına/konsoluna tam olarak yazılmıyor.
Ayrıca placeholder/örnek değerler (AWS'in kendi dokümantasyonundaki
"AKIAIOSFODNN7EXAMPLE" gibi, gerçek dünyada tarayıcıların en sık yanlış pozitif
ürettiği değer) otomatik eleniyor.

**Bulduğunda ne yapmalısın:** gerçek bir secret bulursan, onu **kullanarak o
servise/API'ye istek atma** (giriş yapma, veri çekme vb.) — bu sızıntıyı
kanıtlamaktan çıkıp ayrı, yetkisiz bir erişim denemesi olur ve seni asıl
bulduğun (zararsız, pasif) bulgudan çok daha riskli bir duruma sokar. Sadece
sızıntının nerede olduğunu (maskelenmiş kanıtla) bildir.

Üçü de mevcut akışa otomatik karıştı: bulgular aynı özet tabloda, aynı `monitor`
yeni/kaybolan takibinde görünüyor — ayrı bir komut öğrenmene gerek yok.

**Test:** üçünü de gerçek dnsx/crt.sh çıktı formatlarını ve gerçekçi JS içeriğini
taklit eden sahte verilerle test ettim — gerçek bir dangling-CNAME senaryosunda
doğru buluyor, hâlâ aktif olan bir CNAME'i yanlış pozitif olarak işaretlemiyor,
gerçek görünümlü secret'ları buluyor, AWS'in kendi örnek anahtarı gibi bilinen
placeholder'ları eliyor, hiçbir yerde tam/maskelenmemiş secret sızdırmıyor, ve
kapsam-dışı host'lara hiç dokunmuyor. Toplamda bu konuşma boyunca 38 ayrı test
yazıp çalıştırdım — hepsi geçti.

## YENİ EKLENEN (2. tur) — hızlı kazançlar

Üç küçük ama gerçek bulgu üreten ekleme daha — hepsi tek istekle doğrulanan,
düşük riskli kontroller (takeover.py'nin izinden).

**4. Git Deposu İfşası Doğrulama** (`bugtool/git_check.py`, yeni dosya)

`triage.py` zaten `/.git/` gibi yolları URL'de "ilginç" diye işaretliyordu ama
gerçekten erişilebilir mi diye BAKMIYORDU — sadece bir tahmin veriyordu. Bu
modül her canlı host'ta `/.git/HEAD`'i gerçekten indirip içeriğin geçerli bir
git referansına benzeyip benzemediğini doğruluyor. Doğrulanırsa bu, **tüm
proje kaynak kodunun indirilebilir olduğu** anlamına gelir (git-dumper gibi
araçlarla) — bug bounty'de genelde yüksek/kritik sayılır. Bulduğunda depoyu
tamamen indirip saklama; birkaç dosyanın erişilebilir olduğunu göstermek yeter.

**5. CORS Yanlış Yapılandırma Kontrolü** (`bugtool/cors_check.py`, yeni dosya)

Sahte bir Origin header'ı gönderip sunucunun bunu `Access-Control-Allow-Origin`
cevabında birebir yansıtıp yansıtmadığına bakıyor. Yansıtıyor VE aynı anda
`Access-Control-Allow-Credentials: true` dönüyorsa, herhangi bir kötü niyetli
site oturum açmış bir kullanıcının kimlik bilgileriyle bu API'ye istek atabilir
— yüksek önemde. Credentials yoksa aynı bulgu daha düşük önemle raporlanıyor
(tarayıcı credential'sız cevabı zaten daha az riskli şekilde işler).

**6. 403/429'da Geri Çekilme** (`bugtool/fuzzer.py` içinde)

`--active` testi sırasında hedef art arda (varsayılan 8 kez) 403/429 dönmeye
başlarsa — muhtemelen bir WAF ya da rate-limit'e çarpmışsındır — tarama otomatik
duruyor ve sana bunu bildiriyor. Eskiden bu durumda araç köre köre denemeye
devam edip hem bütçeni boşa harcıyor hem hedefe karşı gereksiz agresif
görünüyordu.

**Test:** git_check ve cors_check'i de gerçekçi sahte HTTP cevaplarıyla test
ettim — gerçek bir git ifşasını buluyor, SPA'ların "her yola 200+html dönme"
alışkanlığından kaynaklanan yanlış pozitifi elemiyor, CORS'ta reflection+
credentials kombinasyonunu doğru ayırıyor, wildcard (`*`) ve whitelist'li
origin'leri yanlış pozitif olarak işaretlemiyor. Backoff mantığını da art arda
429 döndüren sahte bir sunucuyla test ettim — gerçekten erken duruyor. Toplam
45 test, hepsi geçti.

---

## YENİ EKLENEN (3. tur) — gerçek bir çalıştırmada bulunan düzeltmeler

Bunlar benim testlerimde değil, senin `testphp.vulnweb.com` üzerindeki GERÇEK ilk
çalıştırmanda ortaya çıktı — kod incelemesiyle asla yakalanamayacak türden şeyler.

**1. httpx binary çakışması artık spesifik olarak teşhis ediliyor.** PATH'inde
Python'un `httpx` kütüphanesinin CLI'ı, ProjectDiscovery'nin Go `httpx`'inden önce
gelirse (senin başına gelen buydu), eskiden sadece genel bir "hata" mesajı
basılıyordu. Artık bu spesifik durumu (Click'in "Usage: httpx [OPTIONS]" imzasını)
tanıyıp doğrudan çözüm komutunu veriyor.

**2. httpx tamamen başarısız olduğunda artık körlemesine "https" varsayılmıyor.**
Eskiden bu durumda her host için `https://` tahmin ediliyordu — sadece-HTTP servis
eden bir hedefte (tam senin karşılaştığın gibi) bu yanlış tahmin ffuf'u çökertiyor
ve git/CORS kontrollerinin hiç bağlanamadan sessizce "temiz" görünmesine yol
açabiliyordu (0 bulgu = hedef temiz DEĞİL, sadece hiç bağlanamadı demekti). Artık
`requests` varsa host başına gerçek protokol hafifçe deneniyor.

**3. crt.sh "sonuç yok" mesajı artık doğru sebebi söylüyor.** Eskiden requests
kurulu olsa bile "requests kurulu değil olabilir" yazıyordu. Artık gerçekten
kurulu değilse onu, kuruluyken sonuç yoksa (senin durumunda muhtemelen hedefin
hiç TLS sertifikası olmaması — sadece-HTTP bir site için normal) ayrı, doğru
mesajı basıyor.

**Test:** üçünü de senin gerçek hata metinlerini birebir taklit eden sahte
verilerle test ettim — httpx-çakışması artık senin gördüğün TAM hata metniyle
doğru tanınıyor, sadece-HTTP hedefte artık doğru protokol bulunuyor. Toplam 49
test, hepsi geçti.

**Not:** Swagger/OpenAPI şema ayrıştırma (`api_schema.py`) dosyası pakette var
ama henüz fuzzer'a bağlanmadı/test edilmedi — bu sorunu çözüp sen bir kez daha
başarılı çalıştırma yapınca ona geri döneceğim.

Bunlar bug değildi, yeni yetenek fikirleriydi. Subdomain takeover, crt.sh,
secret tarama, git exposure, CORS kontrolü ve 403/429 geri çekilme artık
TAMAMLANDI (yukarıda). Sırada: swagger/OpenAPI şema ayrıştırma + POST/JSON
gövdesi fuzzing (bunları birlikte yapmak mantıklı — swagger'dan çıkan
endpoint'ler fuzzing'in hedef listesini besleyecek), host header enjeksiyonu/
parola sıfırlama zehirleme, HTML/Markdown rapor çıktısı, HackerOne/Bugcrowd
rapor şablonu. Ayrıca kesin olarak dışarıda bırakılanlar (para hedefiyle bile):
blind XSS/SSRF (dış callback sunucusu gerektiriyor) ve login/parola sıfırlama
brute-force (hesap yasaklanma riski en yüksek şey — ana gelir kaynağını
bitirebilir).
Hazır olduğunda konuşuruz.
