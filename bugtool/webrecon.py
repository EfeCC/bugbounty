"""Web recon pipeline — bug bounty asset keşfi. Deterministik, LLM'siz.

subfinder+crt.sh → dnsx → subdomain-takeover → httpx → (katana + gau + ffuf) → nuclei
zincirini `bugtool.shell.run` ile orkestre eder. Her aşama binary/bağımlılık yoksa
SESSİZCE atlanır (graceful-degrade) — asla çökmez, kısmi sonuç döner. Ama bir aşama
VARKEN çalışıp hata verirse artık `reporter.error()` ile görünür oluyor — eskiden
"0 sonuç" ile "araç kırıldı" ayrımı yoktu.

Bu turda eklenenler (para-getirici yüzeyi genişletmek için):
  - Certificate Transparency (crt.sh): subfinder'a ek pasif subdomain kaynağı —
    henüz linklenmemiş, YENİ verilmiş sertifikaları yakalar (bkz. ct_logs.py).
  - Subdomain takeover kontrolü: dangling CNAME'leri bilinen sahiplenilebilir
    servislere (GitHub Pages/S3/Heroku/vb.) karşı kontrol eder (bkz. takeover.py).
  - Secret/API-key tarama: keşfedilen JS dosyalarını (3.taraf/CDN hariç) bilinen
    ~25 servis formatına karşı tarar (bkz. secrets_scan.py). Sonuçlar maskeli.
  Üçü de pasif/düşük-riskli olduğu için --active gerektirmez, her recon'da çalışır.

Önceki turda düzeltilenler:
  - `_in_scope`: scope_checker exception fırlatırsa artık "kapsam-dışı say" (eskiden
    "kapsamda say" dönüyordu — kapsam kontrolünün amacının tam tersiydi).
  - nuclei artık `-jsonl` ile çalıştırılıp yapılandırılmış JSON parse ediliyor (eskiden
    insan-okunur metni regex ile parse ediyordu; extractor kullanan template'lerde
    reproduction URL'i yanlış çıkarabiliyordu).
  - ffuf artık `-o/-of json` ile çalıştırılıp yapılandırılmış JSON parse ediliyor
    (eskiden stdout satırlarının URL mi path mi olduğunu tahmin ediyordu).
  - Her `run()` çağrısından sonra başarısızlık `reporter.error()` ile yüzeye çıkıyor.
"""

import json
import os
import re
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .shell import have, run
from . import artifacts
from . import ct_logs
from . import takeover
from . import secrets_scan
from . import git_check
from . import cors_check
from . import api_schema

# Nuclei için tech-BAĞIMSIZ yüksek-değerli şablon seti (varsayılan). `-as` (automatic
# scan) yalnızca httpx'in tespit ettiği teknolojiye göre şablon seçer; modern SPA/API
# hedeflerinde tech tespiti zayıf olduğunda (ör. sadece 'HSTS') neredeyse hiç şablon
# çalıştırmaz → nuclei işlevsiz kalır. Bu set ise stack'ten bağımsız olarak HER hedefte
# en yüksek sinyalli kontrolleri çalıştırır: ifşa olmuş dosyalar (.env/.git/backup),
# yanlış yapılandırma, default-login, açık panel, subdomain-takeover, genel zafiyetler.
# CVE'ler (çoğu ürün/sürüm-spesifik, custom app'te eşleşmez) ve salt-fingerprint
# 'technologies' seti bilerek DIŞARIDA — hız için. Tam tarama isteyen boş bırakır.
DEFAULT_NUCLEI_TEMPLATES = ("http/exposures/,http/misconfiguration/,http/default-logins/,"
                            "http/exposed-panels/,http/takeovers/,http/vulnerabilities/,"
                            "dns/,ssl/")


class WebRecon:
    """Deterministik web asset-keşif pipeline'ı."""

    def __init__(self, passive_only: bool = False, rate_limit: int = 150,
                 concurrency: int = 25, nuclei_severity: str = "low,medium,high,critical",
                 timeout: int = 600, max_urls: int = 3000, stages: Optional[Dict[str, bool]] = None,
                 ffuf_wordlist: str = "", ffuf_max_hosts: int = 10,
                 ffuf_codes: str = "200,204,301,302,307,401,403,405,500",
                 ffuf_timeout: int = 120,
                 katana_max_hosts: int = 15, katana_crawl_duration: int = 300,
                 nuclei_timeout: int = 1200,
                 nuclei_auto_scan: bool = False,
                 nuclei_templates: str = DEFAULT_NUCLEI_TEMPLATES,
                 nuclei_exclude_tags: str = "dos,fuzz,intrusive",
                 secrets_max_files: int = 40, apischema_max_hosts: int = 15,
                 probe_timeout: int = 8, probe_concurrency: int = 20):
        self.passive_only = passive_only
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        self.nuclei_severity = nuclei_severity
        self.timeout = timeout
        self.max_urls = max_urls
        self.stages = stages or {}
        self.ffuf_wordlist = ffuf_wordlist
        self.ffuf_max_hosts = ffuf_max_hosts
        self.ffuf_codes = ffuf_codes
        self.ffuf_timeout = ffuf_timeout
        self.katana_max_hosts = katana_max_hosts
        self.katana_crawl_duration = katana_crawl_duration
        self.nuclei_timeout = nuclei_timeout
        # DÜZELTME: nuclei filtresiz kurulu template repo'sunun TAMAMINI (binlerce şablon)
        # her host'a karşı deniyordu → tek host'ta bile nuclei_timeout'a çarpıp yarım
        # kesiliyordu. Çözüm: varsayılan olarak tech-bağımsız yüksek-değerli şablon setini
        # (DEFAULT_NUCLEI_TEMPLATES, `-t` ile) çalıştır — hem hızlı hem stack'ten bağımsız.
        # `-as` (auto-scan) opsiyoneldir ama tech tespiti zayıf hedeflerde işe yaramaz,
        # o yüzden artık varsayılan DEĞİL. `-etags` yavaş/riskli kategorileri hariç tutar.
        self.nuclei_auto_scan = nuclei_auto_scan
        self.nuclei_templates = nuclei_templates
        self.nuclei_exclude_tags = nuclei_exclude_tags
        self.secrets_max_files = secrets_max_files
        self.apischema_max_hosts = apischema_max_hosts
        # Per-host prob (git/cors/secret/apischema): KISA istek-timeout'u (self.timeout=600
        # DEĞİL) + paralel çalışma → çok subdomain'de dakikalarca donma yerine saniyeler.
        self.probe_timeout = probe_timeout
        self.probe_concurrency = probe_concurrency

    @classmethod
    def from_config(cls, cfg: Dict[str, Any]) -> "WebRecon":
        wc = (cfg or {}).get("webrecon", {}) or {}
        return cls(
            passive_only=bool(wc.get("passive_only", False)),
            rate_limit=int(wc.get("rate_limit", 150)),
            concurrency=int(wc.get("concurrency", 25)),
            nuclei_severity=str(wc.get("nuclei_severity", "low,medium,high,critical")),
            timeout=int(wc.get("timeout", 600)),
            max_urls=int(wc.get("max_urls", 3000)),
            stages=dict(wc.get("stages", {}) or {}),
            ffuf_wordlist=str(wc.get("ffuf_wordlist", "") or ""),
            ffuf_max_hosts=int(wc.get("ffuf_max_hosts", 10)),
            ffuf_codes=str(wc.get("ffuf_codes", "200,204,301,302,307,401,403,405,500")),
            ffuf_timeout=int(wc.get("ffuf_timeout", 120)),
            katana_max_hosts=int(wc.get("katana_max_hosts", 15)),
            katana_crawl_duration=int(wc.get("katana_crawl_duration", 300)),
            nuclei_timeout=int(wc.get("nuclei_timeout", 1200)),
            nuclei_auto_scan=bool(wc.get("nuclei_auto_scan", False)),
            # Anahtar yoksa → varsayılan set; boş string/null → "" (tam tarama escape-hatch'i).
            nuclei_templates=str(wc.get("nuclei_templates", DEFAULT_NUCLEI_TEMPLATES) or ""),
            nuclei_exclude_tags=str(wc.get("nuclei_exclude_tags", "dos,fuzz,intrusive") or ""),
            secrets_max_files=int(wc.get("secrets_max_files", 40)),
            apischema_max_hosts=int(wc.get("apischema_max_hosts", 15)),
            probe_timeout=int(wc.get("probe_timeout", 8)),
            probe_concurrency=int(wc.get("probe_concurrency", 20)),
        )

    def _find_wordlist(self) -> str:
        """ffuf wordlist yolunu bulur: config'teki, yoksa yaygın SecLists konumları."""
        if self.ffuf_wordlist and os.path.exists(self.ffuf_wordlist):
            return self.ffuf_wordlist
        # DÜZELTME: raft-small-words.txt ~43.000 kelime → 50 req/s ile host başına ~860sn!
        # common.txt ~4.600 kelime → 100 req/s ile ~46sn → timeout'a sığar.
        # Öncelik: küçük → büyük wordlist (eskiden büyük önce deneniyor, timeout patıyordu).
        for cand in (
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        ):
            if os.path.exists(cand):
                return cand
        return ""

    def _ffuf_host(self, host: str, wordlist: str, output_dir: str,
                   timeout: int = 120) -> Tuple[List[str], bool]:
        """Tek host'ta ffuf içerik keşfi (dizin/dosya brute). `-o/-of json` ile
        yapılandırılmış sonuç alır (status code bilgisi korunur, stdout satırlarının
        URL mi path mi olduğunu tahmin etmeye gerek kalmaz). `-ac` (auto-calibrate)
        soft-404/wildcard cevaplarını eler → yanlış-pozitif azaltır.
        Döner: (bulunan URL'ler, aşama başarılı mı)."""
        base = host.rstrip("/")
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("_") or "host"
        out_json = os.path.join(output_dir, artifacts.ffuf_name(safe_name))
        # -maxtime: ffuf'un kendisini kesmesi (graceful stop → JSON dosyası oluşur)
        # -maxtime-job: her host-path denemesi için max süre
        # Subprocess timeout = maxtime + 15sn tampon (ffuf'un JSON'ı yazması için)
        maxtime = max(30, timeout - 15)
        cmd = (f"ffuf -u {base}/FUZZ -w {wordlist} -mc {self.ffuf_codes} "
               f"-ac -s -t {self.concurrency} -rate {self.rate_limit} -timeout 10 "
               f"-maxtime {maxtime} "
               f"-o {out_json} -of json")
        run(cmd, timeout=timeout)
        hits: List[str] = []
        if not os.path.exists(out_json):
            return hits, False
        try:
            with open(out_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            for res in data.get("results", []) or []:
                url = res.get("url", "")
                if url:
                    hits.append(url)
        except (OSError, ValueError):
            return hits, False
        return hits, True

    def _stage_on(self, stage: str, default: bool = True) -> bool:
        return bool(self.stages.get(stage, default))

    @staticmethod
    def _bare_domain(target: str) -> str:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target):
            return urlparse(target).hostname or target
        return target.split("/")[0]

    @staticmethod
    def _lines(stdout: str) -> List[str]:
        return [ln.strip() for ln in (stdout or "").splitlines() if ln.strip()]

    @staticmethod
    def _probe_scheme(host: str, timeout: int = 5) -> str:
        """httpx hiç sonuç vermediğinde yedek yöntem: `requests` varsa host'un gerçekten
        hangi protokolle konuştuğu hafifçe (HEAD) denenir; `requests` yoksa ya da ikisi
        de başarısız olursa eski davranışla (https varsay) aynı sonuca döner — regresyon
        yok, sadece-HTTP hedefte artık doğru protokol bulunur."""
        try:
            import requests
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass
        except ImportError:
            return "https"
        for scheme in ("https", "http"):
            try:
                requests.head(f"{scheme}://{host}", timeout=timeout, verify=False,
                              allow_redirects=True)
                return scheme
            except Exception:
                continue
        return "https"

    @staticmethod
    def _warn_if_failed(reporter: Any, r: Optional[Dict[str, Any]], label: str):
        """Bir `shell.run()` sonucunu kontrol eder: binary çalıştı ama hata verdiyse
        (boş stdout + başarısız dönüş) reporter üzerinden görünür kılar. Eskiden bu
        sessizce 'aşama 0 sonuç buldu' gibi görünüyordu — hedef temiz mi, araç mı
        kırıldı ayırt edilemiyordu."""
        if r is None:
            return
        if not r.get("success") and not (r.get("stdout") or "").strip():
            err = (r.get("stderr") or "").strip()
            first_line = err.splitlines()[0][:200] if err else "bilinmeyen hata"
            reporter.error(f"{label} çalışırken hata: {first_line}")

    def run_pipeline(self, target: str, output_dir: str = "",
                     scope_checker: Optional[Callable[[str], bool]] = None,
                     reporter: Optional[Any] = None) -> Dict[str, Any]:
        """Pipeline'ı çalıştırır. `scope_checker(host)->bool` verilirse kapsam-dışı
        subdomain'ler tarama listesinden düşürülür. `reporter` verilirse her aşama için
        canlı ilerleme (spinner + sonuç + kaydedilen yol) basar (yoksa sessiz)."""
        if reporter is None:
            from .reporter import NullReporter
            reporter = NullReporter()
        domain = self._bare_domain(target)
        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="webrecon_")
        os.makedirs(output_dir, exist_ok=True)
        reporter.info(f"Hedef: {domain} · çıktı: {output_dir}")

        stages_run: List[str] = []
        stages_skipped: List[str] = []
        # Erken başlatıldı: hem subdomain-takeover hem nuclei aynı listeye ekliyor.
        findings: List[Dict[str, Any]] = []

        def _in_scope(host: str) -> bool:
            if not scope_checker:
                return True
            try:
                return bool(scope_checker(host))
            except Exception:
                # DÜZELTME: scope_checker beklenmedik şekilde patlarsa (ör. bozuk bir
                # host string'i) eskiden "kapsamda say" (True) dönüyordu — kapsam
                # kontrolünün amacının tam tersi. Şimdi hata durumunda kapsam-dışı say.
                return False

        # ── 1. Subdomain enumerasyonu (subfinder) ──────────────────
        subdomains: List[str] = []
        if self._stage_on("subfinder") and have("subfinder"):
            with reporter.stage("Subdomain aranıyor (subfinder)"):
                r = run(f"subfinder -d {domain} -silent", timeout=self.timeout)
                subdomains = self._lines(r["stdout"])
            self._warn_if_failed(reporter, r, "subfinder")
            stages_run.append("subfinder")
        else:
            stages_skipped.append("subfinder")
            reporter.skip("Subdomain: subfinder kurulu değil — atlandı (yalnızca apex)")

        # crt.sh (Certificate Transparency) — ek pasif kaynak, subfinder'ın kaçırdığı
        # YENİ/linklenmemiş sertifikaları yakalayabilir. passive_only'den etkilenmez
        # (hedefin kendisine değil, üçüncü taraf bir kayda sorgu atar).
        if self._stage_on("ctlogs"):
            with reporter.stage("Sertifika şeffaflığı logları taranıyor (crt.sh)"):
                ct_subs = ct_logs.fetch_subdomains(domain, timeout=min(self.timeout, 30))
                ct_subs = [s for s in ct_subs if s == domain or s.endswith("." + domain)]
            if ct_subs:
                new_count = len(set(ct_subs) - set(subdomains))
                subdomains.extend(ct_subs)
                stages_run.append("ctlogs")
                reporter.done(f"{len(ct_subs)} subdomain (crt.sh) — {new_count} tanesi yeni")
            else:
                stages_skipped.append("ctlogs")
                # DÜZELTME: eskiden requests kurulu olsa bile aynı belirsiz mesaj
                # basılıyordu, kullanıcı yanlış sebebe yöneliyordu (gerçek sebep genelde
                # hedefin hiç TLS sertifikası olmaması ya da ağ sorunu). Artık gerçek
                # sebep ayırt ediliyor.
                if not ct_logs.requests_available():
                    reporter.skip("crt.sh: 'requests' kütüphanesi kurulu değil — atlandı")
                else:
                    reporter.skip("crt.sh: sertifika kaydı bulunamadı (ağ sorunu ya da "
                                  "hedefin hiç TLS/HTTPS kullanmaması normal bir sebep olabilir)")
        else:
            stages_skipped.append("ctlogs")

        if domain not in subdomains:
            subdomains.insert(0, domain)
        seen = set()
        subdomains = [s for s in subdomains
                      if s not in seen and not seen.add(s) and _in_scope(s)]
        subs_file = artifacts.out_path(output_dir, "subdomains")
        self._write_lines(subs_file, subdomains)
        if "subfinder" in stages_run:
            reporter.done(f"{len(subdomains)} subdomain (scope-içi) bulundu", subs_file)

        # ── 2. DNS çözümleme (dnsx) ─────────────────────────────────
        resolved = subdomains
        if self._stage_on("dnsx") and len(subdomains) > 1 and have("dnsx"):
            with reporter.stage("Canlı subdomain'ler çözümleniyor (dnsx)"):
                r = run(f"dnsx -l {subs_file} -silent", timeout=self.timeout)
                got = [h for h in self._lines(r["stdout"]) if _in_scope(h)]
            self._warn_if_failed(reporter, r, "dnsx")
            if got:
                resolved = got
            stages_run.append("dnsx")
            reporter.done(f"{len(resolved)} çözülen (canlı) subdomain")
        else:
            stages_skipped.append("dnsx")
            reporter.skip("DNS çözümleme (dnsx) atlandı")
        resolved_file = artifacts.out_path(output_dir, "resolved")
        self._write_lines(resolved_file, resolved)

        # ── 2b. Subdomain takeover kontrolü ──────────────────────────
        # Kasıtlı olarak TÜM `subdomains` listesine bakar, sadece `resolved`e değil:
        # klasik dangling-CNAME durumunda CNAME kaydı vardır ama A-record zinciri
        # çözülmeyebilir (bkz. takeover.py docstring'i). Pasif/düşük-riskli olduğu
        # için --active gerektirmez; yine de scope_checker'dan geçer.
        if self._stage_on("takeover") and have("dnsx"):
            with reporter.stage("Subdomain takeover kontrolü (dangling CNAME)"):
                takeover_findings = takeover.check(subdomains, timeout=self.timeout,
                                                   scope_checker=_in_scope)
                findings.extend(takeover_findings)
            stages_run.append("takeover")
            if takeover_findings:
                reporter.done(f"{len(takeover_findings)} takeover adayı ⚠️")
            else:
                reporter.done("takeover adayı yok")
        else:
            stages_skipped.append("takeover")
            if not have("dnsx"):
                reporter.skip("Subdomain takeover kontrolü: dnsx kurulu değil — atlandı")

        # ── 3. HTTP probe (httpx) ────────────────────────────────────
        live_hosts: List[Dict[str, Any]] = []
        if self._stage_on("httpx") and have("httpx"):
            with reporter.stage(f"HTTP servisleri taranıyor (httpx, {len(resolved)} host)"):
                cmd = (f"httpx -l {resolved_file} -silent -sc -title -tech-detect -json "
                       f"-rl {self.rate_limit} -threads {self.concurrency}")
                r = run(cmd, timeout=self.timeout)
                live_hosts = self._parse_httpx(r["stdout"])
                self._write_raw(artifacts.out_path(output_dir, "httpx"), r["stdout"])
            self._warn_if_failed(reporter, r, "httpx")
            stages_run.append("httpx")
            reporter.done(f"{len(live_hosts)} canlı web servisi",
                          artifacts.out_path(output_dir, "httpx"))
        else:
            stages_skipped.append("httpx")
            reporter.skip("HTTP probe (httpx) kurulu değil — atlandı")
        live_urls = [h["url"] for h in live_hosts if h.get("url")]
        if not live_urls:
            # DÜZELTME: httpx hiç sonuç vermediğinde eskiden körlemesine 'https'
            # varsayılıyordu — sadece-HTTP servis eden bir hedefte bu yanlış tahmin
            # sonraki aşamaların (ffuf/git-check/cors-check) hiç bağlanamadan sessizce
            # "0 bulgu" göstermesine yol açabiliyordu (temiz mi, hiç bağlanamadı mı
            # ayırt edilemiyordu). `requests` varsa host başına gerçek protokol
            # hafifçe (HEAD) denenir; ikisi de başarısız olursa eski davranışla
            # (https varsay) aynı sonuca düşülür — regresyon yok.
            reporter.info("httpx sonuç vermedi — host başına http/https deneniyor (yedek yöntem)…")
            live_urls = [f"{self._probe_scheme(h)}://{h}" for h in resolved[:50]]
        live_file = artifacts.out_path(output_dir, "livehosts")
        self._write_lines(live_file, live_urls)

        # ── 3b. Git deposu ifşası doğrulama ──────────────────────────
        # Her canlı host için /.git/HEAD'i gerçekten indirir (triage.py'nin sadece
        # URL string'ine bakan pasif tespitinden farklı olarak içeriği doğrular).
        if self._stage_on("gitcheck"):
            with reporter.stage("Git deposu ifşası kontrolü (/.git/HEAD)"):
                git_findings = git_check.check(
                    live_urls, timeout=self.probe_timeout,
                    concurrency=self.probe_concurrency, scope_checker=_in_scope)
                findings.extend(git_findings)
            stages_run.append("gitcheck")
            if git_findings:
                reporter.done(f"{len(git_findings)} git deposu ifşası ⚠️")
            else:
                reporter.done("git ifşası yok")
        else:
            stages_skipped.append("gitcheck")

        # ── 3c. CORS yanlış yapılandırma kontrolü ────────────────────
        if self._stage_on("cors"):
            with reporter.stage("CORS yanlış yapılandırma kontrolü"):
                cors_findings = cors_check.check(
                    live_urls, timeout=self.probe_timeout,
                    concurrency=self.probe_concurrency, scope_checker=_in_scope)
                findings.extend(cors_findings)
            stages_run.append("cors")
            if cors_findings:
                reporter.done(f"{len(cors_findings)} CORS yanlış yapılandırması ⚠️")
            else:
                reporter.done("CORS sorunu yok")
        else:
            stages_skipped.append("cors")

        # ── 4. URL/endpoint hasadı (katana aktif + gau pasif) ───────
        urls: List[str] = []
        if not self.passive_only and self._stage_on("katana") and have("katana"):
            # DÜZELTME: Eskiden katana TÜM canlı host'ları sınırsız crawl ediyordu →
            # trip.com gibi büyük hedeflerde 600sn timeout patıyordu. Şimdi:
            #   - Host sayısı katana_max_hosts ile sınırlı
            #   - -crawl-duration ile toplam süre kısıtlı (varsayılan 5dk)
            #   - -rl ve -c ile rate/concurrency kontrollü
            #   - subprocess timeout = crawl_duration + 30sn tampon
            katana_hosts = live_urls[:self.katana_max_hosts]
            katana_file = artifacts.out_path(output_dir, "katana")
            self._write_lines(katana_file, katana_hosts)
            crawl_dur = self.katana_crawl_duration
            reporter.info(f"Katana: {len(katana_hosts)} host (max {self.katana_max_hosts}), "
                          f"süre limiti {crawl_dur}sn")
            with reporter.stage(f"URL/endpoint toplanıyor (katana — {len(katana_hosts)} host, max {crawl_dur}sn)"):
                cmd = (f"katana -list {katana_file} -silent -jc -d 3 "
                       f"-crawl-duration {crawl_dur}s "
                       f"-rl {self.rate_limit} -c {self.concurrency} "
                       f"-timeout 10")
                r = run(cmd, timeout=crawl_dur + 30)
                urls.extend(self._lines(r["stdout"]))
            self._warn_if_failed(reporter, r, "katana")
            stages_run.append("katana")
        else:
            stages_skipped.append("katana")
            reporter.skip("URL crawl (katana) atlandı" +
                          (" (passive_only)" if self.passive_only else ""))
        if self._stage_on("gau") and have("gau"):
            with reporter.stage("Arşiv URL'leri toplanıyor (gau — pasif)"):
                r = run(f"gau --threads {self.concurrency} {domain}", timeout=self.timeout)
                urls.extend(self._lines(r["stdout"]))
            self._warn_if_failed(reporter, r, "gau")
            stages_run.append("gau")
        else:
            stages_skipped.append("gau")
            reporter.skip("Arşiv URL (gau) kurulu değil — atlandı")

        # ── 4b. İçerik keşfi / dizin brute (ffuf) ────────────────────
        # Linklenmemiş yolları bulur (/admin, /.git, /backup…). Canlı host başına,
        # cap'li. Sadece GET + status-code — non-destructive. Wordlist/binary yoksa atlanır.
        if not self.passive_only and self._stage_on("ffuf") and have("ffuf"):
            wordlist = self._find_wordlist()
            if not wordlist:
                stages_skipped.append("ffuf")
                reporter.skip("İçerik keşfi (ffuf): wordlist bulunamadı — atlandı "
                              "(config → webrecon.ffuf_wordlist)")
            else:
                hosts = [h for h in live_urls if _in_scope(urlparse(h).hostname or "")]
                hosts = hosts[: self.ffuf_max_hosts]
                ffuf_hits: List[str] = []
                ffuf_fail_count = 0
                # Per-host timeout: config'ten (ffuf_timeout) veya toplam timeout'ü
                # host sayısına böl. Eskiden her host için 600sn timeout vardı → 8 host = 4800sn!
                per_host_timeout = min(self.ffuf_timeout,
                                       max(60, self.timeout // max(len(hosts), 1)))
                reporter.info(f"İçerik keşfi: {len(hosts)} host, host başına max {per_host_timeout}sn")
                for i, host in enumerate(hosts, 1):
                    reporter.info(f"  ffuf [{i}/{len(hosts)}] {host[:80]}")
                    hits, ok = self._ffuf_host(host, wordlist, output_dir,
                                               timeout=per_host_timeout)
                    ffuf_hits.extend(hits)
                    if not ok:
                        ffuf_fail_count += 1
                urls.extend(ffuf_hits)
                stages_run.append("ffuf")
                reporter.done(f"{len(ffuf_hits)} gizli path/dosya (ffuf)")
                if ffuf_fail_count:
                    reporter.error(f"ffuf {ffuf_fail_count}/{len(hosts)} host'ta "
                                   f"sonuç dosyası oluşturamadı")
        else:
            stages_skipped.append("ffuf")
            if not have("ffuf"):
                reporter.skip("İçerik keşfi (ffuf) kurulu değil — atlandı")
            elif self.passive_only:
                reporter.skip("İçerik keşfi (ffuf) atlandı (passive_only)")

        urls = self._dedup_scope_urls(urls, _in_scope)[: self.max_urls]
        urls_file = artifacts.out_path(output_dir, "urls")
        self._write_lines(urls_file, urls)
        endpoints = self._extract_endpoints(urls)
        if any(s in stages_run for s in ("katana", "gau", "ffuf")):
            reporter.done(f"{len(urls)} URL · {len(endpoints)} endpoint (toplam)", urls_file)

        # ── 4c. Secret/API-key tarama (keşfedilen JS dosyaları) ──────
        # 3.taraf/CDN dosyaları hariç tutulur (jquery vb.) — boşa istek harcamamak
        # ve gürültüyü azaltmak için. Bulgular maskeli (ilk4+son4), tam secret hiçbir
        # zaman diske/konsola yazılmaz. Pasif/düşük-riskli, --active gerektirmez.
        if self._stage_on("secrets"):
            with reporter.stage("Secret/API-key taraması (JS dosyaları)"):
                secret_findings = secrets_scan.scan(
                    urls, max_files=self.secrets_max_files, timeout=self.probe_timeout,
                    concurrency=self.probe_concurrency, scope_checker=_in_scope)
                findings.extend(secret_findings)
            stages_run.append("secrets")
            if secret_findings:
                reporter.done(f"{len(secret_findings)} olası secret sızıntısı ⚠️")
            else:
                reporter.done("secret sızıntısı bulunamadı")
        else:
            stages_skipped.append("secrets")

        # ── 4d. Swagger/OpenAPI şema keşfi ────────────────────────────
        # Bilinen konumlarda + keşfedilen URL'ler arasında şema dosyası arar, bulursa
        # query+body parametreli TAM endpoint haritasını çıkarır (bkz. api_schema.py).
        # Tamamen pasif/GET-only, --active gerektirmez. NOT: body_params/body_template
        # şu an sadece bilgi amaçlı — fuzzer'a otomatik BESLENMEZ (fuzzer henüz POST/
        # JSON body fuzzing desteklemiyor, bu ayrı bir özellik).
        api_targets: List[Dict[str, Any]] = []
        if self._stage_on("apischema"):
            with reporter.stage("API şema keşfi (Swagger/OpenAPI)"):
                api_targets = api_schema.discover(
                    live_urls, urls, max_hosts=self.apischema_max_hosts,
                    timeout=self.probe_timeout, concurrency=self.probe_concurrency,
                    scope_checker=_in_scope)
                if api_targets:
                    self._write_json(artifacts.out_path(output_dir, "api_schema"),
                                     api_targets)
            stages_run.append("apischema")
            if api_targets:
                body_count = sum(1 for t in api_targets if t.get("body_params"))
                reporter.done(f"{len(api_targets)} gizli API endpoint'i (şemadan) — "
                              f"{body_count} tanesi body-parametreli")
            else:
                reporter.done("şema dosyası bulunamadı")
        else:
            stages_skipped.append("apischema")

        # ── 5. nuclei ────────────────────────────────────────────────
        # NOT: `findings` fonksiyonun başında başlatıldı (subdomain-takeover da aynı
        # listeye ekliyor) — burada sıfırlanmıyor, üzerine ekleniyor (extend).
        if self._stage_on("nuclei") and live_urls and have("nuclei"):
            # DÜZELTME: nuclei artık kendi timeout'unu kullanıyor (varsayılan 1200sn = 20dk).
            # Eskiden global 600sn timeout kullanılıyordu → büyük hedeflerde patıyordu.
            # -c: paralel template çalıştırma, -timeout: per-istek zaman aşımı (sn).
            reporter.info(f"Nuclei: {len(live_urls)} host, max süre {self.nuclei_timeout}sn "
                          f"({self.nuclei_timeout // 60} dk)")
            with reporter.stage(f"Zafiyet taraması (nuclei, {len(live_urls)} host, "
                                f"max {self.nuclei_timeout // 60}dk)"):
                cmd = (f"nuclei -l {live_file} -jsonl -silent -severity {self.nuclei_severity} "
                       f"-rl {self.rate_limit} -c {self.concurrency} -timeout 10")
                # Şablon seçimi (kurulu template repo'sunun TAMAMINI denemek yavaşlığın
                # asıl sebebiydi): önce -as (istenirse), yoksa tech-bağımsız yüksek-değerli
                # set (-t ile), ikisi de yoksa tam tarama.
                if self.nuclei_auto_scan:
                    cmd += " -as"
                elif self.nuclei_templates:
                    for tmpl in self.nuclei_templates.split(","):
                        tmpl = tmpl.strip()
                        if tmpl:
                            cmd += f" -t {tmpl}"
                if self.nuclei_exclude_tags:
                    cmd += f" -etags {self.nuclei_exclude_tags}"
                r = run(cmd, timeout=self.nuclei_timeout)
                self._write_raw(artifacts.out_path(output_dir, "nuclei"), r["stdout"])
                nuclei_findings = self._parse_nuclei(r["stdout"])
                findings.extend(nuclei_findings)
            self._warn_if_failed(reporter, r, "nuclei")
            stages_run.append("nuclei")
            reporter.done(f"{len(nuclei_findings)} nuclei bulgusu",
                          artifacts.out_path(output_dir, "nuclei"))
        else:
            stages_skipped.append("nuclei")
            reporter.skip("Zafiyet taraması (nuclei) kurulu değil — atlandı")

        # 00_OZET.txt — klasördeki her dosyanın ne olduğunu + adetleri anlatan insan-okunur
        # index. Aktif test bu klasörü kullanırken hangi dosyanın ne içerdiği net olsun diye.
        self._write_summary(output_dir, target, domain, subdomains, live_hosts, urls,
                            endpoints, findings, api_targets, stages_run, stages_skipped)

        return {
            "domain": domain,
            "subdomains": subdomains,
            "live_hosts": live_hosts,
            "urls": urls,
            "discovered_endpoints": endpoints,
            "findings": findings,
            "api_schema_targets": api_targets,
            "stages_run": stages_run,
            "stages_skipped": stages_skipped,
            "output_dir": output_dir,
        }

    def _write_summary(self, output_dir, target, domain, subdomains, live_hosts, urls,
                       endpoints, findings, api_targets, stages_run, stages_skipped):
        """00_OZET.txt — site + tüm çıktı dosyalarının açıklaması ve adetleri (Türkçe)."""
        from datetime import datetime
        # Anahtar başına gösterilecek adet (bilinmiyorsa None → sadece "var/yok").
        counts = {
            "subdomains": len(subdomains),
            "livehosts": len(live_hosts),
            "urls": len(urls),
            "api_schema": len(api_targets),
            "nuclei": sum(1 for f in findings if str(f.get("title", "")).startswith("Nuclei:")),
        }
        lines = [
            f"GitSec Recon Özeti — {domain}",
            f"Hedef: {target}",
            f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Klasör: {output_dir}",
            "",
            f"Subdomain: {len(subdomains)} · Canlı host: {len(live_hosts)} · "
            f"URL: {len(urls)} · Endpoint: {len(endpoints)} · "
            f"Recon bulgusu: {len(findings)} · API şema: {len(api_targets)}",
            "",
            "Bu klasördeki dosyalar (numara = aşama sırası):",
        ]
        for key in ("subdomains", "resolved", "livehosts", "httpx", "urls",
                    "api_endpoints", "api_schema", "nuclei", "findings", "oob"):
            name = artifacts.new_name(key)
            desc = artifacts.DESCRIPTIONS.get(key, "")
            exists = os.path.exists(os.path.join(output_dir, name))
            cnt = counts.get(key)
            mark = f" ({cnt} adet)" if (cnt is not None and exists) else (
                "" if exists else " — (henüz yok)")
            lines.append(f"  {name:<28} — {desc}{mark}")
        lines += [
            "  icerik_kesfi_<host>.json     — ffuf içerik keşfi (host başına)",
            "  katana_hedefleri.txt         — katana'ya verilen host listesi (ara dosya)",
            "",
            f"Çalışan aşamalar: {', '.join(stages_run)}",
            f"Atlanan aşamalar: {', '.join(stages_skipped)}",
            "",
            "Aktif test için (bu reconu yeniden kullanır): "
            "python main.py triage --active --dir " + output_dir,
        ]
        try:
            with open(artifacts.out_path(output_dir, "summary"), "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError:
            pass

    # ── Parse yardımcıları ───────────────────────────────────────────
    def _parse_httpx(self, stdout: str) -> List[Dict[str, Any]]:
        hosts: List[Dict[str, Any]] = []
        for line in self._lines(stdout):
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                continue
            url = obj.get("url") or obj.get("input") or ""
            if not url:
                continue
            hosts.append({
                "url": url,
                "status": obj.get("status_code") or obj.get("status-code") or 0,
                "title": obj.get("title", "") or "",
                "tech": obj.get("tech") or obj.get("technologies") or [],
                "webserver": obj.get("webserver", "") or "",
            })
        return hosts

    def _parse_nuclei(self, stdout: str) -> List[Dict[str, Any]]:
        """nuclei `-jsonl` çıktısını parse eder (satır satır JSON). Eskiden insan-okunur
        metin çıktısı regex ile parse ediliyordu; extractor kullanan template'lerde
        reproduction URL'i yanlış çıkarabiliyordu (satırdaki SON kelimeyi URL sanıyordu,
        oysa extractor sonucu varsa son kelime çıkarılan değer olabiliyordu). JSON alan
        adları resmi nuclei çıktı şemasından doğrulandı: template-id, info.severity,
        info.name, matched-at, extracted-results, curl-command."""
        findings: List[Dict[str, Any]] = []
        cvss_map = {"critical": 9.8, "high": 7.5, "medium": 5.5, "low": 3.1}
        for line in self._lines(stdout):
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                continue
            info = obj.get("info") or {}
            sev = str(info.get("severity") or "").lower()
            if sev not in cvss_map:
                continue
            matched_at = obj.get("matched-at", "") or obj.get("host", "")
            findings.append({
                "title": f"Nuclei: {obj.get('template-id', '')}",
                "severity": sev,
                "description": info.get("name") or f"Nuclei template: {obj.get('template-id', '')}",
                "evidence": ", ".join(obj.get("extracted-results") or []) or matched_at,
                "matched_at": matched_at,
                "reproduction": obj.get("curl-command", "") or matched_at,
                "cvss": cvss_map[sev],
            })
        return findings

    @staticmethod
    def _dedup_scope_urls(urls: List[str], in_scope: Callable[[str], bool]) -> List[str]:
        out: List[str] = []
        seen = set()
        for u in urls:
            if u in seen:
                continue
            seen.add(u)
            host = urlparse(u).hostname or ""
            if host and not in_scope(host):
                continue
            out.append(u)
        return out

    @staticmethod
    def _extract_endpoints(urls: List[str]) -> List[str]:
        eps = set()
        for u in urls:
            try:
                p = urlparse(u).path
            except (ValueError, TypeError):
                continue
            if p and p != "/":
                eps.add(p.rstrip("/"))
        return sorted(eps)

    @staticmethod
    def _write_lines(path: str, lines: List[str]):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + ("\n" if lines else ""))
        except OSError:
            pass

    @staticmethod
    def _write_raw(path: str, raw: str):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(raw or "")
        except OSError:
            pass

    @staticmethod
    def _write_json(path: str, data: Any):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except OSError:
            pass
