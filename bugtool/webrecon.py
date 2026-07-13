"""Web recon pipeline — bug bounty asset keşfi. Deterministik, LLM'siz.

subfinder → dnsx → httpx → (katana + gau) → nuclei zincirini `bugtool.shell.run` ile
orkestre eder. Her aşama binary yoksa SESSİZCE atlanır (graceful-degrade) — asla çökmez,
kısmi sonuç döner.
"""

import json
import os
import re
import tempfile
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from .shell import have, run


class WebRecon:
    """Deterministik web asset-keşif pipeline'ı."""

    def __init__(self, passive_only: bool = False, rate_limit: int = 150,
                 concurrency: int = 25, nuclei_severity: str = "low,medium,high,critical",
                 timeout: int = 600, max_urls: int = 3000, stages: Optional[Dict[str, bool]] = None,
                 ffuf_wordlist: str = "", ffuf_max_hosts: int = 10,
                 ffuf_codes: str = "200,204,301,302,307,401,403,405,500"):
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
        )

    def _find_wordlist(self) -> str:
        """ffuf wordlist yolunu bulur: config'teki, yoksa yaygın SecLists konumları."""
        if self.ffuf_wordlist and os.path.exists(self.ffuf_wordlist):
            return self.ffuf_wordlist
        for cand in (
            "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        ):
            if os.path.exists(cand):
                return cand
        return ""

    def _ffuf_host(self, host: str, wordlist: str) -> List[str]:
        """Tek host'ta ffuf içerik keşfi (dizin/dosya brute). Bulunan yolları tam URL döner.
        `-ac` (auto-calibrate) soft-404/wildcard cevaplarını eler → yanlış-pozitif azaltır."""
        base = host.rstrip("/")
        cmd = (f"ffuf -u {base}/FUZZ -w {wordlist} -mc {self.ffuf_codes} "
               f"-ac -s -t {self.concurrency} -rate {self.rate_limit} -timeout 10")
        r = run(cmd, timeout=self.timeout)
        hits: List[str] = []
        for line in self._lines(r["stdout"]):
            line = line.strip()
            if not line:
                continue
            if line.startswith(("http://", "https://")):
                hits.append(line)
            else:
                hits.append(f"{base}/{line.lstrip('/')}")
        return hits

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

        def _in_scope(host: str) -> bool:
            if not scope_checker:
                return True
            try:
                return bool(scope_checker(host))
            except Exception:
                return True

        # ── 1. Subdomain enumerasyonu (subfinder) ──────────────────
        subdomains: List[str] = []
        if self._stage_on("subfinder") and have("subfinder"):
            with reporter.stage("Subdomain aranıyor (subfinder)"):
                r = run(f"subfinder -d {domain} -silent", timeout=self.timeout)
                subdomains = self._lines(r["stdout"])
            stages_run.append("subfinder")
        else:
            stages_skipped.append("subfinder")
            reporter.skip("Subdomain: subfinder kurulu değil — atlandı (yalnızca apex)")
        if domain not in subdomains:
            subdomains.insert(0, domain)
        seen = set()
        subdomains = [s for s in subdomains
                      if s not in seen and not seen.add(s) and _in_scope(s)]
        subs_file = os.path.join(output_dir, "subdomains.txt")
        self._write_lines(subs_file, subdomains)
        if "subfinder" in stages_run:
            reporter.done(f"{len(subdomains)} subdomain (scope-içi) bulundu", subs_file)

        # ── 2. DNS çözümleme (dnsx) ─────────────────────────────────
        resolved = subdomains
        if self._stage_on("dnsx") and len(subdomains) > 1 and have("dnsx"):
            with reporter.stage("Canlı subdomain'ler çözümleniyor (dnsx)"):
                r = run(f"dnsx -l {subs_file} -silent", timeout=self.timeout)
                got = [h for h in self._lines(r["stdout"]) if _in_scope(h)]
            if got:
                resolved = got
            stages_run.append("dnsx")
            reporter.done(f"{len(resolved)} çözülen (canlı) subdomain")
        else:
            stages_skipped.append("dnsx")
            reporter.skip("DNS çözümleme (dnsx) atlandı")
        resolved_file = os.path.join(output_dir, "resolved.txt")
        self._write_lines(resolved_file, resolved)

        # ── 3. HTTP probe (httpx) ────────────────────────────────────
        live_hosts: List[Dict[str, Any]] = []
        if self._stage_on("httpx") and have("httpx"):
            with reporter.stage(f"HTTP servisleri taranıyor (httpx, {len(resolved)} host)"):
                cmd = (f"httpx -l {resolved_file} -silent -sc -title -tech-detect -json "
                       f"-rl {self.rate_limit} -threads {self.concurrency}")
                r = run(cmd, timeout=self.timeout)
                live_hosts = self._parse_httpx(r["stdout"])
                self._write_raw(os.path.join(output_dir, "httpx.jsonl"), r["stdout"])
            stages_run.append("httpx")
            reporter.done(f"{len(live_hosts)} canlı web servisi",
                          os.path.join(output_dir, "httpx.jsonl"))
        else:
            stages_skipped.append("httpx")
            reporter.skip("HTTP probe (httpx) kurulu değil — atlandı")
        live_urls = [h["url"] for h in live_hosts if h.get("url")]
        if not live_urls:
            live_urls = [f"https://{h}" for h in resolved[:50]]
        live_file = os.path.join(output_dir, "livehosts.txt")
        self._write_lines(live_file, live_urls)

        # ── 4. URL/endpoint hasadı (katana aktif + gau pasif) ───────
        urls: List[str] = []
        if not self.passive_only and self._stage_on("katana") and have("katana"):
            with reporter.stage("URL/endpoint toplanıyor (katana — aktif crawl)"):
                r = run(f"katana -list {live_file} -silent -jc -d 2", timeout=self.timeout)
                urls.extend(self._lines(r["stdout"]))
            stages_run.append("katana")
        else:
            stages_skipped.append("katana")
            reporter.skip("URL crawl (katana) atlandı" +
                          (" (passive_only)" if self.passive_only else ""))
        if self._stage_on("gau") and have("gau"):
            with reporter.stage("Arşiv URL'leri toplanıyor (gau — pasif)"):
                r = run(f"gau --threads {self.concurrency} {domain}", timeout=self.timeout)
                urls.extend(self._lines(r["stdout"]))
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
                with reporter.stage(f"İçerik keşfi (ffuf, {len(hosts)} host × wordlist)"):
                    for host in hosts:
                        ffuf_hits.extend(self._ffuf_host(host, wordlist))
                urls.extend(ffuf_hits)
                stages_run.append("ffuf")
                reporter.done(f"{len(ffuf_hits)} gizli path/dosya (ffuf)")
        else:
            stages_skipped.append("ffuf")
            if not have("ffuf"):
                reporter.skip("İçerik keşfi (ffuf) kurulu değil — atlandı")
            elif self.passive_only:
                reporter.skip("İçerik keşfi (ffuf) atlandı (passive_only)")

        urls = self._dedup_scope_urls(urls, _in_scope)[: self.max_urls]
        urls_file = os.path.join(output_dir, "urls.txt")
        self._write_lines(urls_file, urls)
        endpoints = self._extract_endpoints(urls)
        if any(s in stages_run for s in ("katana", "gau", "ffuf")):
            reporter.done(f"{len(urls)} URL · {len(endpoints)} endpoint (toplam)", urls_file)

        # ── 5. nuclei ────────────────────────────────────────────────
        findings: List[Dict[str, Any]] = []
        if self._stage_on("nuclei") and live_urls and have("nuclei"):
            with reporter.stage(f"Zafiyet taraması (nuclei, {len(live_urls)} host)"):
                cmd = (f"nuclei -l {live_file} -silent -severity {self.nuclei_severity} "
                       f"-no-color -rl {self.rate_limit}")
                r = run(cmd, timeout=self.timeout)
                self._write_raw(os.path.join(output_dir, "nuclei.txt"), r["stdout"])
                findings = self._parse_nuclei(r["stdout"])
            stages_run.append("nuclei")
            reporter.done(f"{len(findings)} nuclei bulgusu",
                          os.path.join(output_dir, "nuclei.txt"))
        else:
            stages_skipped.append("nuclei")
            reporter.skip("Zafiyet taraması (nuclei) kurulu değil — atlandı")

        return {
            "domain": domain,
            "subdomains": subdomains,
            "live_hosts": live_hosts,
            "urls": urls,
            "discovered_endpoints": endpoints,
            "findings": findings,
            "stages_run": stages_run,
            "stages_skipped": stages_skipped,
            "output_dir": output_dir,
        }

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
        findings: List[Dict[str, Any]] = []
        pattern = re.compile(r"\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+(.*)")
        cvss_map = {"critical": 9.8, "high": 7.5, "medium": 5.5, "low": 3.1, "info": 0.0}
        for line in self._lines(stdout):
            m = pattern.search(line)
            if not m:
                continue
            template_id, _proto, sev, evidence = m.group(1), m.group(2), m.group(3).lower(), m.group(4)
            if sev not in cvss_map or sev == "info":
                continue
            findings.append({
                "title": f"Nuclei: {template_id}",
                "severity": sev,
                "description": f"Nuclei '{template_id}' template'i ile zafiyet/misconfig tespit edildi.",
                "evidence": evidence.strip(),
                "reproduction": f"nuclei -id {template_id} -u {evidence.strip().split()[-1] if evidence.strip() else ''}".strip(),
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
