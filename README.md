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
python main.py recon example.com                 # subdomain → httpx → URL → nuclei
python main.py recon example.com --passive        # sadece pasif kaynaklar
python main.py monitor example.com                # YENİ asset diff (baseline karşılaştırma)
python main.py monitor example.com --diff-only
python main.py monitor example.com --notify
```

Detaylı iş akışı (Windsurf ile analiz dahil): [docs/windsurf-workflow.md](docs/windsurf-workflow.md)

## Mimari
- `bugtool/scope.py` — kapsam kontrolü (domain wildcard + CIDR + scope dosyası)
- `bugtool/webrecon.py` — recon pipeline (subfinder→dnsx→httpx→katana/gau→nuclei)
- `bugtool/monitor.py` — baseline diff + webhook bildirimi
- `bugtool/shell.py` — subprocess yardımcı katmanı
- `main.py` — CLI (click)

## Test
```bash
pip install pytest
pytest -q
```
