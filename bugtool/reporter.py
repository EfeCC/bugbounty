"""İlerleme raporlayıcı — CLI'de süreç şeffaflığı.
Amaç: kullanıcı "hangi aşamadayım, devam mı ediyor, ne buldum, nereye kaydedildi" görsün.
Uzun aşamalarda (httpx/nuclei/katana) spinner döner → donmadığı belli olur.
`NullReporter`  : kütüphane (webrecon/fuzzer) ve testler için — hiçbir şey basmaz.
`ConsoleReporter`: CLI için — rich spinner + aşama sonucu + kaydedilen yol + hata.
Kütüphane kodu (webrecon) yalnızca bu arayüzü çağırır; sunum tamamen CLI'nin işi
(bağımsızlık korunur, testler sessiz kalır).

EKLENDİ (önceki incelemede bulundu): `error()` metodu. Eskiden bir aşama (subfinder/
nuclei/…) binary VARKEN çalışıp hata verirse bunu görme imkanı yoktu — "0 sonuç"
ile "araç kırıldı" ayrımı kayboluyordu. `webrecon.py` artık her `run()` sonrası
başarısızlığı bu metotla yüzeye çıkarıyor.
"""
from contextlib import contextmanager


class NullReporter:
    """Sessiz raporlayıcı — kütüphane/test varsayılanı (hiçbir çıktı üretmez)."""

    @contextmanager
    def stage(self, label):
        yield

    def done(self, msg, path=None):
        pass

    def skip(self, msg):
        pass

    def info(self, msg):
        pass

    def error(self, msg):
        pass


class ConsoleReporter:
    """rich tabanlı canlı raporlayıcı — CLI komutları kullanır."""

    def __init__(self, console):
        self.console = console

    @contextmanager
    def stage(self, label):
        """Bir aşamayı spinner ile sarar (bloklayan işlem sürerken döner → 'çalışıyor' belli olur)."""
        with self.console.status(f"[bold cyan]{label}…[/bold cyan]", spinner="dots"):
            yield

    def done(self, msg, path=None):
        """Aşama bitti — kaç sonuç + (varsa) kaydedilen dosya."""
        line = f"[green]  ✅ {msg}[/green]"
        if path:
            line += f"  [dim]→ {path}[/dim]"
        self.console.print(line)

    def skip(self, msg):
        """Aşama atlandı (ör. binary kurulu değil)."""
        self.console.print(f"[yellow]  ⏭️  {msg}[/yellow]")

    def info(self, msg):
        self.console.print(f"[dim]  {msg}[/dim]")

    def error(self, msg):
        """Aşama ÇALIŞTI ama hata verdi — '0 sonuç' ile 'araç kırıldı' farkını gösterir."""
        self.console.print(f"[bold red]  ❌ {msg}[/bold red]")
