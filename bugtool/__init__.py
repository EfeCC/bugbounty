"""bugtool — deterministik bug bounty recon + yeni-asset izleme aracı.

Felsefe: ağır iş (subdomain/URL/zafiyet keşfi) tamamen deterministik script'lerle
yapılır — HİÇ LLM çağırmaz. AI (Windsurf/Claude/vs.) yalnızca çıktının ANALİZİNDE
kullanılır (triyaj, önceliklendirme, rapor). Bu ayrım hem hız/tekrarlanabilirlik
sağlar hem de sınırlı donanımda (VM) AI'ı boşa yormaz.
"""

__version__ = "0.1.0"
