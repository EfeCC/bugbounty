#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# bugtool — Bağımlılık Kurulumu (Ubuntu/Debian)
# ═══════════════════════════════════════════════════════════════════════════
#
# Recon suite: subfinder, dnsx, httpx, katana, gau, nuclei (Go binary'leri).
# Hepsi opsiyonel — kurulu değilse `bugtool` ilgili aşamayı sessizce atlar, çökmez.
#
# Kullanım:
#   chmod +x scripts/install_dependencies.sh
#   ./scripts/install_dependencies.sh                # kur
#   ./scripts/install_dependencies.sh --verify-only   # sadece durumu raporla
# ═══════════════════════════════════════════════════════════════════════════

set -uo pipefail

VERIFY_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --verify-only) VERIFY_ONLY=1 ;;
    esac
done

GOBIN_DIR="$(go env GOBIN 2>/dev/null)"; GOBIN_DIR="${GOBIN_DIR:-$(go env GOPATH 2>/dev/null)/bin}"
GOBIN_DIR="${GOBIN_DIR:-$HOME/go/bin}"

C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'; C_RED='\033[0;31m'; C_CYAN='\033[0;36m'; C_RESET='\033[0m'
ok()   { echo -e "  ${C_GREEN}✅ $1${C_RESET}"; }
warn() { echo -e "  ${C_YELLOW}⚠️  $1${C_RESET}"; }
err()  { echo -e "  ${C_RED}❌ $1${C_RESET}"; }
section() { echo -e "\n${C_CYAN}══════ $1 ══════${C_RESET}"; }

have() { command -v "$1" >/dev/null 2>&1; }

section "Durum Raporu"
for t in subfinder dnsx httpx katana gau nuclei ffuf go python3 pip3; do
    if have "$t"; then ok "$t"; else err "$t — YOK"; fi
done
# İçerik keşfi için wordlist (ffuf) — SecLists/dirb
if [ -e /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt ] \
   || [ -e /usr/share/wordlists/dirb/common.txt ]; then
    ok "ffuf wordlist mevcut"
else
    warn "ffuf wordlist yok — kur: sudo apt install seclists  (veya dirb)"
fi
echo "$PATH" | tr ':' '\n' | grep -qx "$GOBIN_DIR" && ok "$GOBIN_DIR PATH'te" \
    || warn "$GOBIN_DIR PATH'te DEĞİL (go install ile kurulanlar çalışmaz — ~/.bashrc'ye ekleyin)"

if [ "$VERIFY_ONLY" -eq 1 ]; then
    exit 0
fi

section "Go Recon Suite Kurulumu"
if have go; then
    go_install() {
        if go install -v "$2" 2>&1 | tail -2; then ok "$1"; else err "$1 kurulamadı"; fi
    }
    go_install subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go_install dnsx      github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go_install httpx     github.com/projectdiscovery/httpx/cmd/httpx@latest
    go_install katana    github.com/projectdiscovery/katana/cmd/katana@latest
    go_install gau       github.com/lc/gau/v2/cmd/gau@latest
    go_install nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go_install ffuf      github.com/ffuf/ffuf/v2@latest
else
    warn "go kurulu değil — kurulum: https://go.dev/doc/install"
    warn "sonra: export PATH=\$PATH:\$(go env GOPATH)/bin  (~/.bashrc'ye ekleyin)"
fi

section "Python Bağımlılıkları"
if have pip3; then
    pip3 install -r "$(dirname "${BASH_SOURCE[0]}")/../requirements.txt" && ok "requirements.txt kuruldu"
else
    err "pip3 yok"
fi

# ── httpx çakışma çözücü (Kali: Python httpx ↔ ProjectDiscovery httpx) ──────
section "httpx Çakışma Kontrolü"
HTTPX_PATH="$(command -v httpx || true)"
if [ -z "$HTTPX_PATH" ]; then
    warn "httpx PATH'te yok. Kali: sudo apt install httpx-toolkit"
    warn "  sonra config.yaml → binaries.httpx: /usr/bin/httpx-toolkit"
elif httpx -version 2>&1 | grep -qiE "projectdiscovery|current"; then
    ok "httpx doğru sürüm (ProjectDiscovery): $HTTPX_PATH"
else
    warn "PATH'teki httpx ($HTTPX_PATH) ProjectDiscovery DEĞİL (muhtemelen Python httpx CLI)."
    if [ -x "$GOBIN_DIR/httpx" ]; then
        FIX="$GOBIN_DIR/httpx"
    elif have httpx-toolkit; then
        FIX="$(command -v httpx-toolkit)"
    else
        FIX=""
    fi
    if [ -n "$FIX" ]; then
        echo -e "  ${C_CYAN}→ ÇÖZÜM: config.yaml → binaries bölümüne şunu yaz:${C_RESET}"
        echo -e "        binaries:"
        echo -e "          httpx: ${FIX}"
    else
        echo -e "  ${C_CYAN}→ ÇÖZÜM: sudo apt install httpx-toolkit  (sonra binaries.httpx: /usr/bin/httpx-toolkit)${C_RESET}"
    fi
fi

echo -e "\n${C_CYAN}Kurulum tamam. Doğrulamak için: ./scripts/install_dependencies.sh --verify-only${C_RESET}"
echo -e "${C_CYAN}Kali kestirmesi (apt):  sudo apt install -y subfinder dnsx nuclei ffuf katana httpx-toolkit${C_RESET}"
