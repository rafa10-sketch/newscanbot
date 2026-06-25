#!/usr/bin/env bash
# ============================================================
# PentestBot v2 — Tool Installation Script
# Supported: Ubuntu 22.04 LTS / Kali Linux 2024+
# Run as: sudo bash scripts/install_tools.sh
# ============================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────
BOLD="\033[1m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
RED="\033[0;31m"; CYAN="\033[0;36m"; RESET="\033[0m"

info()    { echo -e "${CYAN}${BOLD}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}${BOLD}[ OK ]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}${BOLD}[WARN]${RESET}  $*"; }
err()     { echo -e "${RED}${BOLD}[ERR ]${RESET}  $*"; }
section() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

# ── Root check ────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo bash $0)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ── Detect OS ─────────────────────────────────────────────────
IS_KALI=false
if grep -qi "kali" /etc/os-release 2>/dev/null; then
    IS_KALI=true
    info "Detected: Kali Linux"
else
    info "Detected: Ubuntu/Debian"
fi

# ── System Packages ───────────────────────────────────────────
section "System Dependencies"
apt-get update -qq

PACKAGES=(
    curl wget git unzip build-essential
    python3 python3-pip python3-venv python3-dev
    bsdextrautils jq libjson-perl libjson-xs-perl libnet-ssleay-perl
    libssl-dev libpcap-dev libxml-writer-perl nmap nikto dnsutils
    ca-certificates gnupg lsb-release procps
    libffi-dev net-tools
)
apt-get install -y -qq "${PACKAGES[@]}" 2>/dev/null
ok "System packages installed."

# ── Go Installation ───────────────────────────────────────────
section "Go Runtime"
GO_VERSION="1.22.5"
ARCH="$(dpkg --print-architecture)"
[[ "$ARCH" == "arm64" ]] && GOARCH="arm64" || GOARCH="amd64"

if ! command -v go &>/dev/null || [[ "$(go version 2>/dev/null | awk '{print $3}')" < "go1.21" ]]; then
    info "Installing Go ${GO_VERSION} (${GOARCH})..."
    GOTAR="/tmp/go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -O "$GOTАР" 2>/dev/null || \
    curl -sL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o "$GOTAP"

    # Fix variable name
    GOTAP="/tmp/go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -O "$GOTAP"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$GOTAP"
    rm -f "$GOTAP"

    # System-wide profile
    cat > /etc/profile.d/golang.sh << 'EOF'
export PATH="$PATH:/usr/local/go/bin"
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"
EOF
    chmod +x /etc/profile.d/golang.sh
    ok "Go ${GO_VERSION} installed."
else
    ok "Go already installed: $(go version | awk '{print $3}')"
fi

export PATH="$PATH:/usr/local/go/bin"
export GOPATH="${HOME}/go"
export PATH="$PATH:${GOPATH}/bin"
go env -w GONOSUMCHECK="*" 2>/dev/null || true

# ── Go Security Tools ─────────────────────────────────────────
section "Go-based Security Tools"

install_go_tool() {
    local binary="$1"
    local pkg="$2"
    local desc="${3:-}"

    if command -v "$binary" &>/dev/null; then
        ok "$binary already installed."
        return 0
    fi

    info "Installing $binary${desc:+ ($desc)}..."
    if go install "${pkg}@latest" 2>/dev/null; then
        BIN_PATH="${GOPATH}/bin/${binary}"
        if [[ -f "$BIN_PATH" ]]; then
            cp "$BIN_PATH" /usr/local/bin/
            chmod +x "/usr/local/bin/$binary"
            ok "$binary installed → /usr/local/bin/$binary"
        else
            warn "$binary binary not found after install."
        fi
    else
        warn "Failed to install $binary (non-fatal, pipeline will degrade gracefully)."
    fi
}

install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"   "passive subdomain discovery"
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder"                           "cert transparency lookup"
install_go_tool "anew"        "github.com/tomnomnom/anew"                                  "stream deduplication"
install_go_tool "dnsx"        "github.com/projectdiscovery/dnsx/cmd/dnsx"                  "fast DNS resolver"
install_go_tool "naabu"       "github.com/projectdiscovery/naabu/v2/cmd/naabu"             "port scanner"
install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx"                "HTTP prober"
install_go_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana"              "focused web crawler"
install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau"                               "historical URL discovery"
install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"           "vulnerability scanner"
install_go_tool "dalfox"      "github.com/hahwul/dalfox/v2"                                "XSS scanner"
install_go_tool "s3scanner"   "github.com/sa7mon/S3Scanner"                                "S3 bucket exposure scanner"
if [[ ! -f "/usr/local/bin/s3scanner" && -f "${GOPATH}/bin/S3Scanner" ]]; then
    cp "${GOPATH}/bin/S3Scanner" /usr/local/bin/s3scanner
    chmod +x /usr/local/bin/s3scanner
    ok "S3Scanner installed → /usr/local/bin/s3scanner"
fi

if [[ -f "/usr/local/bin/httpx" ]]; then
    cp /usr/local/bin/httpx /usr/local/bin/pd-httpx
    chmod +x /usr/local/bin/pd-httpx
    ok "ProjectDiscovery httpx aliased as /usr/local/bin/pd-httpx"
fi

# ── Nuclei Templates ──────────────────────────────────────────
section "Nuclei Templates"
if command -v nuclei &>/dev/null; then
    info "Updating Nuclei templates..."
    nuclei -update-templates -duc 2>/dev/null && ok "Nuclei templates updated." \
        || warn "Template update failed (non-fatal)."
fi

# ── testssl.sh ────────────────────────────────────────────────
section "testssl.sh"
if ! command -v testssl.sh &>/dev/null; then
    info "Installing testssl.sh..."
    TESTSSL_DIR="/opt/testssl.sh"
    if [[ -d "$TESTSSL_DIR" ]]; then
        git -C "$TESTSSL_DIR" pull -q
    else
        git clone --depth 1 "https://github.com/drwetter/testssl.sh.git" "$TESTSSL_DIR"
    fi
    chmod +x "${TESTSSL_DIR}/testssl.sh"
    ln -sf "${TESTSSL_DIR}/testssl.sh" /usr/local/bin/testssl.sh
    ok "testssl.sh installed → /usr/local/bin/testssl.sh"
else
    ok "testssl.sh already installed."
fi

# ── Python Dependencies ───────────────────────────────────────
section "Python Dependencies"
if [[ -f "${PROJECT_DIR}/requirements.txt" ]]; then
    info "Installing Python packages..."
    pip3 install --quiet --break-system-packages -r "${PROJECT_DIR}/requirements.txt" 2>/dev/null || \
    pip3 install --quiet -r "${PROJECT_DIR}/requirements.txt" 2>/dev/null || \
    {
        # Virtual env fallback
        python3 -m venv "${PROJECT_DIR}/venv"
        "${PROJECT_DIR}/venv/bin/pip" install --quiet -r "${PROJECT_DIR}/requirements.txt"
        warn "Installed into virtualenv at ${PROJECT_DIR}/venv — use venv/bin/python to run."
    }
    ok "Python packages installed."
else
    warn "requirements.txt not found at ${PROJECT_DIR}. Skipping Python deps."
fi

info "Installing SSLyze Python package..."
pip3 install --quiet --break-system-packages sslyze 2>/dev/null || \
pip3 install --quiet sslyze 2>/dev/null || \
warn "Unable to install sslyze globally; TLS validation will fall back gracefully."

# ── Environment File ──────────────────────────────────────────
section "Configuration"
ENV_FILE="${PROJECT_DIR}/.env"
EXAMPLE_FILE="${PROJECT_DIR}/.env.example"

if [[ ! -f "$ENV_FILE" && -f "$EXAMPLE_FILE" ]]; then
    cp "$EXAMPLE_FILE" "$ENV_FILE"
    ok ".env created from template at: $ENV_FILE"
    warn "Edit $ENV_FILE and add your TELEGRAM_BOT_TOKEN and GROQ_API_KEY."
elif [[ -f "$ENV_FILE" ]]; then
    ok ".env already exists."
else
    warn "No .env.example found. Create .env manually."
fi

# ── Directories ───────────────────────────────────────────────
section "Data Directories"
for dir in "${PROJECT_DIR}/data" "${PROJECT_DIR}/data/work" "${PROJECT_DIR}/logs" "${PROJECT_DIR}/reports"; do
    mkdir -p "$dir"
    ok "Directory ready: $dir"
done

# ── Final Verification ────────────────────────────────────────
section "Tool Verification"

REQUIRED=(subfinder assetfinder anew dnsx naabu httpx katana gau nuclei testssl.sh nmap curl jq)
OPTIONAL=(nikto)
MISSING=()

for tool in "${REQUIRED[@]}"; do
    if command -v "$tool" &>/dev/null; then
        VER="$(${tool} --version 2>/dev/null | head -1 | tr -d '\n' || echo 'installed')"
        ok "${tool} ✓  ${VER:0:60}"
    else
        err "${tool} — NOT FOUND"
        MISSING+=("$tool")
    fi
done

for tool in "${OPTIONAL[@]}"; do
    if command -v "$tool" &>/dev/null; then
        ok "${tool} optional tool available"
    else
        warn "${tool} optional tool not installed"
    fi
done

echo ""
if [[ ${#MISSING[@]} -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}"
    echo "  ╔════════════════════════════════════════╗"
    echo "  ║  ✅  All tools installed successfully! ║"
    echo "  ╚════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "  Run: ${BOLD}python3 main.py --check-tools${RESET}   (verify)"
    echo -e "  Run: ${BOLD}python3 main.py${RESET}                (start bot)"
    echo ""
else
    echo -e "${YELLOW}${BOLD}"
    echo "  ⚠️  Missing tools: ${MISSING[*]}"
    echo "  Some pipeline stages will be skipped."
    echo -e "${RESET}"
fi
