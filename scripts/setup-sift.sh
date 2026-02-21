#!/usr/bin/env bash
#
# setup-sift.sh — AIIR SIFT Platform Installer
#
# Installs the AIIR SIFT platform from the sift-mcp monorepo. Clones one
# repository, creates a single virtual environment, and installs selected
# packages in dependency order.
#
# Three install tiers:
#   Quickstart   — Core platform (~3 min)
#   Recommended  — Adds RAG search + Windows triage (~30 min)
#   Custom       — Choose individual packages (+ OpenCTI)
#
# Usage:
#   ./setup-sift.sh                                    # Interactive (default: Recommended)
#   ./setup-sift.sh --quick -y --examiner=steve --client=claude-code  # Unattended
#   ./setup-sift.sh --recommended -y                   # Fully unattended recommended
#   ./setup-sift.sh --full                             # Custom mode (interactive)
#   ./setup-sift.sh --quick --manual-start             # No auto-start
#   ./setup-sift.sh --opencti                          # Add OpenCTI (triggers wizard)
#   ./setup-sift.sh --client=claude-code               # Install + configure LLM client
#   ./setup-sift.sh --remote                           # Install only, print remote instructions
#
set -euo pipefail

# =============================================================================
# Parse Arguments
# =============================================================================

AUTO_YES=false
MODE=""  # minimal, recommended, custom, or "" (show menu)
INSTALL_DIR_ARG=""
EXAMINER_ARG=""
MANUAL_START=false
ADD_OPENCTI=false
CLIENT_ARG=""
REMOTE_MODE=false

for arg in "$@"; do
    case "$arg" in
        -y|--yes)          AUTO_YES=true ;;
        --quick|--minimal) MODE="minimal" ;;
        --recommended)     MODE="recommended" ;;
        --full|--custom)   MODE="custom" ;;
        --manual-start)    MANUAL_START=true ;;
        --opencti)         ADD_OPENCTI=true ;;
        --remote)          REMOTE_MODE=true ;;
        --install-dir=*)   INSTALL_DIR_ARG="${arg#*=}" ;;
        --examiner=*)      EXAMINER_ARG="${arg#*=}" ;;
        --client=*)        CLIENT_ARG="${arg#*=}" ;;
        -h|--help)
            echo "Usage: setup-sift.sh [OPTIONS]"
            echo ""
            echo "Tiers (pick one):"
            echo "  --quick         Quickstart — core platform (~3 min)"
            echo "  --recommended   Adds RAG search + Windows triage (~30 min)"
            echo "  --full          Custom — choose individual packages"
            echo ""
            echo "Options:"
            echo "  -y, --yes            Accept all defaults (unattended)"
            echo "  --manual-start       Don't auto-start gateway (default: auto-start)"
            echo "  --opencti            Add OpenCTI threat intelligence (triggers wizard)"
            echo "  --install-dir=PATH   Clone target directory (default: ~/aiir/sift-mcp)"
            echo "  --examiner=NAME      Examiner identity slug"
            echo "  --client=CLIENT      Configure LLM client (claude-code|claude-desktop|cursor)"
            echo "  --remote             Skip client config, print remote instructions"
            echo "  -h, --help           Show this help"
            exit 0
            ;;
    esac
done

# =============================================================================
# Colors and Helpers
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()   { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()     { echo -e "${GREEN}[OK]${NC} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()    { echo -e "${RED}[ERROR]${NC} $*"; }
header() { echo -e "\n${BOLD}=== $* ===${NC}\n"; }

prompt() {
    local msg="$1" default="${2:-}"
    if $AUTO_YES && [[ -n "$default" ]]; then
        echo "$default"
        return
    fi
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${BOLD}$msg${NC} [$default]: ")" answer
        echo "${answer:-$default}"
    else
        read -rp "$(echo -e "${BOLD}$msg${NC}: ")" answer
        echo "$answer"
    fi
}

prompt_yn() {
    local msg="$1" default="${2:-y}"
    if $AUTO_YES; then
        [[ "$default" == "y" ]]
        return
    fi
    local suffix
    if [[ "$default" == "y" ]]; then suffix="[Y/n]"; else suffix="[y/N]"; fi
    read -rp "$(echo -e "${BOLD}$msg${NC} $suffix: ")" answer
    answer="${answer:-$default}"
    [[ "${answer,,}" == "y" ]]
}

# =============================================================================
# Banner
# =============================================================================

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  AIIR — SIFT Platform Installer${NC}"
echo -e "${BOLD}  Applied Incident Investigation and Response${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# =============================================================================
# Phase 1: Tier Selection
# =============================================================================

header "Phase 1: Tier Selection"

if [[ -z "$MODE" ]]; then
    if $AUTO_YES; then
        MODE="recommended"
    else
        echo "  1. Quickstart    — forensic-mcp, sift-mcp, gateway (~3 min)"
        echo "  2. Recommended   — Adds RAG search + Windows triage (~30 min)"
        echo "  3. Custom        — Choose individual packages"
        echo ""
        CHOICE=$(prompt "Choose" "2")
        case "$CHOICE" in
            1) MODE="minimal" ;;
            3) MODE="custom" ;;
            *) MODE="recommended" ;;
        esac
    fi
fi

# Translate mode names for display
case "$MODE" in
    minimal)     TIER_DISPLAY="Quickstart" ;;
    recommended) TIER_DISPLAY="Recommended" ;;
    custom)      TIER_DISPLAY="Custom" ;;
esac

info "Install tier: $TIER_DISPLAY"
echo ""

# =============================================================================
# Phase 2: Prerequisites
# =============================================================================

header "Phase 2: Checking Prerequisites"

# Python 3.10+
if command -v python3 &>/dev/null; then
    PYTHON=$(command -v python3)
    PY_VERSION=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$($PYTHON -c 'import sys; print(sys.version_info.major)')
    PY_MINOR=$($PYTHON -c 'import sys; print(sys.version_info.minor)')
    if (( PY_MAJOR >= 3 && PY_MINOR >= 10 )); then
        ok "Python $PY_VERSION ($PYTHON)"
    else
        err "Python 3.10+ required (found $PY_VERSION)"
        echo "  Install: sudo apt install python3.10 python3.10-venv"
        exit 1
    fi
else
    err "Python 3 not found"
    echo "  Install: sudo apt install python3 python3-venv"
    exit 1
fi

# pip
if $PYTHON -m pip --version &>/dev/null; then
    ok "pip available"
else
    err "pip not found"
    echo "  Install: sudo apt install python3-pip"
    exit 1
fi

# venv
if $PYTHON -m venv --help &>/dev/null 2>&1; then
    ok "venv available"
else
    err "python3-venv not found"
    echo "  Install: sudo apt install python3-venv"
    exit 1
fi

# git
if command -v git &>/dev/null; then
    ok "git $(git --version | awk '{print $3}')"
else
    err "git not found"
    echo "  Install: sudo apt install git"
    exit 1
fi

# Network
if git ls-remote https://github.com/AppliedIR/sift-mcp.git HEAD &>/dev/null 2>&1; then
    ok "Network access to GitHub"
else
    warn "Cannot reach GitHub — installation requires network access"
    exit 1
fi

# =============================================================================
# Phase 3: Component Determination
# =============================================================================

# Flags for optional packages
INSTALL_RAG=false
INSTALL_TRIAGE=false
INSTALL_OPENCTI=false

case "$MODE" in
    minimal)
        # Quickstart: core only (FK, sift-common, forensic-mcp, sift-mcp, gateway)
        ;;
    recommended)
        INSTALL_RAG=true
        INSTALL_TRIAGE=true
        ;;
    custom)
        header "Select Packages"

        echo -e "  ${BOLD}Always installed:${NC}"
        echo -e "    forensic-knowledge   — Forensic tool + artifact knowledge base"
        echo -e "    sift-common          — Shared audit, logging, output utilities"
        echo -e "    forensic-mcp         — Case management, findings, discipline"
        echo -e "    sift-mcp             — Forensic tool execution on SIFT"
        echo -e "    sift-gateway         — HTTP gateway for all MCPs"
        echo ""

        echo -e "  ${BOLD}Optional packages:${NC}"
        prompt_yn "    Install forensic-rag (knowledge search — Sigma, MITRE, KAPE)?" "y" && INSTALL_RAG=true
        prompt_yn "    Install windows-triage (Windows baseline validation)?" "y" && INSTALL_TRIAGE=true
        prompt_yn "    Install opencti (threat intelligence — needs OpenCTI server)?" "n" && INSTALL_OPENCTI=true
        echo ""
        ;;
esac

# CLI flag overrides mode default
$ADD_OPENCTI && INSTALL_OPENCTI=true

# =============================================================================
# Install Directory
# =============================================================================

if [[ -n "$INSTALL_DIR_ARG" ]]; then
    INSTALL_DIR="$INSTALL_DIR_ARG"
elif [[ "$MODE" == "custom" ]]; then
    INSTALL_DIR=$(prompt "Clone directory" "$HOME/aiir/sift-mcp")
else
    INSTALL_DIR="$HOME/aiir/sift-mcp"
fi
INSTALL_DIR=$(realpath -m "$INSTALL_DIR")

# Ensure parent exists
mkdir -p "$(dirname "$INSTALL_DIR")"

# =============================================================================
# Phase 4: Clone and Install
# =============================================================================

header "Phase 4: Clone and Install"

REPO_URL="https://github.com/AppliedIR/sift-mcp.git"
INSTALL_ERRORS=0

# --- Clone or update the monorepo ---

if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Repository exists at $INSTALL_DIR — pulling latest..."
    (cd "$INSTALL_DIR" && git pull --quiet) || warn "Could not update repository"
    ok "Repository updated"
elif [[ -d "$INSTALL_DIR" ]] && [[ ! -d "$INSTALL_DIR/.git" ]]; then
    # Directory exists but is not a git repo
    err "$INSTALL_DIR exists but is not a git repository"
    echo "  Remove it or choose a different --install-dir"
    exit 1
else
    info "Cloning sift-mcp monorepo..."
    git clone --quiet "$REPO_URL" "$INSTALL_DIR"
    ok "Repository cloned to $INSTALL_DIR"
fi

# --- Create venv at repo root ---

echo ""
info "Creating virtual environment..."
VENV_DIR="$INSTALL_DIR/.venv"

if [[ ! -d "$VENV_DIR" ]]; then
    $PYTHON -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install --progress-bar off --upgrade pip >/dev/null 2>&1
ok "Virtual environment ready at $VENV_DIR"

VENV_PIP="$VENV_DIR/bin/pip"
VENV_PYTHON="$VENV_DIR/bin/python"

# --- Install packages in dependency order ---

# 1. forensic-knowledge (leaf dependency, no deps on other AIIR packages)
echo ""
info "Installing forensic-knowledge..."
$VENV_PIP install --progress-bar off -e "$INSTALL_DIR/packages/forensic-knowledge" >/dev/null
if ! "$VENV_PYTHON" -c "import forensic_knowledge" 2>/dev/null; then
    err "forensic-knowledge not importable — cannot proceed"
    exit 1
fi
ok "forensic-knowledge"

# 2. sift-common (depends on nothing AIIR-specific)
echo ""
info "Installing sift-common..."
$VENV_PIP install --progress-bar off -e "$INSTALL_DIR/packages/sift-common" >/dev/null
ok "sift-common"

# 3. forensic-mcp (depends on FK + sift-common)
echo ""
info "Installing forensic-mcp..."
$VENV_PIP install --progress-bar off -e "$INSTALL_DIR/packages/forensic-mcp" >/dev/null
ok "forensic-mcp"

# 4. sift-mcp (depends on FK + sift-common)
echo ""
info "Installing sift-mcp..."
$VENV_PIP install --progress-bar off -e "$INSTALL_DIR/packages/sift-mcp" >/dev/null
ok "sift-mcp"

# 5. sift-gateway (depends on sift-common)
echo ""
info "Installing sift-gateway..."
$VENV_PIP install --progress-bar off -e "$INSTALL_DIR/packages/sift-gateway" >/dev/null
ok "sift-gateway"

# 6. Optional: forensic-rag
if $INSTALL_RAG; then
    echo ""
    info "Installing forensic-rag..."
    $VENV_PIP install --progress-bar off -e "$INSTALL_DIR/packages/forensic-rag" >/dev/null
    ok "forensic-rag"
fi

# 7. Optional: windows-triage
if $INSTALL_TRIAGE; then
    echo ""
    info "Installing windows-triage..."
    $VENV_PIP install --progress-bar off -e "$INSTALL_DIR/packages/windows-triage" >/dev/null
    ok "windows-triage"
fi

# 8. Optional: opencti
if $INSTALL_OPENCTI; then
    echo ""
    info "Installing opencti..."
    $VENV_PIP install --progress-bar off -e "$INSTALL_DIR/packages/opencti" >/dev/null
    ok "opencti"
fi

# --- Smoke tests ---

echo ""
info "Verifying installations..."

smoke_test() {
    local name="$1" module="$2"
    if "$VENV_PYTHON" -c "import $module" 2>/dev/null; then
        ok "$name"
    else
        warn "$name import failed"
        INSTALL_ERRORS=$((INSTALL_ERRORS + 1))
    fi
}

smoke_test "forensic-knowledge" "forensic_knowledge"
smoke_test "sift-common" "sift_common"
smoke_test "forensic-mcp" "forensic_mcp"
smoke_test "sift-mcp" "sift_mcp"
smoke_test "sift-gateway" "sift_gateway"
$INSTALL_RAG     && smoke_test "forensic-rag" "rag_mcp"
$INSTALL_TRIAGE  && smoke_test "windows-triage" "windows_triage"
$INSTALL_OPENCTI && smoke_test "opencti" "opencti_mcp"

# Extended smoke test: verify server creation
if "$VENV_PYTHON" -c "from forensic_mcp.server import create_server; print('OK')" 2>/dev/null | grep -q "OK"; then
    ok "forensic-mcp server creation"
else
    warn "forensic-mcp server creation failed"
    INSTALL_ERRORS=$((INSTALL_ERRORS + 1))
fi

if (( INSTALL_ERRORS > 0 )); then
    warn "$INSTALL_ERRORS component(s) failed import — check output above"
fi

# --- Add venv to PATH ---

AIIR_BIN="$VENV_DIR/bin"
if [[ ":$PATH:" != *":$AIIR_BIN:"* ]]; then
    SHELL_RC=""
    if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc";
    elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc"; fi

    if [[ -n "$SHELL_RC" ]]; then
        if ! grep -q "$INSTALL_DIR/.venv/bin" "$SHELL_RC" 2>/dev/null; then
            echo "" >> "$SHELL_RC"
            echo "# AIIR SIFT Platform" >> "$SHELL_RC"
            echo "export PATH=\"$AIIR_BIN:\$PATH\"" >> "$SHELL_RC"
            ok "Added venv to PATH in $SHELL_RC"
        fi
    fi
    export PATH="$AIIR_BIN:$PATH"
fi

# =============================================================================
# Phase 5: Heavy Setup (tier-dependent)
# =============================================================================

if $INSTALL_RAG || $INSTALL_TRIAGE || $INSTALL_OPENCTI; then
    header "Phase 5: Post-Install Setup"
fi

# --- forensic-rag index build ---

if $INSTALL_RAG; then
    if [[ "$MODE" == "custom" ]]; then
        echo "forensic-rag needs to build a search index (~2GB disk for ML model)."
        echo "  Build now:  downloads model + builds index (takes a few minutes)"
        echo "  Skip:       build later with: $VENV_PYTHON -m rag_mcp.build"
        echo ""
        if prompt_yn "Build index now?" "y"; then
            info "Building forensic-rag index (this may take a few minutes)..."
            (cd "$INSTALL_DIR/packages/forensic-rag" && "$VENV_PYTHON" -m rag_mcp.build) && \
                ok "Index built" || warn "Index build failed — you can retry later"
        else
            info "Skipping index build."
        fi
    else
        echo ""
        info "forensic-rag: index will build on first use (~2 min, ~2GB download)"
        info "  Or build now: $VENV_PYTHON -m rag_mcp.build"
    fi
fi

# --- windows-triage database setup ---

if $INSTALL_TRIAGE; then
    if [[ "$MODE" == "custom" ]]; then
        echo ""
        echo "windows-triage needs Windows baseline databases."
        echo "  Set up now: clone data repos + import (takes 30-60 minutes)"
        echo "  Skip:       see $INSTALL_DIR/packages/windows-triage/SETUP.md"
        echo ""
        if prompt_yn "Set up databases now?" "n"; then
            WT_DIR="$INSTALL_DIR/packages/windows-triage"
            DATA_DIR="$WT_DIR/data/sources"
            mkdir -p "$DATA_DIR"

            info "Cloning VanillaWindowsReference..."
            if [[ ! -d "$DATA_DIR/VanillaWindowsReference" ]]; then
                git clone --quiet https://github.com/AndrewRathbun/VanillaWindowsReference.git "$DATA_DIR/VanillaWindowsReference"
            fi

            info "Cloning LOLBAS, LOLDrivers, HijackLibs..."
            for repo in LOLBAS LOLDrivers HijackLibs; do
                if [[ ! -d "$DATA_DIR/$repo" ]]; then
                    git clone --quiet "https://github.com/LOLBAS-Project/$repo.git" "$DATA_DIR/$repo" 2>/dev/null || \
                    git clone --quiet "https://github.com/magicsword-io/$repo.git" "$DATA_DIR/$repo" 2>/dev/null || \
                    warn "Could not clone $repo"
                fi
            done

            info "Initializing databases and importing..."
            (cd "$WT_DIR" && "$VENV_PYTHON" scripts/init_databases.py && \
                "$VENV_PYTHON" scripts/import_all.py --skip-registry) && \
                ok "Databases imported" || warn "Database import had issues — see output above"
        else
            info "Skipping database setup."
        fi
    else
        echo ""
        info "windows-triage: databases can be imported later"
        info "  See: $INSTALL_DIR/packages/windows-triage/SETUP.md"
    fi
fi

# --- OpenCTI credential wizard ---

OPENCTI_URL=""
OPENCTI_TOKEN=""

if $INSTALL_OPENCTI; then
    echo ""
    echo "opencti needs an OpenCTI server URL and API token."
    echo ""
    OPENCTI_URL=$(prompt "OpenCTI URL (e.g., https://opencti.example.com)" "")
    if [[ -n "$OPENCTI_URL" ]]; then
        read -rsp "OpenCTI API Token: " OPENCTI_TOKEN
        echo ""

        # Test connectivity
        if OPENCTI_URL="$OPENCTI_URL" OPENCTI_TOKEN="$OPENCTI_TOKEN" \
            "$VENV_PYTHON" -c "
import os
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.client import OpenCTIClient
c = OpenCTIClient(Config(
    opencti_url=os.environ['OPENCTI_URL'],
    opencti_token=SecretStr(os.environ['OPENCTI_TOKEN']),
))
tools = c.server.list_tools()
print('OK' if tools else 'FAIL')
" 2>/dev/null | grep -q "OK"; then
            ok "OpenCTI connection verified"
        else
            warn "Could not connect to OpenCTI — check URL and token"
        fi
    else
        info "Skipping. Set OPENCTI_URL and OPENCTI_TOKEN in gateway.yaml later."
        OPENCTI_URL=""
        OPENCTI_TOKEN=""
    fi
fi

# =============================================================================
# Phase 6: Examiner Identity
# =============================================================================

header "Phase 6: Examiner Identity"

echo "Your examiner name identifies your work in case files and audit trails."
echo "Use a short slug (e.g., steve, jane, analyst1)."
echo ""

if [[ -n "$EXAMINER_ARG" ]]; then
    EXAMINER="$EXAMINER_ARG"
else
    EXAMINER=$(prompt "Examiner name" "$(whoami)")
fi
EXAMINER=$(echo "$EXAMINER" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')

if [[ -z "$EXAMINER" ]]; then
    EXAMINER=$(whoami | tr '[:upper:]' '[:lower:]')
fi

# Save to config (update existing examiner line or create fresh)
mkdir -p "$HOME/.aiir"
CONFIG_FILE="$HOME/.aiir/config.yaml"
if [[ -f "$CONFIG_FILE" ]] && grep -q "^examiner:" "$CONFIG_FILE" 2>/dev/null; then
    sed -i "s/^examiner:.*$/examiner: $EXAMINER/" "$CONFIG_FILE"
else
    echo "examiner: $EXAMINER" >> "$CONFIG_FILE"
fi
ok "Saved examiner identity: $EXAMINER"

# Add or update AIIR_EXAMINER in shell profile
SHELL_RC=""
if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc";
elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc"; fi

if [[ -n "$SHELL_RC" ]]; then
    if grep -q "AIIR_EXAMINER" "$SHELL_RC" 2>/dev/null; then
        sed -i "s/^export AIIR_EXAMINER=.*$/export AIIR_EXAMINER=\"$EXAMINER\"/" "$SHELL_RC"
        ok "Updated AIIR_EXAMINER in $SHELL_RC"
    else
        echo "export AIIR_EXAMINER=\"$EXAMINER\"" >> "$SHELL_RC"
        ok "Added AIIR_EXAMINER to $SHELL_RC"
    fi
fi
export AIIR_EXAMINER="$EXAMINER"

# =============================================================================
# Phase 6b: aiir CLI
# =============================================================================

echo ""
AIIR_CLI_DIR="$HOME/aiir/aiir-cli"
AIIR_CLI=""
AIIR_CLI_INSTALLED=false

install_aiir_cli() {
    local cli_dir="$1"

    if [[ -d "$cli_dir/.git" ]]; then
        info "aiir CLI repo exists at $cli_dir — pulling latest..."
        (cd "$cli_dir" && git pull --quiet) || warn "Could not update aiir CLI"
    else
        info "Cloning aiir CLI..."
        mkdir -p "$(dirname "$cli_dir")"
        git clone --quiet "https://github.com/AppliedIR/aiir.git" "$cli_dir"
    fi

    info "Installing aiir CLI..."
    $VENV_PIP install --progress-bar off -e "$cli_dir" >/dev/null

    if "$VENV_PYTHON" -c "import aiir_cli" 2>/dev/null; then
        AIIR_CLI="$VENV_DIR/bin/aiir"
        AIIR_CLI_INSTALLED=true
        ok "aiir CLI installed"
    else
        warn "aiir CLI import failed"
    fi
}

# Check if aiir CLI is already importable in the venv
if "$VENV_PYTHON" -c "import aiir_cli" 2>/dev/null; then
    AIIR_CLI="$VENV_DIR/bin/aiir"
    AIIR_CLI_INSTALLED=true
    ok "aiir CLI already available"
elif $AUTO_YES; then
    install_aiir_cli "$AIIR_CLI_DIR"
elif prompt_yn "Install aiir CLI (human review, approval, configuration)?" "y"; then
    CLI_DIR=$(prompt "aiir CLI directory" "$AIIR_CLI_DIR")
    install_aiir_cli "$CLI_DIR"
else
    echo ""
    echo "  To install later:"
    echo "    git clone https://github.com/AppliedIR/aiir.git $AIIR_CLI_DIR"
    echo "    $VENV_PIP install -e $AIIR_CLI_DIR"
fi

# =============================================================================
# Phase 7: Gateway Configuration and Startup
# =============================================================================

header "Phase 7: Gateway Setup"

GATEWAY_CONFIG="$INSTALL_DIR/config/gateway.yaml"
GATEWAY_PORT=4508

# Generate gateway.yaml with all installed packages as backends
info "Generating gateway configuration..."
mkdir -p "$(dirname "$GATEWAY_CONFIG")"

export _INST_OPENCTI_URL="${OPENCTI_URL:-}"
export _INST_OPENCTI_TOKEN="${OPENCTI_TOKEN:-}"

"$VENV_PYTHON" -c "
import yaml, os

config = {
    'gateway': {
        'host': '127.0.0.1',
        'port': $GATEWAY_PORT,
        'log_level': 'INFO',
    },
    'backends': {},
}

# All backends use the venv python
venv_python = '$VENV_DIR/bin/python'

# Core backends (always installed)
backends = [
    ('forensic-mcp', 'forensic_mcp'),
    ('sift-mcp', 'sift_mcp'),
]

# Optional backends
if '$INSTALL_RAG' == 'true':
    backends.append(('forensic-rag', 'rag_mcp'))
if '$INSTALL_TRIAGE' == 'true':
    backends.append(('windows-triage', 'windows_triage'))
if '$INSTALL_OPENCTI' == 'true':
    backends.append(('opencti', 'opencti_mcp'))

for name, module in backends:
    entry = {
        'type': 'stdio',
        'command': venv_python,
        'args': ['-m', module],
        'env': {
            'AIIR_CASE_DIR': '\${AIIR_CASE_DIR}',
            'AIIR_EXAMINER': '\${AIIR_EXAMINER}',
        },
        'enabled': True,
    }
    if name == 'opencti':
        url = os.environ.get('_INST_OPENCTI_URL', '')
        token = os.environ.get('_INST_OPENCTI_TOKEN', '')
        if url:
            entry['env']['OPENCTI_URL'] = url
            entry['env']['OPENCTI_TOKEN'] = token
        else:
            entry['env']['OPENCTI_URL'] = '\${OPENCTI_URL}'
            entry['env']['OPENCTI_TOKEN'] = '\${OPENCTI_TOKEN}'
    config['backends'][name] = entry

with open('$GATEWAY_CONFIG', 'w') as f:
    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
" 2>/dev/null

chmod 600 "$GATEWAY_CONFIG"
ok "Generated: $GATEWAY_CONFIG"

# Generate startup script
GATEWAY_START="$INSTALL_DIR/start-gateway.sh"
cat > "$GATEWAY_START" << SCRIPT
#!/usr/bin/env bash
# Start AIIR SIFT Gateway
export AIIR_EXAMINER="${EXAMINER}"
exec "$VENV_DIR/bin/python" -m sift_gateway --config "$GATEWAY_CONFIG"
SCRIPT
chmod +x "$GATEWAY_START"

# Start gateway to verify it works
info "Starting gateway on port $GATEWAY_PORT..."
"$VENV_DIR/bin/python" -m sift_gateway --config "$GATEWAY_CONFIG" &
GATEWAY_PID=$!
sleep 2

if kill -0 "$GATEWAY_PID" 2>/dev/null; then
    if curl -sf "http://127.0.0.1:$GATEWAY_PORT/health" &>/dev/null; then
        ok "Gateway running on port $GATEWAY_PORT"
    else
        warn "Gateway started but health check failed"
    fi
else
    warn "Gateway failed to start — check $GATEWAY_CONFIG"
    GATEWAY_PID=""
fi

# Determine auto-start behavior
AUTOSTART=true
if $MANUAL_START; then
    AUTOSTART=false
elif [[ "$MODE" == "custom" ]]; then
    echo ""
    echo "  1. Auto-start at boot (systemd service)"
    echo "  2. Manual start (use start-gateway.sh)"
    echo ""
    START_CHOICE=$(prompt "Choose" "1")
    [[ "$START_CHOICE" != "1" ]] && AUTOSTART=false
fi

if $AUTOSTART; then
    # Install systemd user service
    SYSTEMD_DIR="$HOME/.config/systemd/user"
    mkdir -p "$SYSTEMD_DIR"

    cat > "$SYSTEMD_DIR/aiir-gateway.service" << SERVICE
[Unit]
Description=AIIR SIFT Gateway
After=network.target

[Service]
ExecStart=$VENV_DIR/bin/python -m sift_gateway --config $GATEWAY_CONFIG
Environment=AIIR_EXAMINER=$EXAMINER
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
SERVICE

    # Stop the test process — systemd will manage it now
    if [[ -n "${GATEWAY_PID:-}" ]]; then
        kill "$GATEWAY_PID" 2>/dev/null || true
        wait "$GATEWAY_PID" 2>/dev/null || true
    fi

    systemctl --user daemon-reload
    systemctl --user enable aiir-gateway.service 2>/dev/null && \
        ok "Systemd service enabled (auto-start at login)"
    systemctl --user start aiir-gateway.service 2>/dev/null && \
        ok "Gateway started via systemd" || \
        warn "Could not start via systemd — use $GATEWAY_START manually"

    # Enable lingering so service runs without active login session
    if command -v loginctl &>/dev/null; then
        loginctl enable-linger "$(whoami)" 2>/dev/null && \
            ok "Linger enabled (gateway runs without active login)" || true
    fi
else
    ok "Manual start: $GATEWAY_START"
    if [[ -n "${GATEWAY_PID:-}" ]]; then
        info "Gateway is running now (PID $GATEWAY_PID) — will stop on logout"
    fi
fi

# =============================================================================
# Team Deployment (Custom mode only)
# =============================================================================

if [[ "$MODE" == "custom" ]]; then
    echo ""
    if prompt_yn "Set up for team collaboration?" "n"; then
        header "Team Deployment"

        CASE_DIR=$(prompt "Shared case directory" "/cases")

        echo ""
        echo "To share cases with other examiners, export the case directory via NFS or Samba."
        echo ""
        echo -e "${BOLD}NFS:${NC}"
        echo "  Add to /etc/exports:"
        echo "    $CASE_DIR *(rw,sync,no_subtree_check,no_root_squash)"
        echo "  Then run: sudo exportfs -ra"
        echo ""
        echo -e "${BOLD}Samba:${NC}"
        echo "  Add to /etc/samba/smb.conf:"
        echo "    [$(basename "$CASE_DIR")]"
        echo "        path = $CASE_DIR"
        echo "        browsable = yes"
        echo "        writable = yes"
        echo "        valid users = @forensics"
        echo "  Then run: sudo systemctl restart smbd"
        echo ""

        # Test connectivity to Windows workstation
        if prompt_yn "Test connectivity to a Windows workstation?" "n"; then
            WIN_HOST=$(prompt "Windows workstation IP or hostname" "")
            if [[ -n "$WIN_HOST" ]]; then
                WIN_PORT=$(prompt "wintools-mcp port" "4624")
                if curl -sf "http://$WIN_HOST:$WIN_PORT/health" &>/dev/null; then
                    ok "Connected to wintools-mcp at $WIN_HOST:$WIN_PORT"
                else
                    warn "Cannot reach $WIN_HOST:$WIN_PORT — ensure wintools-mcp is running"
                fi
            fi
        fi
    fi
fi

# =============================================================================
# LLM Client Configuration
# =============================================================================

CLIENT_CONFIGURED=false

if $REMOTE_MODE; then
    # --remote: skip local client config, print instructions for remote machine
    header "Remote Client Instructions"
    echo "To configure your LLM client on your remote machine:"
    echo ""
    echo "  pip install aiir"
    echo "  aiir setup client --sift=http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'THIS_IP'):$GATEWAY_PORT"
    echo ""
    echo "Replace the IP with this machine's address if auto-detect is wrong."
elif $AIIR_CLI_INSTALLED; then
    if [[ -n "$CLIENT_ARG" ]]; then
        # --client=X: explicit client choice
        header "LLM Client Configuration"
        "$AIIR_CLI" setup client \
            --sift="http://127.0.0.1:$GATEWAY_PORT" \
            --client="$CLIENT_ARG" \
            --examiner="$EXAMINER" \
            -y && CLIENT_CONFIGURED=true || warn "Client configuration failed"
    elif $AUTO_YES; then
        # Non-interactive without --client: skip (require --client for unattended)
        echo ""
        info "No --client specified — skipping LLM client configuration"
        echo "  Configure later: aiir setup client --sift=http://127.0.0.1:$GATEWAY_PORT"
    else
        # Interactive: always ask
        header "LLM Client Configuration"
        if prompt_yn "Working from this machine? Configure LLM client now?" "y"; then
            "$AIIR_CLI" setup client \
                --sift="http://127.0.0.1:$GATEWAY_PORT" \
                --examiner="$EXAMINER" && CLIENT_CONFIGURED=true || warn "Client configuration failed"
        else
            echo ""
            echo "To configure your LLM client on your remote machine:"
            echo ""
            echo "  pip install aiir"
            echo "  aiir setup client --sift=http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'THIS_IP'):$GATEWAY_PORT"
            echo ""
        fi
    fi
else
    # No aiir CLI available
    if ! $REMOTE_MODE; then
        echo ""
        info "aiir CLI not installed — skipping client configuration"
        echo "  Install aiir CLI, then run: aiir setup client --sift=http://127.0.0.1:$GATEWAY_PORT"
    fi
fi

# =============================================================================
# Summary
# =============================================================================

header "Installation Complete"

echo "Installed packages:"
ok "forensic-knowledge"
ok "sift-common"
ok "forensic-mcp"
ok "sift-mcp"
ok "sift-gateway (port $GATEWAY_PORT)"
$INSTALL_RAG     && ok "forensic-rag"
$INSTALL_TRIAGE  && ok "windows-triage"
$INSTALL_OPENCTI && ok "opencti"
$AIIR_CLI_INSTALLED && ok "aiir CLI"

echo ""
echo "Examiner:    $EXAMINER"
echo "Install dir: $INSTALL_DIR"
echo "Venv:        $VENV_DIR"
echo "Gateway:     http://127.0.0.1:$GATEWAY_PORT"
if $AUTOSTART; then
    echo "Auto-start:  enabled (systemd)"
else
    echo "Start:       $GATEWAY_START"
fi
if $CLIENT_CONFIGURED; then
    echo "LLM client:  configured"
fi
echo ""

echo "Next steps:"
STEP=1
echo "  $STEP. Restart your shell (or: source ${SHELL_RC:-~/.bashrc})"
if ! $CLIENT_CONFIGURED && ! $REMOTE_MODE; then
    STEP=$((STEP + 1))
    echo "  $STEP. Configure your LLM client:  aiir setup client"
fi
if ! $AIIR_CLI_INSTALLED; then
    STEP=$((STEP + 1))
    echo "  $STEP. Install aiir CLI:"
    echo "     git clone https://github.com/AppliedIR/aiir.git $AIIR_CLI_DIR"
    echo "     $VENV_PIP install -e $AIIR_CLI_DIR"
fi
STEP=$((STEP + 1))
echo "  $STEP. Verify installation:         aiir setup test"

if $INSTALL_RAG && [[ "$MODE" != "custom" ]]; then
    echo ""
    echo "Deferred setup:"
    echo "  RAG index:   $VENV_PYTHON -m rag_mcp.build"
fi
if $INSTALL_TRIAGE && [[ "$MODE" != "custom" ]]; then
    echo "  Triage DBs:  see $INSTALL_DIR/packages/windows-triage/SETUP.md"
fi

echo ""
echo -e "${BOLD}Documentation:${NC} $INSTALL_DIR/AGENTS.md"
echo ""
