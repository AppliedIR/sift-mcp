#!/usr/bin/env bash
#
# sift-install.sh — AIIR SIFT Platform Installer
#
# Installs MCP servers, the gateway, and all dependencies from the sift-mcp
# monorepo into a shared virtual environment at ~/.aiir/venv/.
#
# Three install tiers:
#   Quick        — Core platform only (~3 min)
#   Recommended  — Adds RAG search + Windows triage (~30 min with index build)
#   Custom       — Choose individual packages (+ OpenCTI)
#
# Usage:
#   ./sift-install.sh                    # Interactive (default: Recommended)
#   ./sift-install.sh --quick -y         # Unattended quick install
#   ./sift-install.sh --custom           # Interactive package picker
#   ./sift-install.sh --remote           # Enable TLS + bind 0.0.0.0
#   ./sift-install.sh --manual-start     # Skip auto-start/systemd
#   ./sift-install.sh -h                 # Help
#
set -euo pipefail

# =============================================================================
# Parse Arguments
# =============================================================================

AUTO_YES=false
MODE=""  # quick, recommended, custom, or "" (show menu)
REMOTE_MODE=false
INSTALL_DIR=""
VENV_DIR=""
GATEWAY_PORT=4508
MANUAL_START=false

for arg in "$@"; do
    case "$arg" in
        -y|--yes)          AUTO_YES=true ;;
        --quick)           MODE="quick" ;;
        --recommended)     MODE="recommended" ;;
        --custom)          MODE="custom" ;;
        --remote)          REMOTE_MODE=true ;;
        --manual-start)    MANUAL_START=true ;;
        --install-dir=*)   INSTALL_DIR="${arg#*=}" ;;
        --venv=*)          VENV_DIR="${arg#*=}" ;;
        --port=*)          GATEWAY_PORT="${arg#*=}" ;;
        -h|--help)
            echo "Usage: sift-install.sh [OPTIONS]"
            echo ""
            echo "Tiers (pick one):"
            echo "  --quick         Core platform only (~3 min)"
            echo "  --recommended   Core + RAG + Windows triage (default)"
            echo "  --custom        Interactive package picker"
            echo ""
            echo "Options:"
            echo "  --remote          Enable TLS + bind 0.0.0.0 (for remote clients)"
            echo "  --install-dir=X   Override source clone dir (default: ~/.aiir/src/sift-mcp)"
            echo "  --venv=X          Override venv path (default: ~/.aiir/venv)"
            echo "  --port=N          Override gateway port (default: 4508)"
            echo "  --manual-start    Skip auto-start/systemd"
            echo "  -y, --yes         Accept all defaults (non-interactive)"
            echo "  -h, --help        Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (use -h for help)"
            exit 1
            ;;
    esac
done

# Defaults
[[ -z "$INSTALL_DIR" ]] && INSTALL_DIR="$HOME/.aiir/src/sift-mcp"
[[ -z "$VENV_DIR" ]] && VENV_DIR="$HOME/.aiir/venv"

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
echo -e "${BOLD}  Artificial Intelligence Incident Response${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# =============================================================================
# Platform Check
# =============================================================================

PLATFORM="$(uname -s)"
if [[ "$PLATFORM" != "Linux" ]]; then
    if [[ "$PLATFORM" == "Darwin" ]]; then
        warn "macOS detected. This installer targets Linux (SIFT Workstation)."
        warn "Homebrew python3 + venv should work, but systemd will not."
    else
        err "Unsupported platform: $PLATFORM"
        exit 1
    fi
fi

# =============================================================================
# Phase 1: Prerequisites
# =============================================================================

header "Checking Prerequisites"

# Python 3.11+
if command -v python3 &>/dev/null; then
    PYTHON=$(command -v python3)
    PY_VERSION=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$($PYTHON -c 'import sys; print(sys.version_info.major)')
    PY_MINOR=$($PYTHON -c 'import sys; print(sys.version_info.minor)')
    if (( PY_MAJOR > 3 || (PY_MAJOR == 3 && PY_MINOR >= 11) )); then
        ok "Python $PY_VERSION ($PYTHON)"
    else
        err "Python 3.11+ required (found $PY_VERSION)"
        echo "  Install: sudo apt install python3.11 python3.11-venv"
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

# curl (used for health checks and network test)
if command -v curl &>/dev/null; then
    ok "curl available"
else
    err "curl not found"
    echo "  Install: sudo apt install curl"
    exit 1
fi

# openssl (required for --remote)
if $REMOTE_MODE; then
    if command -v openssl &>/dev/null; then
        ok "openssl available (needed for TLS)"
    else
        err "openssl not found (required for --remote TLS)"
        echo "  Install: sudo apt install openssl"
        exit 1
    fi
fi

# Network check
if curl -sf --max-time 10 "https://github.com" &>/dev/null; then
    ok "Network access to GitHub"
elif git ls-remote https://github.com/AppliedIR/sift-mcp.git HEAD &>/dev/null 2>&1; then
    ok "Network access to GitHub"
else
    warn "Cannot reach GitHub. Installation requires network access."
    exit 1
fi

# =============================================================================
# Phase 2: Tier Selection
# =============================================================================

header "Tier Selection"

if [[ -z "$MODE" ]]; then
    if $AUTO_YES; then
        MODE="recommended"
    else
        echo "  1. Quick        — forensic-mcp, sift-mcp, gateway (~3 min)"
        echo "  2. Recommended  — Adds RAG search + Windows triage (~30 min)"
        echo "  3. Custom       — Choose individual packages"
        echo ""
        CHOICE=$(prompt "Choose" "2")
        case "$CHOICE" in
            1) MODE="quick" ;;
            3) MODE="custom" ;;
            *) MODE="recommended" ;;
        esac
    fi
fi

case "$MODE" in
    quick)       TIER_DISPLAY="Quick" ;;
    recommended) TIER_DISPLAY="Recommended" ;;
    custom)      TIER_DISPLAY="Custom" ;;
esac

info "Install tier: $TIER_DISPLAY"

# Flags for optional packages
INSTALL_RAG=false
INSTALL_TRIAGE=false
INSTALL_OPENCTI=false

case "$MODE" in
    quick)
        # Core only
        ;;
    recommended)
        INSTALL_RAG=true
        INSTALL_TRIAGE=true
        ;;
    custom)
        echo ""
        echo -e "  ${BOLD}Always installed:${NC}"
        echo "    forensic-knowledge   — Forensic tool + artifact knowledge base"
        echo "    sift-common          — Shared audit, logging, output utilities"
        echo "    forensic-mcp         — Case management, findings, discipline"
        echo "    sift-mcp             — Forensic tool execution on SIFT"
        echo "    sift-gateway         — HTTP gateway for all MCPs"
        echo ""
        echo -e "  ${BOLD}Optional packages:${NC}"
        prompt_yn "    Install forensic-rag (knowledge search — Sigma, MITRE, KAPE)?" "y" && INSTALL_RAG=true
        prompt_yn "    Install windows-triage (Windows baseline validation)?" "y" && INSTALL_TRIAGE=true
        prompt_yn "    Install opencti (threat intelligence — needs OpenCTI server)?" "n" && INSTALL_OPENCTI=true
        echo ""
        ;;
esac

# =============================================================================
# Phase 3: Clone Repository
# =============================================================================

header "Source Repository"

REPO_URL="https://github.com/AppliedIR/sift-mcp.git"
INSTALL_DIR=$(realpath -m "$INSTALL_DIR")
mkdir -p "$(dirname "$INSTALL_DIR")"

if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Repository exists at $INSTALL_DIR. Pulling latest..."
    if (cd "$INSTALL_DIR" && git pull --quiet); then
        ok "Repository updated"
    else
        warn "Could not update repository. Continuing with existing code."
    fi
elif [[ -d "$INSTALL_DIR" ]] && [[ ! -d "$INSTALL_DIR/.git" ]]; then
    err "$INSTALL_DIR exists but is not a git repository"
    echo "  Remove it or choose a different --install-dir"
    exit 1
else
    info "Cloning sift-mcp monorepo..."
    if ! git clone --quiet "$REPO_URL" "$INSTALL_DIR"; then
        err "Failed to clone sift-mcp repository"
        echo "  Check network access and try again"
        exit 1
    fi
    ok "Repository cloned to $INSTALL_DIR"
fi

# =============================================================================
# Phase 4: Virtual Environment + Package Installation
# =============================================================================

header "Installing Packages"

VENV_DIR=$(realpath -m "$VENV_DIR")
mkdir -p "$(dirname "$VENV_DIR")"

if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment at $VENV_DIR..."
    if ! $PYTHON -m venv "$VENV_DIR"; then
        err "Failed to create virtual environment"
        echo "  Ensure python3-venv is installed: sudo apt install python3-venv"
        exit 1
    fi
fi

if [[ ! -f "$VENV_DIR/bin/python" ]]; then
    err "Virtual environment created but python not found at $VENV_DIR/bin/python"
    exit 1
fi

"$VENV_DIR/bin/pip" install --progress-bar off --upgrade pip >/dev/null 2>&1 || true
ok "Virtual environment ready at $VENV_DIR"

VENV_PIP="$VENV_DIR/bin/pip"
VENV_PYTHON="$VENV_DIR/bin/python"

# Helper: install a package with error handling
install_pkg() {
    local name="$1" path="$2"
    echo ""
    info "Installing $name..."
    if ! $VENV_PIP install --progress-bar off -e "$path" >/dev/null; then
        err "Failed to install $name"
        echo "  Check pip output: $VENV_PIP install -e $path"
        return 1
    fi
    ok "$name installed"
}

INSTALL_ERRORS=0

# 1. forensic-knowledge (no deps)
install_pkg "forensic-knowledge" "$INSTALL_DIR/packages/forensic-knowledge" || exit 1

# 2. sift-common (no deps)
install_pkg "sift-common" "$INSTALL_DIR/packages/sift-common" || exit 1

# 3. forensic-mcp (depends on 1+2)
install_pkg "forensic-mcp" "$INSTALL_DIR/packages/forensic-mcp" || exit 1

# 4. sift-mcp (depends on 1+2)
install_pkg "sift-mcp" "$INSTALL_DIR/packages/sift-mcp" || exit 1

# 5. sift-gateway (depends on 2)
install_pkg "sift-gateway" "$INSTALL_DIR/packages/sift-gateway" || exit 1

# 6. windows-triage-mcp (optional, depends on 2)
if $INSTALL_TRIAGE; then
    install_pkg "windows-triage-mcp" "$INSTALL_DIR/packages/windows-triage" || {
        warn "windows-triage install failed. Continuing without it."
        INSTALL_TRIAGE=false
    }
fi

# 7. rag-mcp (optional, depends on 2)
if $INSTALL_RAG; then
    install_pkg "rag-mcp" "$INSTALL_DIR/packages/forensic-rag" || {
        warn "forensic-rag install failed. Continuing without it."
        INSTALL_RAG=false
    }
fi

# 8. opencti-mcp (optional, depends on 2)
if $INSTALL_OPENCTI; then
    install_pkg "opencti-mcp" "$INSTALL_DIR/packages/opencti" || {
        warn "opencti install failed. Continuing without it."
        INSTALL_OPENCTI=false
    }
fi

# =============================================================================
# Phase 5: Smoke Tests
# =============================================================================

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
smoke_test "sift-common"        "sift_common"
smoke_test "forensic-mcp"       "forensic_mcp"
smoke_test "sift-mcp"           "sift_mcp"
smoke_test "sift-gateway"       "sift_gateway"
$INSTALL_TRIAGE  && smoke_test "windows-triage-mcp" "windows_triage"
$INSTALL_RAG     && smoke_test "rag-mcp"            "rag_mcp"
$INSTALL_OPENCTI && smoke_test "opencti-mcp"        "opencti_mcp"

if (( INSTALL_ERRORS > 0 )); then
    warn "$INSTALL_ERRORS component(s) failed import. Check output above."
fi

# =============================================================================
# Phase 5b: Post-Install Setup (data downloads, index builds)
# =============================================================================

if $INSTALL_RAG || $INSTALL_TRIAGE; then
    header "Post-Install Setup"
fi

# --- forensic-rag index build ---
if $INSTALL_RAG; then
    if ! $AUTO_YES; then
        echo "forensic-rag needs to build a search index (~2GB disk for ML model)."
        echo "  Build now:  downloads model + builds index (takes a few minutes)"
        echo "  Skip:       build later with: $VENV_PYTHON -m rag_mcp.build"
        echo ""
        if prompt_yn "Build index now?" "y"; then
            info "Building forensic-rag index (this may take a few minutes)..."
            "$VENV_PYTHON" -m rag_mcp.build && \
                ok "Index built" || warn "Index build failed. You can retry later."
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
    WT_DIR="$INSTALL_DIR/packages/windows-triage"
    DB_DIR="$WT_DIR/data"

    # Ensure zstandard is available for the download module
    "$VENV_PYTHON" -m pip install --quiet zstandard 2>/dev/null || true

    if ! $AUTO_YES; then
        echo ""
        echo "windows-triage needs Windows baseline databases."
        echo "  1. Download pre-built databases (recommended, ~1.2 GB download)"
        echo "  2. Build from source (clones 4 repos, 30-60 minutes)"
        echo "  3. Skip (set up later)"
        echo ""
        DB_CHOICE=$(prompt "Database setup [1/2/3]" "1")
    else
        DB_CHOICE="1"   # -y mode: auto-download (was: skip)
    fi

    case "$DB_CHOICE" in
        1)
            info "Downloading pre-built databases..."
            "$VENV_PYTHON" -m windows_triage.scripts.download_databases \
                --dest "$DB_DIR" && \
                ok "Databases downloaded and verified" || {
                warn "Download failed. You can retry later:"
                warn "  $VENV_PYTHON -m windows_triage.scripts.download_databases --dest $DB_DIR"
            }
            ;;
        2)
            info "Building databases from source..."
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
                ok "Databases imported" || warn "Database import had issues. See output above."
            ;;
        3|*)
            info "Skipping database setup."
            info "  Download later: $VENV_PYTHON -m windows_triage.scripts.download_databases --dest $DB_DIR"
            ;;
    esac
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
    else
        info "Skipping. Set OPENCTI_URL and OPENCTI_TOKEN in gateway.yaml later."
        OPENCTI_URL=""
        OPENCTI_TOKEN=""
    fi
fi

# =============================================================================
# Phase 6: Generate Bearer Token
# =============================================================================

echo ""
info "Generating gateway bearer token..."

# Preserve existing token if gateway.yaml already has one
GATEWAY_CONFIG="$HOME/.aiir/gateway.yaml"
EXISTING_TOKEN=""
if [[ -f "$GATEWAY_CONFIG" ]]; then
    EXISTING_TOKEN=$("$VENV_PYTHON" -c "
import yaml, sys
try:
    with open('$GATEWAY_CONFIG') as f:
        cfg = yaml.safe_load(f) or {}
    keys = cfg.get('api_keys', {}) or {}
    if keys:
        print(next(iter(keys)))
except Exception:
    pass
" 2>/dev/null || true)
fi

if [[ -n "$EXISTING_TOKEN" ]]; then
    TOKEN="$EXISTING_TOKEN"
    ok "Reusing existing token from gateway.yaml"
else
    TOKEN=$("$VENV_PYTHON" -c "from sift_gateway.token_gen import generate_gateway_token; print(generate_gateway_token())")
    ok "Token generated"
fi

# =============================================================================
# Phase 7: TLS Certificates (--remote only)
# =============================================================================

if $REMOTE_MODE; then
    header "TLS Certificate Generation"

    TLS_DIR="$HOME/.aiir/tls"
    mkdir -p "$TLS_DIR"

    # Determine SAN entries
    HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    HOST_NAME=$(hostname 2>/dev/null || echo "localhost")

    SAN="IP:$HOST_IP,DNS:$HOST_NAME,DNS:localhost,IP:127.0.0.1"

    if [[ -f "$TLS_DIR/ca-cert.pem" ]] && [[ -f "$TLS_DIR/gateway-cert.pem" ]]; then
        info "Existing TLS certificates found. Preserving."
        echo "  Delete $TLS_DIR/ and re-run to regenerate."
    else
        info "Generating CA certificate (10-year validity)..."
        openssl genrsa -out "$TLS_DIR/ca-key.pem" 4096 2>/dev/null
        openssl req -new -x509 -key "$TLS_DIR/ca-key.pem" \
            -out "$TLS_DIR/ca-cert.pem" \
            -days 3650 \
            -subj "/CN=AIIR Gateway CA" 2>/dev/null
        ok "CA certificate generated"

        info "Generating gateway certificate (1-year validity)..."
        openssl genrsa -out "$TLS_DIR/gateway-key.pem" 2048 2>/dev/null

        # Create CSR with SAN
        openssl req -new \
            -key "$TLS_DIR/gateway-key.pem" \
            -out "$TLS_DIR/gateway.csr" \
            -subj "/CN=AIIR Gateway" \
            -addext "subjectAltName=$SAN" 2>/dev/null

        # Sign with CA
        openssl x509 -req \
            -in "$TLS_DIR/gateway.csr" \
            -CA "$TLS_DIR/ca-cert.pem" \
            -CAkey "$TLS_DIR/ca-key.pem" \
            -CAcreateserial \
            -out "$TLS_DIR/gateway-cert.pem" \
            -days 365 \
            -copy_extensions copyall 2>/dev/null
        ok "Gateway certificate generated (SAN: $SAN)"

        # Clean up CSR
        rm -f "$TLS_DIR/gateway.csr" "$TLS_DIR/ca-cert.srl"

        # Restrict key permissions
        chmod 600 "$TLS_DIR/ca-key.pem" "$TLS_DIR/gateway-key.pem"
        chmod 644 "$TLS_DIR/ca-cert.pem" "$TLS_DIR/gateway-cert.pem"
    fi
fi

# =============================================================================
# Phase 8: Gateway Configuration
# =============================================================================

header "Gateway Configuration"

mkdir -p "$HOME/.aiir"

if [[ -f "$GATEWAY_CONFIG" ]]; then
    info "Existing gateway config found. Preserving: $GATEWAY_CONFIG"
    echo "  Delete $GATEWAY_CONFIG and re-run to regenerate."
else
    info "Generating gateway configuration..."

    # Build config with Python for proper YAML output
    "$VENV_PYTHON" << PYEOF
import yaml, os

venv_python = "$VENV_PYTHON"
remote = "$REMOTE_MODE" == "true"
token = "$TOKEN"
port = int("$GATEWAY_PORT")

config = {
    "gateway": {
        "host": "0.0.0.0" if remote else "127.0.0.1",
        "port": port,
        "log_level": "INFO",
    },
    "api_keys": {
        token: {
            "examiner": "default",
            "role": "lead",
        },
    },
    "backends": {},
}

if remote:
    config["gateway"]["tls"] = {
        "certfile": os.path.expanduser("~/.aiir/tls/gateway-cert.pem"),
        "keyfile": os.path.expanduser("~/.aiir/tls/gateway-key.pem"),
    }

# Core backends (always installed)
core_backends = [
    ("forensic-mcp", "forensic_mcp"),
    ("sift-mcp", "sift_mcp"),
]

# Optional backends
optional = []
if "$INSTALL_TRIAGE" == "true":
    optional.append(("windows-triage-mcp", "windows_triage"))
if "$INSTALL_RAG" == "true":
    optional.append(("forensic-rag-mcp", "rag_mcp"))
if "$INSTALL_OPENCTI" == "true":
    optional.append(("opencti-mcp", "opencti_mcp"))

for name, module in core_backends + optional:
    entry = {
        "type": "stdio",
        "command": venv_python,
        "args": ["-m", module],
        "env": {
            "AIIR_CASE_DIR": "\${AIIR_CASE_DIR}",
            "AIIR_ACTIVE_CASE": "\${AIIR_ACTIVE_CASE}",
            "AIIR_EXAMINER": "\${AIIR_EXAMINER}",
        },
        "enabled": True,
    }
    if name == "opencti-mcp":
        octi_url = "$OPENCTI_URL"
        octi_token = "$OPENCTI_TOKEN"
        entry["env"]["OPENCTI_URL"] = octi_url if octi_url else "\${OPENCTI_URL}"
        entry["env"]["OPENCTI_TOKEN"] = octi_token if octi_token else "\${OPENCTI_TOKEN}"
    config["backends"][name] = entry

with open("$GATEWAY_CONFIG", "w") as f:
    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
PYEOF

    chmod 600 "$GATEWAY_CONFIG"
    ok "Generated: $GATEWAY_CONFIG"
fi

# =============================================================================
# Phase 9: Manifest
# =============================================================================

MANIFEST="$HOME/.aiir/manifest.json"
info "Writing manifest..."

"$VENV_PYTHON" << PYEOF
import json, datetime, subprocess, os

venv_python = "$VENV_PYTHON"
venv_dir = "$VENV_DIR"
install_dir = "$INSTALL_DIR"
port = int("$GATEWAY_PORT")
tier = "$MODE"

packages = {}
pkg_list = [
    ("forensic-knowledge", "forensic_knowledge"),
    ("sift-common", "sift_common"),
    ("forensic-mcp", "forensic_mcp"),
    ("sift-mcp", "sift_mcp"),
    ("sift-gateway", "sift_gateway"),
]

if "$INSTALL_TRIAGE" == "true":
    pkg_list.append(("windows-triage-mcp", "windows_triage"))
if "$INSTALL_RAG" == "true":
    pkg_list.append(("rag-mcp", "rag_mcp"))
if "$INSTALL_OPENCTI" == "true":
    pkg_list.append(("opencti-mcp", "opencti_mcp"))

for pip_name, module in pkg_list:
    version = "unknown"
    try:
        result = subprocess.run(
            [venv_python, "-c", f"import importlib.metadata; print(importlib.metadata.version('{pip_name}'))"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            version = result.stdout.strip()
    except Exception:
        pass
    packages[pip_name] = {"module": module, "version": version}

manifest = {
    "version": "1.0",
    "installed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "tier": tier,
    "venv": venv_dir,
    "source": install_dir,
    "gateway_port": port,
    "packages": packages,
    "case_dir": os.path.expanduser("~/cases"),
}

with open("$MANIFEST", "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PYEOF

ok "Manifest written: $MANIFEST"

# =============================================================================
# Phase 10: Default Case Directory
# =============================================================================

CASE_DIR="$HOME/cases"
if [[ ! -d "$CASE_DIR" ]]; then
    mkdir -p "$CASE_DIR"
    ok "Created default case directory: $CASE_DIR"
else
    ok "Case directory exists: $CASE_DIR"
fi

# =============================================================================
# Phase 11: Add venv to PATH
# =============================================================================

AIIR_BIN="$VENV_DIR/bin"
if [[ ":$PATH:" != *":$AIIR_BIN:"* ]]; then
    SHELL_RC=""
    if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc";
    elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc"; fi

    if [[ -n "$SHELL_RC" ]]; then
        if ! grep -q "$VENV_DIR/bin" "$SHELL_RC" 2>/dev/null; then
            echo "" >> "$SHELL_RC"
            echo "# AIIR Platform" >> "$SHELL_RC"
            echo "export PATH=\"$AIIR_BIN:\$PATH\"" >> "$SHELL_RC"
            ok "Added venv to PATH in $SHELL_RC"
        fi
    fi
    export PATH="$AIIR_BIN:$PATH"
fi

# =============================================================================
# Phase 12: Systemd Service + Gateway Start
# =============================================================================

header "Starting Gateway"

# Generate startup script (always regenerate — contains paths)
GATEWAY_START="$HOME/.aiir/start-gateway.sh"
cat > "$GATEWAY_START" << SCRIPT
#!/usr/bin/env bash
# Start AIIR Gateway
exec "$VENV_DIR/bin/python" -m sift_gateway --config "$GATEWAY_CONFIG"
SCRIPT
chmod +x "$GATEWAY_START"

# Determine protocol for health check
if $REMOTE_MODE; then
    HEALTH_URL="https://127.0.0.1:$GATEWAY_PORT/health"
    CURL_EXTRA="-k"  # self-signed cert
else
    HEALTH_URL="http://127.0.0.1:$GATEWAY_PORT/health"
    CURL_EXTRA=""
fi

# Check if gateway is already running
GATEWAY_PID=""
if curl -sf ${CURL_EXTRA:+"$CURL_EXTRA"} "$HEALTH_URL" &>/dev/null; then
    ok "Gateway already running on port $GATEWAY_PORT"
elif ! $MANUAL_START; then
    info "Starting gateway on port $GATEWAY_PORT..."
    "$VENV_DIR/bin/python" -m sift_gateway --config "$GATEWAY_CONFIG" &
    GATEWAY_PID=$!
    sleep 2

    if kill -0 "$GATEWAY_PID" 2>/dev/null; then
        if curl -sf ${CURL_EXTRA:+"$CURL_EXTRA"} "$HEALTH_URL" &>/dev/null; then
            ok "Gateway running on port $GATEWAY_PORT"
        else
            warn "Gateway started but health check failed"
        fi
    else
        warn "Gateway failed to start. Check $GATEWAY_CONFIG"
        GATEWAY_PID=""
    fi
fi

# Determine auto-start behavior
AUTOSTART=true
if $MANUAL_START; then
    AUTOSTART=false
elif [[ "$MODE" == "custom" ]] && ! $AUTO_YES; then
    echo ""
    echo "  1. Auto-start at boot (systemd service)"
    echo "  2. Manual start (use start-gateway.sh)"
    echo ""
    START_CHOICE=$(prompt "Choose" "1")
    [[ "$START_CHOICE" != "1" ]] && AUTOSTART=false
fi

if $AUTOSTART; then
    if command -v systemctl &>/dev/null && systemctl --user status &>/dev/null 2>&1; then
        SYSTEMD_DIR="$HOME/.config/systemd/user"
        mkdir -p "$SYSTEMD_DIR"

        cat > "$SYSTEMD_DIR/aiir-gateway.service" << SERVICE
[Unit]
Description=AIIR Gateway
After=network.target

[Service]
ExecStart=$VENV_DIR/bin/python -m sift_gateway --config $GATEWAY_CONFIG
Environment=AIIR_CASE_DIR=$CASE_DIR
Environment=AIIR_EXAMINER=default
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
SERVICE

        # Stop test process — systemd will manage it now
        if [[ -n "${GATEWAY_PID:-}" ]]; then
            kill "$GATEWAY_PID" 2>/dev/null || true
            wait "$GATEWAY_PID" 2>/dev/null || true
        fi

        systemctl --user daemon-reload 2>/dev/null
        systemctl --user enable aiir-gateway.service 2>/dev/null && \
            ok "Systemd service enabled (auto-start at login)"
        systemctl --user start aiir-gateway.service 2>/dev/null && \
            ok "Gateway started via systemd" || \
            warn "Could not start via systemd. Use $GATEWAY_START manually."

        # Enable lingering so service runs without active login session
        if command -v loginctl &>/dev/null; then
            loginctl enable-linger "$(whoami)" 2>/dev/null && \
                ok "Linger enabled (gateway runs without active login)" || true
        fi
    else
        warn "systemd user sessions not available (WSL or container?)"
        ok "Use startup script: $GATEWAY_START"
        if [[ -n "${GATEWAY_PID:-}" ]]; then
            info "Gateway is running now (PID $GATEWAY_PID). Will stop on logout."
        fi
    fi
else
    ok "Manual start: $GATEWAY_START"
    if [[ -n "${GATEWAY_PID:-}" ]]; then
        info "Gateway is running now (PID $GATEWAY_PID). Will stop on logout."
    fi
fi

# =============================================================================
# Phase 8b: Multi-Machine Setup (remote mode only)
# =============================================================================

if $REMOTE_MODE; then
    header "Multi-Machine Setup"

    # Detect host IP for join instructions
    HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'THIS_IP')

    # Wait for gateway to be ready before generating join codes
    JOIN_READY=false
    if curl -sf ${CURL_EXTRA:+"$CURL_EXTRA"} "$HEALTH_URL" &>/dev/null; then
        JOIN_READY=true
    fi

    if $JOIN_READY; then
        # Generate join code for the remote LLM client machine
        JOIN_OUTPUT=$("$VENV_DIR/bin/python" -m aiir_cli setup join-code 2>&1) || true
        JOIN_CODE=$(echo "$JOIN_OUTPUT" | grep "Join code:" | awk '{print $3}')

        if [[ -n "$JOIN_CODE" ]]; then
            echo ""
            echo -e "${BOLD}Remote LLM Client${NC}"
            echo "  On the machine running your LLM client (Claude Code, Cursor, etc.):"
            echo ""
            echo -e "    ${BOLD}aiir join --sift $HOST_IP:$GATEWAY_PORT --code $JOIN_CODE${NC}"
            echo ""

            # Offer to generate a second join code for Windows wintools
            if prompt_yn "Will you connect a Windows forensic workstation?" "n"; then
                WIN_OUTPUT=$("$VENV_DIR/bin/python" -m aiir_cli setup join-code 2>&1) || true
                WIN_CODE=$(echo "$WIN_OUTPUT" | grep "Join code:" | awk '{print $3}')
                if [[ -n "$WIN_CODE" ]]; then
                    echo ""
                    echo -e "${BOLD}Windows Workstation${NC}"
                    echo "  On the Windows machine with wintools-mcp:"
                    echo ""
                    echo -e "    ${BOLD}aiir join --sift $HOST_IP:$GATEWAY_PORT --code $WIN_CODE --wintools${NC}"
                    echo ""
                fi
            fi

            echo ""
            echo "  Join codes expire in 2 hours. Generate new codes with:"
            echo "    aiir setup join-code"
        else
            warn "Could not generate join code. Generate one later with:"
            echo "    aiir setup join-code"
        fi
    else
        warn "Gateway not responding. Start it first, then generate join codes:"
        echo "    $GATEWAY_START"
        echo "    aiir setup join-code"
    fi

    echo ""
    echo -e "${BOLD}SSH Access${NC}"
    echo "  For CLI operations (approve, review, report), SSH into this machine:"
    echo "    ssh $(whoami)@$HOST_IP"
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
ok "sift-gateway"
$INSTALL_TRIAGE  && ok "windows-triage-mcp"
$INSTALL_RAG     && ok "rag-mcp (forensic-rag)"
$INSTALL_OPENCTI && ok "opencti-mcp"

PROTOCOL="http"
BIND_ADDR="127.0.0.1"
if $REMOTE_MODE; then
    PROTOCOL="https"
    BIND_ADDR="0.0.0.0"
fi

echo ""
echo "Tier:        $TIER_DISPLAY"
echo "Source:      $INSTALL_DIR"
echo "Venv:        $VENV_DIR"
echo "Config:      $GATEWAY_CONFIG"
echo "Manifest:    $MANIFEST"
echo "Case dir:    $CASE_DIR"
echo "Gateway:     $PROTOCOL://$BIND_ADDR:$GATEWAY_PORT"
if $AUTOSTART; then
    echo "Auto-start:  enabled (systemd)"
else
    echo "Start:       $GATEWAY_START"
fi

echo ""
if $REMOTE_MODE; then
    echo -e "${BOLD}Bearer token:${NC} $TOKEN"
    echo "  (Stored in gateway config. Remote clients use 'aiir join' instead.)"
    echo ""
    echo -e "${BOLD}TLS CA certificate:${NC}"
    echo "  $HOME/.aiir/tls/ca-cert.pem"
else
    echo -e "${BOLD}Bearer token:${NC} $TOKEN"
    echo "  Use this token to authenticate LLM clients to the gateway."
fi

echo ""
echo "Next steps:"
STEP=1
echo "  $STEP. Restart your shell (or: source ${SHELL_RC:-~/.bashrc})"
STEP=$((STEP + 1))
if $REMOTE_MODE; then
    echo "  $STEP. On your LLM client machine, install the aiir CLI:"
    echo "     curl -sSL https://raw.githubusercontent.com/AppliedIR/aiir/main/aiir-install.sh | bash"
    STEP=$((STEP + 1))
    echo "  $STEP. Run the 'aiir join' command shown above"
    STEP=$((STEP + 1))
    echo "  $STEP. Configure your LLM client:  aiir setup client --remote"
else
    echo "  $STEP. Install the aiir CLI:"
    echo "     curl -sSL https://raw.githubusercontent.com/AppliedIR/aiir/main/aiir-install.sh | bash"
    echo "     (or: ./aiir-install.sh if you have the repo)"
    STEP=$((STEP + 1))
    echo "  $STEP. Configure your LLM client:  aiir setup client"
fi
STEP=$((STEP + 1))
echo "  $STEP. Verify installation:         aiir setup test"

if $INSTALL_RAG || $INSTALL_TRIAGE; then
    echo ""
    echo "Deferred setup:"
fi
if $INSTALL_RAG; then
    echo "  RAG index:   ~/.aiir/venv/bin/python -m rag_mcp.build"
fi
if $INSTALL_TRIAGE; then
    echo "  Triage DBs:  $VENV_PYTHON -m windows_triage.scripts.download_databases"
fi

echo ""
echo -e "${BOLD}Documentation:${NC} $INSTALL_DIR/AGENTS.md"
echo ""

# Exit with error if smoke tests failed
if (( INSTALL_ERRORS > 0 )); then
    exit 1
fi
