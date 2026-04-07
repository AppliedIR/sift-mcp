#!/usr/bin/env bash
#
# setup-sift.sh — Valhuntir SIFT Platform Installer
#
# Installs MCP servers, the gateway, vhir CLI, and all dependencies into a
# shared virtual environment at ~/.vhir/venv/. Includes examiner identity
# setup and LLM client configuration.
#
# Three install tiers:
#   Quick        — Core platform only (~3 min)
#   Recommended  — Adds RAG search + Windows triage (~30 min with index build)
#   Custom       — Choose individual packages (+ OpenCTI)
#
# Usage:
#   ./setup-sift.sh                      # Interactive (default: Recommended)
#   ./setup-sift.sh --quick -y           # Unattended quick install
#   ./setup-sift.sh --custom             # Interactive package picker
#   ./setup-sift.sh --remote             # Enable TLS + bind 0.0.0.0
#   ./setup-sift.sh --manual-start       # Skip auto-start/systemd
#   ./setup-sift.sh -h                   # Help
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
UNINSTALL_MODE=false
INSTALL_OPENSEARCH_FLAG=false
EXAMINER_NAME=""
CLIENT=""

for arg in "$@"; do
    case "$arg" in
        -y|--yes)          AUTO_YES=true ;;
        --quick)           MODE="quick" ;;
        --recommended)     MODE="recommended" ;;
        --custom)          MODE="custom" ;;
        --remote)          REMOTE_MODE=true ;;
        --manual-start)    MANUAL_START=true ;;
        --uninstall)       UNINSTALL_MODE=true ;;
        --opensearch)      INSTALL_OPENSEARCH_FLAG=true ;;
        --examiner=*)      EXAMINER_NAME="${arg#*=}" ;;
        --client=*)        CLIENT="${arg#*=}" ;;
        --install-dir=*)   INSTALL_DIR="${arg#*=}" ;;
        --venv=*)          VENV_DIR="${arg#*=}" ;;
        --port=*)          GATEWAY_PORT="${arg#*=}" ;;
        --cases-dir=*)     CASE_DIR="${arg#--cases-dir=}" ;;
        -h|--help)
            echo "Usage: setup-sift.sh [OPTIONS]"
            echo ""
            echo "Tiers (pick one):"
            echo "  --quick         Core platform only (~3 min)"
            echo "  --recommended   Core + RAG + Windows triage (default)"
            echo "  --custom        Interactive package picker"
            echo ""
            echo "Options:"
            echo "  --remote          Enable TLS + bind 0.0.0.0 (for remote clients)"
            echo "  --examiner=NAME   Set examiner identity (non-interactive)"
            echo "  --client=CLIENT   Set LLM client (claude-code, claude-desktop, librechat, other)"
            echo "  --install-dir=X   Override source clone dir (default: ~/.vhir/src/sift-mcp)"
            echo "  --venv=X          Override venv path (default: ~/.vhir/venv)"
            echo "  --port=N          Override gateway port (default: 4508)"
            echo "  --cases-dir=X     Override cases root directory (default: ~/cases)"
            echo "  --opensearch      Clone and install opensearch-mcp (evidence indexing)"
            echo "  --uninstall       Uninstall Valhuntir forensic controls (delegates to vhir setup client)"
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

# Validate --port
if ! [[ "$GATEWAY_PORT" =~ ^[0-9]+$ ]] || (( GATEWAY_PORT < 1 || GATEWAY_PORT > 65535 )); then
    echo "Invalid port: $GATEWAY_PORT (must be 1-65535)"
    exit 1
fi

# Reject running as root — $HOME becomes /root, breaking all user-dir paths.
# The script uses sudo internally only where needed (apt, samba, apparmor).
if [[ "$(id -u)" -eq 0 ]]; then
    echo "[ERROR] Do not run this script with sudo. It prompts for sudo when needed."
    echo "  Run: $(basename "$0") ${*}"
    exit 1
fi

# Defaults
[[ -z "$INSTALL_DIR" ]] && INSTALL_DIR="$HOME/.vhir/src/sift-mcp"
[[ -z "$VENV_DIR" ]] && VENV_DIR="$HOME/.vhir/venv"

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

# When running via curl | bash, stdin is the pipe. Read from /dev/tty instead.
if [[ -t 0 ]]; then
    READ_FROM="/dev/stdin"
else
    READ_FROM="/dev/tty"
fi

prompt() {
    local msg="$1" default="${2:-}"
    if $AUTO_YES && [[ -n "$default" ]]; then
        echo "$default"
        return
    fi
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${BOLD}$msg${NC} [$default]: ")" answer < "$READ_FROM"
        echo "${answer:-$default}"
    else
        read -rp "$(echo -e "${BOLD}$msg${NC}: ")" answer < "$READ_FROM"
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
    read -rp "$(echo -e "${BOLD}$msg${NC} $suffix: ")" answer < "$READ_FROM"
    answer="${answer:-$default}"
    [[ "${answer,,}" == "y" ]]
}

prompt_yn_strict() {
    local msg="$1"
    while true; do
        if ! read -rp "$(echo -e "${BOLD}$msg${NC} [y/n]: ")" answer < "$READ_FROM"; then
            echo ""
            return 1
        fi
        case "${answer,,}" in
            y) return 0 ;;
            n) return 1 ;;
            *) echo "    Please enter y or n." ;;
        esac
    done
}

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
# Uninstall passthrough
# =============================================================================

if ${UNINSTALL_MODE:-false}; then
    # Deletion on a forensics machine requires human approval per component.
    # Never allow -y to bypass uninstall prompts.
    AUTO_YES=false

    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}  Valhuntir — Platform Uninstall${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo ""

    # [1] Client forensic controls (while venv still exists)
    VHIR_CMD="$HOME/.vhir/venv/bin/vhir"
    if [[ ! -x "$VHIR_CMD" ]]; then
        VHIR_CMD=$(command -v vhir 2>/dev/null || true)
    fi
    if [[ -n "$VHIR_CMD" ]]; then
        echo -e "${BOLD}[1] Client forensic controls${NC}"
        echo "    MCP config, hooks, permissions, discipline docs"
        echo ""
        if prompt_yn_strict "    Remove client forensic controls?"; then
            "$VHIR_CMD" setup client --uninstall
        else
            info "Skipped client controls."
        fi
        echo ""
    else
        warn "vhir CLI not found. Client forensic controls must be removed manually:"
        echo "    ~/.claude.json (MCP entries)"
        echo "    ~/.claude/settings.json (hooks, permissions)"
        echo "    ~/.vhir/hooks/forensic-audit.sh"
        echo "    ~/.claude/CLAUDE.md, ~/.claude/rules/"
        echo ""
    fi

    # [2] Gateway systemd service
    SERVICE_NAME="vhir-gateway"
    UNIT_FILE="$HOME/.config/systemd/user/${SERVICE_NAME}.service"
    if systemctl --user is-enabled "$SERVICE_NAME" &>/dev/null 2>&1 || [[ -f "$UNIT_FILE" ]]; then
        echo -e "${BOLD}[2] Gateway systemd service${NC}"
        echo "    Service: $SERVICE_NAME"
        echo "    Status: $(systemctl --user is-active "$SERVICE_NAME" 2>/dev/null || echo 'unknown')"
        echo ""
        if prompt_yn_strict "    Stop and disable gateway service?"; then
            systemctl --user stop "$SERVICE_NAME" 2>/dev/null || true
            systemctl --user disable "$SERVICE_NAME" 2>/dev/null || true
            if [[ -f "$UNIT_FILE" ]]; then
                rm -f "$UNIT_FILE"
                systemctl --user daemon-reload 2>/dev/null || true
            fi
            ok "Gateway service stopped and removed."
        else
            info "Skipped gateway service."
        fi
        echo ""
    fi

    # [3] Virtual environment
    KEPT_VENV=false
    if [[ -d "$VENV_DIR" ]]; then
        VENV_SIZE=$(du -sh "$VENV_DIR" 2>/dev/null | cut -f1 || echo "unknown")
        echo -e "${BOLD}[3] Virtual environment${NC}"
        echo "    Path: $VENV_DIR"
        echo "    Size: $VENV_SIZE"
        echo ""
        if prompt_yn_strict "    Remove virtual environment?"; then
            rm -rf "$VENV_DIR"
            ok "Virtual environment removed."
        else
            KEPT_VENV=true
            info "Skipped virtual environment."
        fi
        echo ""
    fi

    # [4] Source code (includes RAG index and triage databases via editable install)
    KEPT_SRC=false
    SRC_DIR="$(dirname "$INSTALL_DIR")"
    if [[ -d "$SRC_DIR" ]]; then
        SRC_SIZE=$(du -sh "$SRC_DIR" 2>/dev/null | cut -f1 || echo "unknown")
        echo -e "${BOLD}[4] Source code${NC}"
        echo "    Path: $SRC_DIR"
        echo "    Size: $SRC_SIZE"

        # Surface RAG index and triage DB sizes if present
        INCLUDES=""
        RAG_DIR="$SRC_DIR/sift-mcp/packages/forensic-rag/data"
        if [[ -d "$RAG_DIR/chroma" ]]; then
            RAG_SIZE=$(du -sh "$RAG_DIR" 2>/dev/null | cut -f1)
            [[ -n "$RAG_SIZE" ]] && INCLUDES="RAG index (~$RAG_SIZE)"
        fi
        TRIAGE_DIR="$SRC_DIR/sift-mcp/packages/windows-triage/data"
        if [[ -f "$TRIAGE_DIR/known_good.db" ]]; then
            TRIAGE_SIZE=$(du -sh "$TRIAGE_DIR" 2>/dev/null | cut -f1)
            if [[ -n "$TRIAGE_SIZE" ]]; then
                if [[ -n "$INCLUDES" ]]; then
                    INCLUDES="$INCLUDES, triage databases (~$TRIAGE_SIZE)"
                else
                    INCLUDES="triage databases (~$TRIAGE_SIZE)"
                fi
            fi
        fi
        [[ -n "$INCLUDES" ]] && echo "    Includes: $INCLUDES"

        echo ""
        if prompt_yn_strict "    Remove source code?"; then
            rm -rf "$SRC_DIR"
            ok "Source code removed."
        else
            KEPT_SRC=true
            info "Skipped source code."
        fi
        echo ""
    fi

    # [5] Shell profile
    SHELL_RC=""
    if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc";
    elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc"; fi

    if [[ -n "$SHELL_RC" ]] && grep -q "Valhuntir" "$SHELL_RC" 2>/dev/null; then
        echo -e "${BOLD}[5] Shell profile${NC}"
        echo "    File: $SHELL_RC"
        echo "    Lines: VHIR_EXAMINER, VHIR_CASES_DIR, PATH, argcomplete"
        echo ""
        if prompt_yn_strict "    Remove Valhuntir lines from $SHELL_RC?"; then
            sed -i '/# Valhuntir Platform/d' "$SHELL_RC"
            sed -i '/VHIR_EXAMINER/d' "$SHELL_RC"
            sed -i '/VHIR_CASES_DIR/d' "$SHELL_RC"
            sed -i '/# vhir-path/d' "$SHELL_RC"
            sed -i '\|\.vhir/venv/bin|d' "$SHELL_RC"
            sed -i '/register-python-argcomplete vhir/d' "$SHELL_RC"
            ok "Shell profile cleaned."
        else
            info "Skipped. Remove manually if needed."
        fi
        echo ""
    fi

    # [6] Gateway config and credentials
    CONFIG_FILES=()
    for f in gateway.yaml manifest.json config.yaml; do
        [[ -f "$HOME/.vhir/$f" ]] && CONFIG_FILES+=("$HOME/.vhir/$f")
    done
    TLS_DIR="$HOME/.vhir/tls"
    if [[ ${#CONFIG_FILES[@]} -gt 0 ]] || [[ -d "$TLS_DIR" ]]; then
        echo -e "${BOLD}[6] Gateway config and credentials${NC}"
        for f in "${CONFIG_FILES[@]}"; do
            echo "    $f"
        done
        [[ -d "$TLS_DIR" ]] && echo "    $TLS_DIR/ (TLS certificates)"
        echo ""
        if prompt_yn_strict "    Remove gateway config and credentials?"; then
            for f in "${CONFIG_FILES[@]}"; do
                rm -f "$f"
            done
            [[ -d "$TLS_DIR" ]] && rm -rf "$TLS_DIR"
            ok "Gateway config removed."
        else
            info "Skipped gateway config."
        fi
        echo ""
    fi

    # [7] Remaining ~/.vhir/ contents (hooks, logs, start-gateway.sh)
    # Exclude items the user chose to keep in steps 3-4
    VHIR_DIR="$HOME/.vhir"
    if [[ -d "$VHIR_DIR" ]]; then
        EXCLUDE_ARGS=()
        $KEPT_VENV && EXCLUDE_ARGS+=(! -name "venv")
        $KEPT_SRC  && EXCLUDE_ARGS+=(! -name "src")

        REMAINING=$(find "$VHIR_DIR" -mindepth 1 -maxdepth 1 "${EXCLUDE_ARGS[@]}" 2>/dev/null | head -5)
        if [[ -n "$REMAINING" ]]; then
            echo -e "${BOLD}[7] Remaining ~/.vhir/ contents${NC}"
            while IFS= read -r item; do
                echo "    $(basename "$item")"
            done <<< "$REMAINING"
            REMAINING_COUNT=$(find "$VHIR_DIR" -mindepth 1 -maxdepth 1 "${EXCLUDE_ARGS[@]}" 2>/dev/null | wc -l)
            if (( REMAINING_COUNT > 5 )); then
                echo "    ... and $((REMAINING_COUNT - 5)) more"
            fi
            echo ""
            if prompt_yn_strict "    Remove remaining ~/.vhir/ contents?"; then
                # Remove only items not preserved in earlier steps
                find "$VHIR_DIR" -mindepth 1 -maxdepth 1 "${EXCLUDE_ARGS[@]}" -exec rm -rf {} +
                ok "Remaining ~/.vhir/ contents removed."
            else
                info "Skipped. Directory preserved at $VHIR_DIR"
            fi
        else
            # Only remove directory if truly empty
            rmdir "$VHIR_DIR" 2>/dev/null || true
        fi
        echo ""
    fi

    # [8] Verification ledger (/var/lib/vhir)
    VERIF_DIR="/var/lib/vhir"
    if [[ -d "$VERIF_DIR" ]]; then
        echo -e "${BOLD}[8] Verification ledger${NC}"
        echo "    Path: $VERIF_DIR/verification/"
        LEDGER_COUNT=$(find "$VERIF_DIR/verification" -name "*.jsonl" 2>/dev/null | wc -l)
        echo "    Ledger files: $LEDGER_COUNT"
        echo -e "    ${YELLOW}Contains HMAC approval records for case findings.${NC}"
        echo ""
        if prompt_yn_strict "    Remove verification ledger? (requires sudo)"; then
            sudo rm -rf "$VERIF_DIR" && ok "Verification ledger removed." || warn "Could not remove $VERIF_DIR (sudo required)"
        else
            info "Skipped. Ledger preserved at $VERIF_DIR"
        fi
        echo ""
    fi

    # [9] AppArmor bwrap profile
    BWRAP_PROFILE="/etc/apparmor.d/bwrap"
    if [[ -f "$BWRAP_PROFILE" ]]; then
        echo -e "${BOLD}[9] AppArmor bwrap profile${NC}"
        echo "    Path: $BWRAP_PROFILE"
        echo ""
        if prompt_yn_strict "    Remove AppArmor bwrap profile? (requires sudo)"; then
            if sudo rm -f "$BWRAP_PROFILE"; then
                if sudo apparmor_parser --remove bwrap 2>/dev/null || sudo systemctl reload apparmor 2>/dev/null; then
                    ok "AppArmor bwrap profile removed and unloaded."
                else
                    ok "AppArmor bwrap profile removed from disk."
                    info "Could not unload from kernel. Profile will clear on next reboot."
                fi
            else
                warn "Could not remove $BWRAP_PROFILE (sudo required)"
            fi
        else
            info "Skipped. Profile preserved at $BWRAP_PROFILE"
        fi
        echo ""
    fi

    # Case data warning
    CASES_DIR="$HOME/cases"
    if [[ -d "$CASES_DIR" ]]; then
        echo -e "${YELLOW}${BOLD}Case data preserved${NC}"
        echo "    $CASES_DIR"
        echo "    Case data is never removed by uninstall."
        echo "    Back up and remove manually if needed."
        echo ""
    fi

    echo -e "${BOLD}Uninstall complete.${NC}"
    exit 0
fi

# =============================================================================
# Banner
# =============================================================================

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  Valhuntir — SIFT Platform Installer${NC}"
echo -e "${BOLD}  Artificial Intelligence Incident Response${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# =============================================================================
# Phase 1: Prerequisites
# =============================================================================

header "Checking Prerequisites"

# Python 3.10+
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" &>/dev/null; then
        PY_MAJOR=$("$candidate" -c 'import sys; print(sys.version_info.major)' 2>/dev/null) || continue
        PY_MINOR=$("$candidate" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null) || continue
        if (( PY_MAJOR == 3 && PY_MINOR >= 10 )); then
            PYTHON=$(command -v "$candidate")
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    err "Python 3.10+ required. Found candidates:"
    for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
        command -v "$candidate" &>/dev/null && echo "  $candidate: $($candidate --version 2>&1)"
    done
    echo "  Install: sudo apt install python3.11 python3.11-venv"
    exit 1
fi

PY_VERSION=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
ok "Python $PY_VERSION ($PYTHON)"

# pip
if $PYTHON -m pip --version &>/dev/null; then
    ok "pip available"
else
    err "pip not found"
    echo "  Install: sudo apt install python3-pip"
    exit 1
fi

# uv (or venv fallback check — uv is installed in Phase 4 if missing)
if command -v uv &>/dev/null; then
    ok "uv available"
elif $PYTHON -m venv --help &>/dev/null 2>&1; then
    ok "venv available (uv will be installed in Phase 4)"
else
    # Neither uv nor python3-venv — uv will be auto-installed in Phase 4,
    # but warn if curl/wget are also missing (uv install needs one of them)
    if command -v curl &>/dev/null || command -v wget &>/dev/null; then
        ok "uv will be installed in Phase 4"
    else
        err "Neither uv, python3-venv, curl, nor wget found"
        echo "  Install curl: sudo apt install curl"
        exit 1
    fi
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

# bubblewrap + socat (required for Claude Code kernel sandbox)
if command -v bwrap &>/dev/null; then
    ok "bubblewrap (bwrap) available"
else
    info "Installing bubblewrap (required for Claude Code kernel sandbox)..."
    if sudo apt-get install -y bubblewrap &>/dev/null; then
        ok "bubblewrap installed"
    else
        warn "Could not install bubblewrap. Claude Code sandbox (L9) will not function."
        echo "  Install manually: sudo apt install bubblewrap"
    fi
fi

if command -v socat &>/dev/null; then
    ok "socat available"
else
    info "Installing socat (required for sandbox network proxy)..."
    if sudo apt-get install -y socat &>/dev/null; then
        ok "socat installed"
    else
        warn "Could not install socat. Sandbox network proxy may not function."
        echo "  Install manually: sudo apt install socat"
    fi
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
# Phase 1b: Verification Ledger Directory
# =============================================================================

if [ -d /var/lib/vhir/verification ]; then
    ok "Verification ledger: /var/lib/vhir/verification/"
else
    info "Creating verification ledger directory (requires sudo)..."
    if sudo mkdir -p /var/lib/vhir/verification && \
       sudo chown "$USER:$USER" /var/lib/vhir/verification && \
       sudo chmod 700 /var/lib/vhir/verification; then
        ok "Verification ledger: /var/lib/vhir/verification/"
    else
        err "Could not create /var/lib/vhir/verification/"
        echo "  The HMAC verification ledger is required for finding integrity."
        echo "  Run: sudo mkdir -p /var/lib/vhir/verification && sudo chown $USER:$USER /var/lib/vhir/verification && sudo chmod 700 /var/lib/vhir/verification"
        exit 1
    fi
fi

# =============================================================================
# Phase 1b2: Password Storage Directory
# =============================================================================

if [ -d /var/lib/vhir/passwords ]; then
    ok "Password storage: /var/lib/vhir/passwords/"
else
    info "Creating password storage directory (requires sudo)..."
    if sudo mkdir -p /var/lib/vhir/passwords && \
       sudo chown "$USER:$USER" /var/lib/vhir/passwords && \
       sudo chmod 700 /var/lib/vhir/passwords; then
        ok "Password storage: /var/lib/vhir/passwords/"
    else
        err "Could not create /var/lib/vhir/passwords/"
        echo "  Run: sudo mkdir -p /var/lib/vhir/passwords && sudo chown $USER:$USER /var/lib/vhir/passwords && sudo chmod 700 /var/lib/vhir/passwords"
        exit 1
    fi
fi

# =============================================================================
# Phase 1c: Sandbox Diagnostic + AppArmor Fix
# =============================================================================
# Claude Code's kernel sandbox (L9) uses bubblewrap to isolate Bash commands
# in network and PID namespaces. On non-setuid bwrap (all Ubuntu 18.10+),
# this requires unprivileged user namespace support in the kernel.
#
# Multiple mechanisms can block user namespaces:
#   - AppArmor restrict_unprivileged_userns (Ubuntu 23.10+)
#   - kernel.unprivileged_userns_clone=0 (older Ubuntu, hardened kernels)
#   - Container restrictions (Docker, LXC without nesting)
#   - WSL1 (no namespace support)
#   - user.max_user_namespaces=0
#
# See: https://appliedir.github.io/Valhuntir/security/ (L9 — Kernel Sandbox)

BWRAP_PROFILE="/etc/apparmor.d/bwrap"

# Container detection — covers Docker, Podman, LXC, nspawn, Kubernetes
_is_container() {
    if command -v systemd-detect-virt &>/dev/null; then
        local virt
        virt=$(systemd-detect-virt --container 2>/dev/null)
        # Exclude "wsl" — handled by dedicated WSL check in cascade
        [[ $? -eq 0 && "$virt" != "wsl" ]] && return 0
    fi
    [[ -f /.dockerenv ]] && return 0
    [[ -f /run/.containerenv ]] && return 0
    grep -qE '/(docker|lxc|containerd|kubepods)' /proc/1/cgroup 2>/dev/null && return 0
    return 1
}

if command -v bwrap &>/dev/null; then
    # Test what the sandbox actually does: network namespace isolation
    # Capture exit code without letting set -e kill the script on failure
    BWRAP_RC=0
    BWRAP_ERR=$(timeout 5 bwrap --ro-bind / / --unshare-net -- /bin/true 2>&1) || BWRAP_RC=$?

    if [[ $BWRAP_RC -eq 0 ]]; then
        ok "Sandbox: bwrap network namespace works"

    # --- Timeout? (RC=124 from timeout command) ---
    elif [[ $BWRAP_RC -eq 124 ]]; then
        warn "Sandbox test timed out (5s)."
        echo "  bwrap may be hanging on a kernel call."
        echo "  Run: timeout 5 bwrap --ro-bind / / --unshare-net -- /bin/true"

    # --- Container? (check first — overrides everything else) ---
    elif _is_container; then
        warn "Sandbox test failed — running inside a container."
        [[ -n "$BWRAP_ERR" ]] && echo "  bwrap: $BWRAP_ERR"
        echo "  Containers restrict namespace creation by default."
        echo ""
        echo "  Docker:  run with --privileged or --security-opt seccomp=unconfined"
        echo "  LXC/LXD: set security.nesting=true on the container profile"
        echo "  Podman:  podman run --privileged or --security-opt label=disable"
        echo ""
        echo "  If you cannot enable privileged namespaces, Claude Code's"
        echo "  enableWeakerNestedSandbox provides partial isolation (network +"
        echo "  filesystem restrictions remain; process isolation is reduced)."
        echo "  Set in settings.json: \"sandbox\": {\"enableWeakerNestedSandbox\": true}"
        echo "  WARNING: This weakens process isolation. Only use inside containers."

    # --- WSL1? ---
    elif [[ "$(uname -r)" == *Microsoft* || "$(uname -r)" == *WSL* ]] \
         && [[ "$(uname -r)" != *microsoft-standard-WSL2* ]]; then
        warn "Sandbox test failed — WSL1 does not support user namespaces."
        [[ -n "$BWRAP_ERR" ]] && echo "  bwrap: $BWRAP_ERR"
        echo "  Upgrade to WSL2: wsl --set-version <distro> 2"

    # --- AppArmor bwrap profile already installed but test still fails? ---
    elif [[ -f "$BWRAP_PROFILE" ]]; then
        warn "AppArmor bwrap profile exists at $BWRAP_PROFILE but sandbox test failed."
        [[ -n "$BWRAP_ERR" ]] && echo "  bwrap: $BWRAP_ERR"
        echo "  Try: sudo apparmor_parser -rT $BWRAP_PROFILE (or reboot)"

    # --- AppArmor userns restriction? (Ubuntu 23.10+) ---
    elif [[ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null)" == "1" ]]; then
        echo ""
        warn "Sandbox test failed."
        echo "  AppArmor on this system blocks unprivileged user namespaces"
        echo "  (kernel.apparmor_restrict_unprivileged_userns=1). This prevents"
        echo "  Claude Code's kernel sandbox (L9) from isolating Bash commands."
        echo ""
        echo "  Recommended fix: install a targeted AppArmor profile that grants"
        echo "  only /usr/bin/bwrap the 'userns' permission. This only affects"
        echo "  /usr/bin/bwrap — other processes are not changed."
        echo ""
        echo "  Profile location: $BWRAP_PROFILE"
        echo "  Side effect:      Any process using /usr/bin/bwrap gains user namespace access."
        echo ""

        if ! prompt_yn "  Install AppArmor profile for bwrap? (requires sudo)" "y"; then
            info "Skipped. The kernel sandbox (L9) will not function on this system."
            echo "  You can install the profile later by re-running setup-sift.sh."
        elif ! sudo tee "$BWRAP_PROFILE" > /dev/null << 'APPARMOR'
# AppArmor profile for bubblewrap — grants user namespace access.
# Installed by Valhuntir setup-sift.sh for Claude Code kernel sandbox (L9).
# This profile is specific to /usr/bin/bwrap and does not affect other
# processes. Safe to remove: sudo rm /etc/apparmor.d/bwrap && sudo systemctl reload apparmor
abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
APPARMOR
        then
            warn "Could not write AppArmor profile (sudo required)."
            echo "  The kernel sandbox (L9) will not function on this system."
            echo "  Manual fix:"
            echo "    sudo tee $BWRAP_PROFILE << 'EOF'"
            echo "    abi <abi/4.0>,"
            echo "    include <tunables/global>"
            echo "    profile bwrap /usr/bin/bwrap flags=(unconfined) {"
            echo "      userns,"
            echo "      include if exists <local/bwrap>"
            echo "    }"
            echo "    EOF"
            echo "    sudo systemctl reload apparmor"
        else
            # Profile written — try to load it
            PARSER_OUTPUT=""
            if PARSER_OUTPUT=$(sudo apparmor_parser -rT "$BWRAP_PROFILE" 2>&1); then
                PROFILE_LOADED=true
            elif PARSER_OUTPUT=$(sudo apparmor_parser -r "$BWRAP_PROFILE" 2>&1); then
                PROFILE_LOADED=true
            elif sudo systemctl reload apparmor 2>/dev/null; then
                PROFILE_LOADED=true
            else
                PROFILE_LOADED=false
            fi

            if $PROFILE_LOADED; then
                if bwrap --ro-bind / / --unshare-net -- /bin/true 2>/dev/null; then
                    ok "AppArmor bwrap profile installed and verified"
                else
                    warn "AppArmor profile installed and loaded but sandbox test still fails."
                    echo "  This may require a reboot to take effect."
                    echo "  After reboot, verify: bwrap --ro-bind / / --unshare-net -- /bin/true"
                fi
            else
                warn "Could not load AppArmor profile."
                if [[ -n "$PARSER_OUTPUT" ]]; then
                    echo "  apparmor_parser: $PARSER_OUTPUT"
                fi
                echo "  Profile written to $BWRAP_PROFILE but not active."
                echo "  Try: sudo apparmor_parser -rT $BWRAP_PROFILE"
                echo "  Or reboot to load the profile automatically."
            fi
        fi

    # --- unprivileged_userns_clone=0? (pre-23.10 mechanism, hardened kernels) ---
    elif [[ "$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null)" == "0" ]]; then
        warn "Sandbox test failed — user namespaces disabled by sysctl."
        [[ -n "$BWRAP_ERR" ]] && echo "  bwrap: $BWRAP_ERR"
        echo "  kernel.unprivileged_userns_clone=0 prevents bwrap from creating"
        echo "  the namespaces needed for Claude Code's kernel sandbox (L9)."
        echo ""
        echo "  Temporary fix:"
        echo "    sudo sysctl -w kernel.unprivileged_userns_clone=1"
        echo ""
        echo "  Permanent fix:"
        echo "    echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/60-userns.conf"
        echo "    sudo sysctl --system"

    # --- user.max_user_namespaces=0? ---
    elif [[ "$(sysctl -n user.max_user_namespaces 2>/dev/null)" == "0" ]]; then
        warn "Sandbox test failed — user namespace limit is zero."
        [[ -n "$BWRAP_ERR" ]] && echo "  bwrap: $BWRAP_ERR"
        echo "  Fix: sudo sysctl -w user.max_user_namespaces=15000"

    # --- Unknown cause ---
    else
        warn "Sandbox test failed."
        if [[ -n "$BWRAP_ERR" ]]; then
            echo "  bwrap: $BWRAP_ERR"
        fi
        echo "  Run manually to diagnose: bwrap --ro-bind / / --unshare-net -- /bin/true"
        echo "  The kernel sandbox (L9) may not function correctly."
    fi
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
        prompt_yn "    Install opensearch-mcp (evidence indexing — needs Docker)?" "n" && INSTALL_OPENSEARCH_FLAG=true
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

# Clone vhir (for vhir-cli — required before case-mcp/report-mcp)
VHIR_DIR="$(dirname "$INSTALL_DIR")/vhir"
VHIR_REPO_URL="https://github.com/AppliedIR/Valhuntir.git"

if [[ -d "$VHIR_DIR/.git" ]]; then
    info "vhir repository exists at $VHIR_DIR. Pulling latest..."
    if (cd "$VHIR_DIR" && git pull --quiet); then
        ok "vhir repository updated"
    else
        warn "Could not update vhir repository. Continuing with existing code."
    fi
elif [[ -d "$VHIR_DIR" ]] && [[ ! -d "$VHIR_DIR/.git" ]]; then
    err "$VHIR_DIR exists but is not a git repository"
    echo "  Remove it or choose a different --install-dir"
    exit 1
else
    info "Cloning vhir..."
    if ! git clone --quiet "$VHIR_REPO_URL" "$VHIR_DIR"; then
        err "Failed to clone vhir repository"
        echo "  Check network access and try again"
        exit 1
    fi
    ok "vhir repository cloned to $VHIR_DIR"
fi

# =============================================================================
# Phase 4: Virtual Environment + Package Installation
# =============================================================================

header "Installing Packages"

# --- uv package manager ---
ensure_uv() {
    if command -v uv &>/dev/null; then
        return
    fi
    info "Installing uv package manager..."
    if ! curl -LsSf https://astral.sh/uv/install.sh | sh 2>/dev/null; then
        err "uv installation failed"
        echo "  Install manually: curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi
    export PATH="$HOME/.local/bin:$PATH"
    if ! command -v uv &>/dev/null; then
        err "uv installed but not found on PATH"
        exit 1
    fi
    ok "uv installed"
}

# Bridge existing pip mirror config to uv
[ -n "${PIP_INDEX_URL:-}" ] && export UV_INDEX_URL="$PIP_INDEX_URL"

ensure_uv

# --- Virtual environment ---
VENV_DIR=$(realpath -m "$VENV_DIR")
mkdir -p "$(dirname "$VENV_DIR")"

if [[ -d "$VENV_DIR" && ! -f "$VENV_DIR/bin/python" ]]; then
    warn "Broken virtual environment detected at $VENV_DIR — recreating..."
    rm -rf "$VENV_DIR"
fi

if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment at $VENV_DIR..."
    if ! uv venv "$VENV_DIR" --python "$PYTHON" --seed --quiet; then
        err "Failed to create virtual environment"
        exit 1
    fi
fi

if [[ ! -f "$VENV_DIR/bin/python" ]]; then
    err "Virtual environment at $VENV_DIR is missing python binary"
    exit 1
fi

ok "Virtual environment ready at $VENV_DIR"

VENV_PYTHON="$VENV_DIR/bin/python"

# Helper: install a single package (used for fallback and one-off installs)
install_pkg() {
    local name="$1" path="$2"
    if ! uv pip install --python "$VENV_PYTHON" --quiet -e "$path"; then
        err "Failed to install $name"
        echo "  Check: uv pip install --python $VENV_PYTHON -e $path"
        return 1
    fi
    ok "$name installed"
}

INSTALL_ERRORS=0

# --- Core packages (always installed) — batched for unified resolution ---
info "Installing core packages..."
if ! uv pip install --python "$VENV_PYTHON" --quiet \
    -e "$INSTALL_DIR/packages/forensic-knowledge" \
    -e "$INSTALL_DIR/packages/sift-common" \
    -e "$INSTALL_DIR/packages/forensic-mcp" \
    -e "$INSTALL_DIR/packages/sift-mcp" \
    -e "$INSTALL_DIR/packages/sift-gateway" \
    -e "$VHIR_DIR" \
    -e "$INSTALL_DIR/packages/case-mcp" \
    -e "$INSTALL_DIR/packages/report-mcp" \
    -e "$INSTALL_DIR/packages/case-dashboard"; then
    err "Failed to install core packages"
    exit 1
fi
ok "Core packages installed"

# --- Optional packages — batched for unified opentelemetry resolution ---
OPTIONAL_PKGS=""
$INSTALL_TRIAGE  && OPTIONAL_PKGS="$OPTIONAL_PKGS -e $INSTALL_DIR/packages/windows-triage"
$INSTALL_OPENCTI && OPTIONAL_PKGS="$OPTIONAL_PKGS -e $INSTALL_DIR/packages/opencti"

if $INSTALL_RAG; then
    echo ""
    info "Installing optional packages (including ML dependencies)..."
    echo "  (may take several minutes on first install)"
    OPTIONAL_PKGS="$OPTIONAL_PKGS -e $INSTALL_DIR/packages/forensic-rag"
fi

if [ -n "$OPTIONAL_PKGS" ]; then
    # --reinstall-package forces re-resolution of the exporter when opencti
    # is added to an existing RAG install (prevents sdk/exporter version mismatch)
    REINSTALL_FLAG=""
    if $INSTALL_OPENCTI && $INSTALL_RAG; then
        REINSTALL_FLAG="--reinstall-package opentelemetry-exporter-otlp-proto-grpc"
    fi
    if ! uv pip install --python "$VENV_PYTHON" --quiet $REINSTALL_FLAG $OPTIONAL_PKGS; then
        # If batched optional fails, try each individually to isolate the failure
        warn "Batched optional install failed. Installing individually..."
        if $INSTALL_TRIAGE; then
            install_pkg "windows-triage-mcp" "$INSTALL_DIR/packages/windows-triage" || {
                warn "windows-triage install failed. Continuing without it."
                INSTALL_TRIAGE=false
            }
        fi
        if $INSTALL_RAG; then
            install_pkg "rag-mcp" "$INSTALL_DIR/packages/forensic-rag" || {
                warn "forensic-rag install failed. Continuing without it."
                INSTALL_RAG=false
            }
        fi
        if $INSTALL_OPENCTI; then
            install_pkg "opencti-mcp" "$INSTALL_DIR/packages/opencti" || {
                warn "opencti install failed. Continuing without it."
                INSTALL_OPENCTI=false
            }
        fi
    else
        ok "Optional packages installed"
    fi
fi

# --- OpenSearch MCP (evidence indexing — optional) ---
OPENSEARCH_MCP_DIR="$INSTALL_DIR/../opensearch-mcp"
if [ ! -d "$OPENSEARCH_MCP_DIR" ]; then
    OPENSEARCH_MCP_DIR="$HOME/.vhir/src/opensearch-mcp"
fi

# Clone or update opensearch-mcp
if $INSTALL_OPENSEARCH_FLAG && [ ! -d "$OPENSEARCH_MCP_DIR" ]; then
    OPENSEARCH_MCP_DIR="$INSTALL_DIR/../opensearch-mcp"
    info "Cloning opensearch-mcp..."
    if git clone --quiet https://github.com/AppliedIR/opensearch-mcp.git "$OPENSEARCH_MCP_DIR"; then
        ok "opensearch-mcp cloned to $OPENSEARCH_MCP_DIR"
    else
        warn "opensearch-mcp clone failed. OpenSearch features unavailable."
        OPENSEARCH_MCP_DIR=""
    fi
elif [ -d "$OPENSEARCH_MCP_DIR" ] && [ -d "$OPENSEARCH_MCP_DIR/.git" ]; then
    info "Updating opensearch-mcp..."
    git -C "$OPENSEARCH_MCP_DIR" pull --ff-only --quiet 2>/dev/null && ok "opensearch-mcp updated" || true
fi

INSTALL_OPENSEARCH=false
if [ -d "$OPENSEARCH_MCP_DIR" ]; then
    info "Installing opensearch-mcp from $OPENSEARCH_MCP_DIR..."
    if uv pip install --python "$VENV_PYTHON" --quiet -e "$OPENSEARCH_MCP_DIR"; then
        ok "opensearch-mcp installed"
        INSTALL_OPENSEARCH=true

        # Run setup-opensearch.sh to start Docker + templates + credentials
        SETUP_OS_SCRIPT="$OPENSEARCH_MCP_DIR/scripts/setup-opensearch.sh"
        if [ -f "$SETUP_OS_SCRIPT" ]; then
            echo ""
            info "Setting up OpenSearch (Docker container, templates, credentials)..."

            # Ensure Docker is accessible before calling setup-opensearch.sh
            if command -v docker &>/dev/null; then
                if ! docker ps &>/dev/null; then
                    if ! groups | grep -qw docker; then
                        info "Adding $USER to docker group (requires sudo)..."
                        if sudo usermod -aG docker "$USER"; then
                            ok "Added to docker group"
                            if sg docker -c 'bash "'"$SETUP_OS_SCRIPT"'"'; then
                                ok "OpenSearch setup complete"
                            else
                                warn "OpenSearch setup failed. Run manually: $SETUP_OS_SCRIPT"
                            fi
                        else
                            warn "Could not add $USER to docker group. OpenSearch setup skipped."
                        fi
                        SETUP_OS_SCRIPT=""
                    else
                        info "Starting Docker daemon..."
                        sudo systemctl start docker
                        if ! docker ps &>/dev/null; then
                            warn "Could not start Docker. OpenSearch setup skipped."
                            SETUP_OS_SCRIPT=""
                        fi
                    fi
                fi
            else
                warn "Docker not installed. OpenSearch setup skipped."
                warn "Install Docker: https://docs.docker.com/engine/install/"
                SETUP_OS_SCRIPT=""
            fi

            # Normal call (docker access already working)
            if [ -n "$SETUP_OS_SCRIPT" ]; then
                if bash "$SETUP_OS_SCRIPT"; then
                    ok "OpenSearch setup complete"
                else
                    warn "OpenSearch setup failed. Run manually: $SETUP_OS_SCRIPT"
                fi
            fi
        fi
    else
        warn "opensearch-mcp install failed. OpenSearch features unavailable."
    fi
else
    info "opensearch-mcp not found — skipping (use --opensearch to install, or clone to $INSTALL_DIR/../opensearch-mcp)"
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
smoke_test "vhir-cli"           "vhir_cli"
smoke_test "case-mcp"           "case_mcp"
smoke_test "report-mcp"         "report_mcp"
smoke_test "case-dashboard"     "case_dashboard"
$INSTALL_TRIAGE  && smoke_test "windows-triage-mcp" "windows_triage"
$INSTALL_RAG     && smoke_test "rag-mcp"            "rag_mcp"
$INSTALL_OPENCTI    && smoke_test "opencti-mcp"        "opencti_mcp"
$INSTALL_OPENSEARCH && smoke_test "opensearch-mcp"     "opensearch_mcp"

if (( INSTALL_ERRORS > 0 )); then
    warn "$INSTALL_ERRORS component(s) failed import. Check output above."
fi

# =============================================================================
# Phase 5b: Post-Install Setup (data downloads, index builds)
# =============================================================================

if $INSTALL_RAG || $INSTALL_TRIAGE; then
    header "Post-Install Setup"
fi

# --- forensic-rag index ---
if $INSTALL_RAG; then
    INDEX_COUNT=$("$VENV_PYTHON" -m rag_mcp.status --json --no-check 2>/dev/null | \
        "$VENV_PYTHON" -c "import sys,json; print(json.load(sys.stdin).get('document_count',0))" \
        2>/dev/null) || INDEX_COUNT=0

    if [ "$INDEX_COUNT" -gt 0 ] 2>/dev/null; then
        ok "RAG index exists ($INDEX_COUNT records)"
    else
        echo "  Downloading pre-built RAG index..."
        if ANONYMIZED_TELEMETRY=False "$VENV_PYTHON" -m rag_mcp.scripts.download_index 2>&1; then
            ok "RAG index downloaded"
        else
            if ! $AUTO_YES; then
                echo "Download failed. Build from source instead?"
                echo "  This takes 15 minutes to 3 hours depending on CPU."
                echo "  Skip: build later with: $VENV_PYTHON -m rag_mcp.build"
                if prompt_yn "Build index now?" "y"; then
                    info "Building from source..."
                    ANONYMIZED_TELEMETRY=False "$VENV_PYTHON" -m rag_mcp.build && \
                        ok "Index built" || warn "Build failed. Retry later."
                else
                    info "Skipping index build."
                fi
            else
                warn "RAG index download failed. Build manually: $VENV_PYTHON -m rag_mcp.build"
            fi
        fi
    fi
fi

# --- windows-triage database setup ---
if $INSTALL_TRIAGE; then
    WT_DIR="$INSTALL_DIR/packages/windows-triage"
    DB_DIR="$WT_DIR/data"

    # Ensure zstandard is available for the download module
    uv pip install --python "$VENV_PYTHON" --quiet zstandard 2>/dev/null || true

    # Check if databases already exist
    DB_EXISTS=false
    if [[ -s "$DB_DIR/known_good.db" ]] && [[ -s "$DB_DIR/context.db" ]]; then
        if "$VENV_PYTHON" -c "import sqlite3; sqlite3.connect('$DB_DIR/known_good.db').execute('SELECT 1')" 2>/dev/null; then
            DB_EXISTS=true
        fi
    fi

    if $DB_EXISTS; then
        DB_SIZE=$(du -sh "$DB_DIR" 2>/dev/null | cut -f1 || echo "unknown")
        ok "Triage databases exist ($DB_SIZE)"
        DB_CHOICE="3"  # skip
    elif ! $AUTO_YES; then
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

    # Validate triage databases (after all download/build/skip paths)
    for db in known_good.db context.db; do
        db_path="$DB_DIR/$db"
        if [ -s "$db_path" ]; then
            if "$VENV_PYTHON" -c "import sqlite3; sqlite3.connect('$db_path').execute('SELECT 1')" 2>/dev/null; then
                ok "$db valid"
            else
                warn "$db exists but is not valid SQLite"
            fi
        else
            warn "$db missing or empty"
        fi
    done
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
        # Validate URL — reject quotes/backslashes that would break Python heredoc
        if [[ "$OPENCTI_URL" =~ [\"\'\\] ]]; then
            err "OpenCTI URL contains invalid characters (quotes or backslashes)"
            OPENCTI_URL=""
        else
            read -rp "OpenCTI API Token: " OPENCTI_TOKEN < "$READ_FROM"
            echo ""
            if [[ "$OPENCTI_TOKEN" =~ [\"\'\\] ]]; then
                err "OpenCTI token contains invalid characters (quotes or backslashes)"
                OPENCTI_URL=""
                OPENCTI_TOKEN=""
            fi
        fi
    fi
    if [[ -z "$OPENCTI_URL" ]]; then
        info "Skipping. Set OPENCTI_URL and OPENCTI_TOKEN in gateway.yaml later."
        OPENCTI_URL=""
        OPENCTI_TOKEN=""
    fi
fi

# =============================================================================
# Phase 6: Examiner Identity
# =============================================================================

header "Examiner Identity"

if [[ -z "$EXAMINER_NAME" ]]; then
    DEFAULT_EXAMINER=$(whoami | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | head -c 20)
    while true; do
        EXAMINER_NAME=$(prompt "Examiner identity (name slug)" "$DEFAULT_EXAMINER")
        EXAMINER_NAME=$(echo "$EXAMINER_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | head -c 20)
        [[ -z "$EXAMINER_NAME" ]] && EXAMINER_NAME="$DEFAULT_EXAMINER"
        echo ""
        echo "  Examiner: $EXAMINER_NAME"
        if prompt_yn "Correct?" "y"; then break; fi
    done
else
    EXAMINER_NAME=$(echo "$EXAMINER_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | head -c 20)
fi
[[ -z "$EXAMINER_NAME" ]] && EXAMINER_NAME="examiner"
ok "Examiner: $EXAMINER_NAME"

# Write to config.yaml
VHIR_CONFIG="$HOME/.vhir/config.yaml"
mkdir -p "$HOME/.vhir"
if [[ -f "$VHIR_CONFIG" ]]; then
    # Update examiner in existing config
    if grep -q "^examiner:" "$VHIR_CONFIG" 2>/dev/null; then
        sed -i "s/^examiner:.*/examiner: $EXAMINER_NAME/" "$VHIR_CONFIG"
    else
        echo "examiner: $EXAMINER_NAME" >> "$VHIR_CONFIG"
    fi
else
    echo "examiner: $EXAMINER_NAME" > "$VHIR_CONFIG"
    chmod 600 "$VHIR_CONFIG"
fi

# Write VHIR_EXAMINER to shell profile
SHELL_RC_EXAMINER=""
if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC_EXAMINER="$HOME/.bashrc";
elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC_EXAMINER="$HOME/.zshrc"; fi

if [[ -n "$SHELL_RC_EXAMINER" ]]; then
    if grep -q "VHIR_EXAMINER" "$SHELL_RC_EXAMINER" 2>/dev/null; then
        sed -i "s/^export VHIR_EXAMINER=.*/export VHIR_EXAMINER=\"$EXAMINER_NAME\"/" "$SHELL_RC_EXAMINER"
    else
        # Prepend marker if not already present (Phase 12 will add PATH under it)
        if ! grep -q "# Valhuntir Platform" "$SHELL_RC_EXAMINER" 2>/dev/null; then
            echo "" >> "$SHELL_RC_EXAMINER"
            echo "# Valhuntir Platform" >> "$SHELL_RC_EXAMINER"
        fi
        echo "export VHIR_EXAMINER=\"$EXAMINER_NAME\"" >> "$SHELL_RC_EXAMINER"
    fi
fi
export VHIR_EXAMINER="$EXAMINER_NAME"

# --- Password setup ---
# setup_password() reads from /dev/tty and requires termios.
# Skip in non-interactive mode (AUTO_YES / no terminal).
if [[ -t 0 ]] && ! $AUTO_YES; then
    echo ""
    echo "Setting up your approval password..."
    echo ""
    echo "This password protects finding approvals and HMAC signing."
    echo "You will need it every time you commit reviews (Examiner Portal or CLI)."
    echo "It cannot be recovered if lost — you would need to reset it and"
    echo "re-sign all previously approved findings."
    echo ""
    echo "Minimum 8 characters. Choose something memorable."
    echo ""
    # Flush stdin to discard typeahead before password prompt
    read -r -d '' -t 0.1 < /dev/tty 2>/dev/null || true
    "$VENV_DIR/bin/vhir" config --setup-password || {
        warn "Password setup failed or was cancelled."
        echo "  Set your password later with: vhir config --setup-password"
    }
else
    echo ""
    warn "Skipping password setup (non-interactive mode)."
    echo "  Set your password later with: vhir config --setup-password"
fi

# =============================================================================
# Phase 7: Generate Bearer Token
# =============================================================================

echo ""
info "Generating gateway bearer token..."

# Preserve existing token if gateway.yaml already has one
GATEWAY_CONFIG="$HOME/.vhir/gateway.yaml"
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
# Phase 7b: Static IP Configuration (--remote only)
# =============================================================================

if $REMOTE_MODE; then
    header "Network Configuration"

    echo "  The SIFT gateway connects to remote clients by IP address."
    echo "  A static IP prevents the address from changing after reboot."
    echo ""

    # _ensure_static_ip() is interactive (prompts + reads stdin) and prints
    # status to stdout. We run it directly (not captured) so the user sees
    # prompts, then read the result from ~/.vhir/network.yaml afterward.
    "$VENV_PYTHON" -c "
from vhir_cli.commands.join import _ensure_static_ip
_ensure_static_ip()
" || true

    # Read the configured IP from network.yaml (written by _apply_static_ip)
    STATIC_IP=""
    NETWORK_YAML="$HOME/.vhir/network.yaml"
    if [[ -f "$NETWORK_YAML" ]]; then
        STATIC_IP=$("$VENV_PYTHON" -c "
import yaml
with open('$NETWORK_YAML') as f:
    doc = yaml.safe_load(f) or {}
ip = doc.get('static_ip', '')
if ip:
    print(ip)
" 2>/dev/null || true)
    fi

    if [[ -n "$STATIC_IP" ]]; then
        ok "Static IP: $STATIC_IP"
    else
        info "Skipped static IP. Current address may change after reboot."
    fi
fi

# =============================================================================
# Phase 8: TLS Certificates (--remote only)
# =============================================================================

if $REMOTE_MODE; then
    header "TLS Certificate Generation"

    TLS_DIR="$HOME/.vhir/tls"
    mkdir -p "$TLS_DIR"

    # Determine SAN entries — use static IP if configured, else detect
    HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    [[ -n "$STATIC_IP" ]] && HOST_IP="$STATIC_IP"
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
            -subj "/CN=Valhuntir Gateway CA" 2>/dev/null
        ok "CA certificate generated"

        info "Generating gateway certificate (1-year validity)..."
        openssl genrsa -out "$TLS_DIR/gateway-key.pem" 2048 2>/dev/null

        # Create CSR with SAN
        openssl req -new \
            -key "$TLS_DIR/gateway-key.pem" \
            -out "$TLS_DIR/gateway.csr" \
            -subj "/CN=Valhuntir Gateway" \
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
# Phase 9: Gateway Configuration
# =============================================================================

header "Gateway Configuration"

mkdir -p "$HOME/.vhir"

if [[ -f "$GATEWAY_CONFIG" ]]; then
    info "Existing gateway config found — checking for new backends..."

    # Merge any newly installed backends into existing config
    MERGE_CONFIG="$GATEWAY_CONFIG" \
    MERGE_VENV="$VENV_PYTHON" \
    MERGE_TRIAGE="${INSTALL_TRIAGE:-false}" \
    MERGE_RAG="${INSTALL_RAG:-false}" \
    MERGE_OPENCTI="${INSTALL_OPENCTI:-false}" \
    MERGE_OPENSEARCH="${INSTALL_OPENSEARCH:-false}" \
    "$VENV_PYTHON" << 'MERGE_EOF'
import os, yaml

config_path = os.environ["MERGE_CONFIG"]
venv_python = os.environ["MERGE_VENV"]

with open(config_path) as f:
    config = yaml.safe_load(f) or {}

existing = set(config.get("backends", {}).keys())

# Same backend list as initial generation
expected = [("forensic-mcp", "forensic_mcp"), ("sift-mcp", "sift_mcp"),
            ("case-mcp", "case_mcp"), ("report-mcp", "report_mcp")]
if os.environ.get("MERGE_TRIAGE") == "true":
    expected.append(("windows-triage-mcp", "windows_triage"))
if os.environ.get("MERGE_RAG") == "true":
    expected.append(("forensic-rag-mcp", "rag_mcp"))
if os.environ.get("MERGE_OPENCTI") == "true":
    expected.append(("opencti-mcp", "opencti_mcp"))
if os.environ.get("MERGE_OPENSEARCH") == "true":
    expected.append(("opensearch-mcp", "opensearch_mcp"))

added = []
for name, module in expected:
    if name not in existing:
        entry = {
            "type": "stdio",
            "command": venv_python,
            "args": ["-m", module],
            "env": {
                "VHIR_CASE_DIR": "${VHIR_CASE_DIR}",
                "VHIR_ACTIVE_CASE": "${VHIR_ACTIVE_CASE}",
                "VHIR_EXAMINER": "${VHIR_EXAMINER}",
            },
            "enabled": True,
        }
        if name == "forensic-mcp":
            entry["args"].append("--deferred-tools")
        if name in ("case-mcp", "report-mcp", "forensic-mcp"):
            entry["env"]["VHIR_CASES_DIR"] = "${VHIR_CASES_DIR}"
        if name == "forensic-rag-mcp":
            entry["env"]["ANONYMIZED_TELEMETRY"] = "False"
        if name == "opensearch-mcp":
            entry["env"]["OPENSEARCH_CONFIG"] = os.path.expanduser("~/.vhir/opensearch.yaml")
        config.setdefault("backends", {})[name] = entry
        added.append(name)

if added:
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    for n in added:
        print(f"  Added backend: {n}")
else:
    print("  All expected backends already present.")
MERGE_EOF

else
    info "Generating gateway configuration..."

    # Build config with Python for proper YAML output
    "$VENV_PYTHON" << PYEOF
import yaml, os

venv_python = "$VENV_PYTHON"
remote = "$REMOTE_MODE" == "true"
token = "$TOKEN"
port = int("$GATEWAY_PORT")
examiner = "$EXAMINER_NAME"

config = {
    "gateway": {
        "host": "0.0.0.0" if remote else "127.0.0.1",
        "port": port,
        "log_level": "INFO",
    },
    "api_keys": {
        token: {
            "examiner": examiner,
            "role": "lead",
        },
    },
    "backends": {},
}

if remote:
    config["gateway"]["tls"] = {
        "certfile": os.path.expanduser("~/.vhir/tls/gateway-cert.pem"),
        "keyfile": os.path.expanduser("~/.vhir/tls/gateway-key.pem"),
    }

# Core backends (always installed)
core_backends = [
    ("forensic-mcp", "forensic_mcp"),
    ("sift-mcp", "sift_mcp"),
    ("case-mcp", "case_mcp"),
    ("report-mcp", "report_mcp"),
]

# Optional backends
optional = []
if "$INSTALL_TRIAGE" == "true":
    optional.append(("windows-triage-mcp", "windows_triage"))
if "$INSTALL_RAG" == "true":
    optional.append(("forensic-rag-mcp", "rag_mcp"))
if "$INSTALL_OPENCTI" == "true":
    optional.append(("opencti-mcp", "opencti_mcp"))
if "$INSTALL_OPENSEARCH" == "true":
    optional.append(("opensearch-mcp", "opensearch_mcp"))

for name, module in core_backends + optional:
    entry = {
        "type": "stdio",
        "command": venv_python,
        "args": ["-m", module],
        "env": {
            "VHIR_CASE_DIR": "\${VHIR_CASE_DIR}",
            "VHIR_ACTIVE_CASE": "\${VHIR_ACTIVE_CASE}",
            "VHIR_EXAMINER": "\${VHIR_EXAMINER}",
        },
        "enabled": True,
    }
    if name == 'forensic-mcp':
        entry['args'].append('--deferred-tools')
    if name in ('case-mcp', 'report-mcp', 'forensic-mcp'):
        entry['env']['VHIR_CASES_DIR'] = '\${VHIR_CASES_DIR}'
    if name == "opencti-mcp":
        octi_url = "$OPENCTI_URL"
        octi_token = "$OPENCTI_TOKEN"
        entry["env"]["OPENCTI_URL"] = octi_url if octi_url else "\${OPENCTI_URL}"
        entry["env"]["OPENCTI_TOKEN"] = octi_token if octi_token else "\${OPENCTI_TOKEN}"
    if name == "forensic-rag-mcp":
        entry["env"]["ANONYMIZED_TELEMETRY"] = "False"
    if name == "opensearch-mcp":
        entry["env"]["OPENSEARCH_CONFIG"] = os.path.expanduser("~/.vhir/opensearch.yaml")
    config["backends"][name] = entry

with open("$GATEWAY_CONFIG", "w") as f:
    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
PYEOF

    chmod 600 "$GATEWAY_CONFIG"
    ok "Generated: $GATEWAY_CONFIG"
fi

# =============================================================================
# Phase 10: Manifest
# =============================================================================

MANIFEST="$HOME/.vhir/manifest.json"
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
    ("case-mcp", "case_mcp"),
    ("report-mcp", "report_mcp"),
    ("sift-gateway", "sift_gateway"),
    ("vhir-cli", "vhir_cli"),
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

git_hashes = {}
for repo_name, repo_dir in [("sift-mcp", install_dir), ("vhir", os.path.join(os.path.dirname(install_dir), "vhir"))]:
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            git_hashes[repo_name] = result.stdout.strip()
    except Exception:
        pass

manifest = {
    "version": "1.0",
    "installed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "tier": tier,
    "venv": venv_dir,
    "source": install_dir,
    "gateway_port": port,
    "packages": packages,
    "case_dir": os.path.expanduser("~/cases"),
    "git": git_hashes,
}

with open("$MANIFEST", "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PYEOF

chmod 600 "$MANIFEST"
ok "Manifest written: $MANIFEST"

# =============================================================================
# Phase 11: Default Case Directory
# =============================================================================

CASE_DIR="${CASE_DIR:-$HOME/cases}"
if [[ ! -d "$CASE_DIR" ]]; then
    mkdir -p "$CASE_DIR"
    ok "Created default case directory: $CASE_DIR"
else
    ok "Case directory exists: $CASE_DIR"
fi


# =============================================================================
# Phase 12: Add venv to PATH
# =============================================================================

VHIR_BIN="$VENV_DIR/bin"
SHELL_RC=""
if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc";
elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc"; fi

if [[ -n "$SHELL_RC" ]]; then
    # Clean up pre-rebrand marker and its associated lines
    if grep -q "# ValiHuntIR Platform" "$SHELL_RC" 2>/dev/null; then
        sed -i '/# ValiHuntIR Platform/d' "$SHELL_RC"
        # Remove duplicate PATH lines left by old installer
        sed -i '/\.vhir\/venv\/bin.*# vhir-path/!{/\.vhir\/venv\/bin/d;}' "$SHELL_RC" 2>/dev/null || true
    fi
    if grep -q "# Valhuntir Platform" "$SHELL_RC" 2>/dev/null; then
        # Marker exists — update PATH line in-place (handles changed venv path)
        if grep -q '# vhir-path' "$SHELL_RC" 2>/dev/null; then
            sed -i "s|^export PATH=.*# vhir-path|export PATH=\"$VHIR_BIN:\$PATH\"  # vhir-path|" "$SHELL_RC"
        elif grep -q '\.vhir/venv/bin' "$SHELL_RC" 2>/dev/null; then
            # Legacy install without tag — replace and add tag
            sed -i "s|^export PATH=.*\.vhir/venv/bin.*|export PATH=\"$VHIR_BIN:\$PATH\"  # vhir-path|" "$SHELL_RC"
        else
            # Marker exists but no PATH line — append after marker
            echo "export PATH=\"$VHIR_BIN:\$PATH\"  # vhir-path" >> "$SHELL_RC"
        fi
        ok "Updated venv PATH in $SHELL_RC"
    else
        echo "" >> "$SHELL_RC"
        echo "# Valhuntir Platform" >> "$SHELL_RC"
        echo "export PATH=\"$VHIR_BIN:\$PATH\"  # vhir-path" >> "$SHELL_RC"
        ok "Added venv to PATH in $SHELL_RC"
    fi

    # VHIR_CASES_DIR — so vhir CLI resolves ~/cases (or custom --cases-dir)
    if grep -q "VHIR_CASES_DIR" "$SHELL_RC" 2>/dev/null; then
        sed -i "s|^export VHIR_CASES_DIR=.*|export VHIR_CASES_DIR=\"$CASE_DIR\"|" "$SHELL_RC"
    else
        echo "export VHIR_CASES_DIR=\"$CASE_DIR\"" >> "$SHELL_RC"
    fi
else
    warn "No .bashrc or .zshrc found. Add to your shell profile: export PATH=\"$VHIR_BIN:\$PATH\""
fi
if [[ ":$PATH:" != *":$VHIR_BIN:"* ]]; then
    export PATH="$VHIR_BIN:$PATH"
fi
export VHIR_CASES_DIR="$CASE_DIR"

# Symlink: valhuntir → vhir (users expect the product name to work)
if [[ -f "$VHIR_BIN/vhir" && ! -e "$VHIR_BIN/valhuntir" ]]; then
    ln -sf "$VHIR_BIN/vhir" "$VHIR_BIN/valhuntir"
fi

# Tab completion
if [[ -z "${SHELL_RC:-}" ]]; then
    if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc";
    elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc"; fi
fi
if command -v register-python-argcomplete &>/dev/null; then
    COMP_LINE='eval "$(register-python-argcomplete vhir)"'
    if [[ -n "$SHELL_RC" ]] && ! grep -q "register-python-argcomplete vhir" "$SHELL_RC" 2>/dev/null; then
        echo "$COMP_LINE" >> "$SHELL_RC"
        ok "Added vhir tab completion to $SHELL_RC"
    fi
fi

# =============================================================================
# Phase 13: Systemd Service + Gateway Start
# =============================================================================

header "Starting Gateway"

# Generate startup script (always regenerate — contains paths)
GATEWAY_START="$HOME/.vhir/start-gateway.sh"
cat > "$GATEWAY_START" << SCRIPT
#!/usr/bin/env bash
# Start Valhuntir Gateway
export VHIR_EXAMINER="$EXAMINER_NAME"
export VHIR_CASES_DIR="$CASE_DIR"
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
GW_DIRECT_FAILED=false
if curl -sf ${CURL_EXTRA:+"$CURL_EXTRA"} "$HEALTH_URL" &>/dev/null; then
    ok "Gateway already running on port $GATEWAY_PORT"
elif ! $MANUAL_START; then
    info "Starting gateway on port $GATEWAY_PORT..."
    "$VENV_DIR/bin/python" -m sift_gateway --config "$GATEWAY_CONFIG" >/dev/null 2>&1 &
    GATEWAY_PID=$!

    # Wait for health endpoint (backends need time to start)
    # Don't warn here — systemd fallback may recover. Track failure silently.
    GW_READY=false
    GW_DIRECT_FAILED=false
    for i in 1 2 3 4 5 6; do
        sleep 1
        if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
            GW_DIRECT_FAILED=true
            GATEWAY_PID=""
            break
        fi
        if curl -sf ${CURL_EXTRA:+"$CURL_EXTRA"} "$HEALTH_URL" &>/dev/null; then
            ok "Gateway running on port $GATEWAY_PORT"
            GW_READY=true
            break
        fi
    done
    if [[ -n "${GATEWAY_PID:-}" ]] && ! $GW_READY; then
        GW_DIRECT_FAILED=true
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

        cat > "$SYSTEMD_DIR/vhir-gateway.service" << SERVICE
[Unit]
Description=Valhuntir Gateway
After=network.target

[Service]
ExecStart=$VENV_DIR/bin/python -m sift_gateway --config $GATEWAY_CONFIG
Environment=VHIR_EXAMINER=$EXAMINER_NAME
Environment=VHIR_CASES_DIR=$CASE_DIR
PassEnvironment=DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR
MemoryMax=4G
KillMode=process
TimeoutStopSec=10
Restart=always
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
        systemctl --user enable vhir-gateway.service 2>/dev/null && \
            ok "Systemd service enabled (auto-start at login)"
        if systemctl --user is-active vhir-gateway.service &>/dev/null; then
            systemctl --user restart vhir-gateway.service 2>/dev/null && \
                ok "Gateway restarted via systemd" || \
                warn "Gateway restart failed. Check $GATEWAY_CONFIG"
        elif systemctl --user start vhir-gateway.service 2>/dev/null; then
            ok "Gateway started via systemd"
        else
            warn "Gateway failed to start. Check $GATEWAY_CONFIG"
            info "Manual start: $GATEWAY_START"
        fi

        # Enable lingering so service runs without active login session
        if command -v loginctl &>/dev/null; then
            loginctl enable-linger "$(whoami)" 2>/dev/null && \
                ok "Linger enabled (gateway runs without active login)" || true
        fi
    else
        warn "systemd user sessions not available (WSL or container?)"
        if $GW_DIRECT_FAILED; then
            warn "Gateway failed to start. Check $GATEWAY_CONFIG"
        fi
        ok "Use startup script: $GATEWAY_START"
        if [[ -n "${GATEWAY_PID:-}" ]] && ! $GW_DIRECT_FAILED; then
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
# Phase 13b: Multi-Machine Setup (remote mode only)
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
        JOIN_OUTPUT=$("$VENV_DIR/bin/vhir" setup join-code 2>&1) || true
        JOIN_CODE=$(echo "$JOIN_OUTPUT" | grep "Join code:" | awk '{print $3}')

        if [[ -n "$JOIN_CODE" ]]; then
            GW_URL="https://$HOST_IP:$GATEWAY_PORT"
            echo ""
            echo -e "${BOLD}Remote client setup${NC} (run on the machine where your LLM client runs):"
            echo ""
            echo "  Linux (full support):"
            echo "    curl -fsSL https://raw.githubusercontent.com/AppliedIR/Valhuntir/main/setup-client-linux.sh \\"
            echo "      | bash -s -- --sift=$GW_URL --code=$JOIN_CODE"
            echo ""
            echo "  macOS:"
            echo "    curl -fsSL https://raw.githubusercontent.com/AppliedIR/Valhuntir/main/setup-client-macos.sh \\"
            echo "      | bash -s -- --sift=$GW_URL --code=$JOIN_CODE"
            echo ""
            echo "  Windows (PowerShell):"
            echo "    Invoke-WebRequest -Uri https://raw.githubusercontent.com/AppliedIR/Valhuntir/main/setup-client-windows.ps1 -OutFile setup-client-windows.ps1"
            echo "    .\\setup-client-windows.ps1 -Sift $GW_URL -Code $JOIN_CODE"
            echo ""
            echo "  Note: Your LLM client must run locally on your machine to reach the"
            echo "  SIFT gateway. Cloud-hosted LLM services cannot connect to internal"
            echo "  network addresses."

            # Offer to generate a second join code for Windows wintools
            if prompt_yn "Will you connect a Windows forensic workstation?" "n"; then
                WIN_OUTPUT=$("$VENV_DIR/bin/vhir" setup join-code 2>&1) || true
                WIN_CODE=$(echo "$WIN_OUTPUT" | grep "Join code:" | awk '{print $3}')
                if [[ -n "$WIN_CODE" ]]; then
                    echo ""
                    echo -e "${BOLD}Windows Workstation${NC}"
                    echo "  The Windows installer will prompt for:"
                    echo "    Join code:  $WIN_CODE"
                    echo "    SIFT IP:    $HOST_IP"
                    echo "    Port:       $GATEWAY_PORT"
                    echo ""
                    echo "  If the installer is not already running:"
                    echo "    .\\setup-windows.ps1"
                    echo ""
                fi
            fi

            echo ""
            echo "  Join codes expire in 2 hours. Generate new codes with:"
            echo "    vhir setup join-code"
        else
            warn "Could not generate join code. Generate one later with:"
            echo "    vhir setup join-code"
        fi
    else
        warn "Gateway not responding. Start it first, then generate join codes:"
        echo "    $GATEWAY_START"
        echo "    vhir setup join-code"
    fi

    echo ""
    echo -e "${BOLD}SSH Access${NC}"
    echo "  For CLI operations (approve, review, report), SSH into this machine:"
    echo "    ssh $(whoami)@$HOST_IP"
fi

# =============================================================================
# Phase 14: LLM Client Configuration
# =============================================================================

header "LLM Client Configuration"

if $REMOTE_MODE; then
    SIFT_URL="https://127.0.0.1:$GATEWAY_PORT"
else
    SIFT_URL="http://127.0.0.1:$GATEWAY_PORT"
fi

# Prompt for client if not set via --client flag
if [[ -z "$CLIENT" ]] && ! $AUTO_YES; then
    echo ""
    echo "Which LLM client will connect to Valhuntir?"
    echo ""
    echo "  1. Claude Code      CLI agent (full forensic controls)"
    echo "  2. Claude Desktop   Desktop app (MCP-only)"
    echo "  3. LibreChat        Web UI (MCP-only)"
    echo "  4. Other / manual   Raw config for any MCP client"
    echo ""
    CLIENT_CHOICE=$(prompt "Choose" "1")
    case "$CLIENT_CHOICE" in
        1) CLIENT="claude-code" ;;
        2) CLIENT="claude-desktop" ;;
        3) CLIENT="librechat" ;;
        4) CLIENT="other" ;;
        *) CLIENT="other" ;;
    esac
elif [[ -z "$CLIENT" ]]; then
    # -y mode: default to claude-code
    CLIENT="claude-code"
fi

"$VENV_DIR/bin/vhir" setup client --client="$CLIENT" --sift="$SIFT_URL" -y \
    || warn "Client configuration failed. Run manually: vhir setup client"


# Global deployment message for claude-code
if grep -qE '"forensic-mcp"|"vhir"' "$HOME/.claude.json" 2>/dev/null; then
    echo ""
    echo -e "${BOLD}Forensic controls deployed globally.${NC}"
    echo "Claude Code can be launched from any directory on this machine."
    echo "Audit logging, permission guardrails, and MCP tools will always apply."
    echo ""
    echo "Run /welcome in Claude Code to verify your installation and get oriented."
fi

# =============================================================================
# Summary
# =============================================================================

header "Installation Complete"

PROTOCOL="http"
BIND_ADDR="127.0.0.1"
if $REMOTE_MODE; then
    PROTOCOL="https"
    BIND_ADDR="0.0.0.0"
fi

echo "Tier:        $TIER_DISPLAY"
echo "Examiner:    $EXAMINER_NAME"
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
    echo "  (Stored in gateway config. Remote clients use join codes instead.)"
    echo ""
    echo -e "${BOLD}TLS CA certificate:${NC}"
    echo "  $HOME/.vhir/tls/ca-cert.pem"
else
    echo "Token:       stored in $GATEWAY_CONFIG"
fi

# =============================================================================
# Data Maintenance
# =============================================================================

if $INSTALL_RAG || $INSTALL_TRIAGE; then
    echo ""
    echo "Checking installed data for updates..."
    echo ""
fi

RAG_STALE_COUNT=""
if $INSTALL_RAG; then
    RAG_STALE_COUNT=$(timeout 60 bash -c "\"$VENV_PYTHON\" -m rag_mcp.status --json 2>/dev/null" | \
        "$VENV_PYTHON" -c "
import sys, json
data = json.load(sys.stdin)
print(sum(1 for s in data.get('online_sources', []) if s.get('has_update')))
" 2>/dev/null) || RAG_STALE_COUNT=""

    if [[ -n "$RAG_STALE_COUNT" ]] && [[ "$RAG_STALE_COUNT" -gt 0 ]] 2>/dev/null; then
        echo -e "  ${BOLD}RAG knowledge base:${NC} $RAG_STALE_COUNT of 23 sources have updates available."
        echo "  Refresh now or later with: $VENV_PYTHON -m rag_mcp.refresh"
        echo "  Time: a few minutes to a couple of hours depending on changes and CPU."
        if ! $AUTO_YES; then
            if prompt_yn "  Refresh now?" "n"; then
                ANONYMIZED_TELEMETRY=False "$VENV_PYTHON" -m rag_mcp.refresh
            fi
        fi
    elif [[ -n "$RAG_STALE_COUNT" ]] && [[ "$RAG_STALE_COUNT" -eq 0 ]] 2>/dev/null; then
        ok "RAG knowledge base: all 23 sources are current."
    else
        warn "Could not check RAG status. Check later with: $VENV_PYTHON -m rag_mcp.status"
    fi
fi

if $INSTALL_TRIAGE; then
    ok "Triage databases: installed. Re-download when needed: $VENV_PYTHON -m windows_triage.scripts.download_databases"
fi

if $INSTALL_RAG || $INSTALL_TRIAGE; then
    echo ""
fi

# =============================================================================
# Next Steps (always last)
# =============================================================================

echo ""
echo -e "${BOLD}Documentation:${NC} https://appliedir.github.io/Valhuntir/"

echo ""
echo -e "${BOLD}Next steps:${NC}"
echo "  Reload your shell profile (new terminals load it automatically):"
echo "    source ${SHELL_RC:-~/.bashrc}"
echo ""

case "$CLIENT" in
    claude-code)
        echo "  To start an investigation:"
        echo "    vhir case init <case-name>"
        echo "    cd ~/cases/<case-name>"
        echo "    claude"
        echo ""
        echo "  Type /welcome inside Claude Code for an introduction."
        ;;
    claude-desktop)
        echo "  To start an investigation:"
        echo "    vhir case init <case-name>"
        echo "  Then open Claude Desktop and ask it to activate the case."
        ;;
    librechat)
        echo "  To start an investigation:"
        echo "    vhir case init <case-name>"
        echo "  Then open LibreChat and ask the LLM to activate the case."
        ;;
    *)
        echo "  To start an investigation:"
        echo "    vhir case init <case-name>"
        echo "  Then connect your MCP client and ask the LLM to activate the case."
        ;;
esac
echo ""
echo "  To connect a Windows forensic workstation:"
echo "    Run setup-windows.ps1 on the Windows machine and follow the prompts."

if $REMOTE_MODE; then
    echo ""
    echo "Remote clients: run the setup commands shown above on each client machine."
fi
echo ""

# Exit with error if smoke tests failed
if (( INSTALL_ERRORS > 0 )); then
    exit 1
fi
