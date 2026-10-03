#!/usr/bin/env bash
#
# quickstart-lite.sh — Valhuntir Lite Installer
#
# Installs Valhuntir Lite: forensic knowledge MCPs + discipline files + audit hook.
# No gateway, no sandbox, no deny rules. Claude runs tools directly via Bash.
#
# Usage:
#   ./quickstart-lite.sh                          # Full install (default)
#   ./quickstart-lite.sh --quick                  # Packages + config only (~2 min)
#   ./quickstart-lite.sh --custom                 # Choose data to download/build
#   ./quickstart-lite.sh --no-rag                 # Skip RAG index build
#   ./quickstart-lite.sh --rebuild-rag            # Force rebuild RAG index
#   ./quickstart-lite.sh --opencti                # Add OpenCTI MCP
#   ./quickstart-lite.sh --remnux=HOST:PORT       # Add REMnux MCP
#   ./quickstart-lite.sh -y                       # Non-interactive
#   ./quickstart-lite.sh -h                       # Full help
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; exit 1; }

# Whether $1's bytes are a version of $2 in the sift clone's git history.
_shipped() {
    local blob
    blob=$(git hash-object "$1" 2>/dev/null) || return 1
    git -C "$SCRIPT_DIR" log HEAD --follow --format= --raw --no-abbrev -- "${2#"$SCRIPT_DIR"/}" 2>/dev/null |
        awk '/^:/ { print $3; print $4 }' | grep -x "$blob" >/dev/null
}
# A file in the user's project: absent or identical, deployed quietly; a version
# Valhuntir shipped, replaced; one the user changed, replaced only with -y or a
# "y" at a terminal, after a backup, and otherwise left alone.
UNDO_LINES=()
_deploy_file() {  # <new content> <dest> <source in the sift clone, or ""> <name>
    local new="$1" dest="$2" src="$3" name="$4" base bak n=1 reply=""
    if [[ ! -e "$dest" ]]; then
        cp "$new" "$dest"
        ok "Deployed $name"
        return 0
    fi
    cmp -s "$new" "$dest" && return 0
    if [[ -n "$src" ]] && _shipped "$dest" "$src"; then
        cp "$new" "$dest"
        ok "Updated $name (an earlier Valhuntir version)"
        return 0
    fi
    if [[ "$YES" != "true" ]]; then
        if [[ -t 0 ]]; then
            diff -u "$dest" "$new" || true
            read -rp "  Replace your $dest with Valhuntir's? [y/N] " reply || reply=""
        fi
        if [[ ! "$reply" =~ ^[Yy] ]]; then
            warn "$dest differs from Valhuntir's: NOT deployed. Re-run in a terminal or with -y to replace it (backed up first)."
            return 0
        fi
    fi
    base="$dest.vhir-backup-$(date -u +%Y%m%dT%H%M%SZ)"
    bak="$base"
    while [[ -e "$bak" ]]; do n=$((n + 1)); bak="$base-$n"; done
    cp -p "$dest" "$bak"
    cat "$new" > "$dest"
    warn "Replaced $dest; your version is at $bak"
    UNDO_LINES+=("cp -p $(printf %q "$bak") $(printf %q "$dest")")
}
header() { echo -e "\n${BOLD}=== $1 ===${NC}"; }

_write_install_marker() {
    local marker="$HOME/.vhir/lite-install.json"
    local version commit installed_at
    version=$("$VENV_PYTHON" -c "
try:
    from importlib.metadata import version
    print(version('sift-common'))
except Exception:
    print('unknown')
" 2>/dev/null) || version="unknown"
    commit=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null) || commit="unknown"
    installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    "$VENV_PYTHON" -c "
import json, sys
marker = {
    'version': sys.argv[1],
    'commit': sys.argv[2],
    'installed_at': sys.argv[3],
    'source_dir': sys.argv[4],
    'rag': sys.argv[5] == 'true',
    'rag_method': sys.argv[6],
    'triage': sys.argv[7] == 'true',
}
if sys.argv[9]:  # the PyTorch build the user chose (asked, or --cpu/--gpu)
    marker['torch_variant'] = sys.argv[9]
with open(sys.argv[8], 'w') as f:
    json.dump(marker, f, indent=2)
    f.write('\n')
" "$version" "$commit" "$installed_at" "$SCRIPT_DIR" \
  "$INSTALL_RAG" "${RAG_METHOD:-skipped}" "$INSTALL_TRIAGE" "$marker" "${TORCH_RECORD:-}"
}

_validate_credential() {
    # Reject quotes and backslashes that would break JSON output.
    # Returns 0 if valid, 1 if invalid. Matches setup-sift.sh:995,1001.
    local val="$1" label="$2"
    if [[ "$val" =~ [\"\'\\] ]]; then
        warn "$label contains invalid characters (quotes or backslashes). Skipped."
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
YES=false
MODE=""
INSTALL_OPENCTI=false
INSTALL_MSLEARN=false
INSTALL_ZELTSER=false
INSTALL_REGISTRY=false
REMNUX_ADDR=""
TORCH_FLAG=""  # cpu or gpu: the PyTorch build, given on the command line

for arg in "$@"; do
    case "$arg" in
        -y|--yes) YES=true ;;
        --opencti) INSTALL_OPENCTI=true ;;
        --mslearn) INSTALL_MSLEARN=true ;;
        --zeltser) INSTALL_ZELTSER=true ;;
        --registry) INSTALL_REGISTRY=true ;;
        --remnux=*) REMNUX_ADDR="${arg#--remnux=}" ;;
        --wintools=*)
            echo "ERROR: Wintools integration requires Full Valhuntir (setup-sift.sh)."
            echo "Lite cannot share case data or retrieve large extraction results."
            echo "See: https://appliedir.github.io/Valhuntir/deployment/"
            exit 1
            ;;
        --quick)   MODE="quick" ;;
        --custom)  MODE="custom" ;;
        --no-rag)     NO_RAG=true ;;
        --no-triage)  NO_TRIAGE=true ;;
        --rebuild-rag)     REBUILD_RAG=true ;;
        --rebuild-triage)  REBUILD_TRIAGE=true ;;
        --venv-only) VENV_ONLY=true ;;
        --cpu|--gpu)
            if [[ -n "$TORCH_FLAG" && "$TORCH_FLAG" != "${arg#--}" ]]; then
                echo "Use only one of --cpu and --gpu"
                exit 1
            fi
            TORCH_FLAG="${arg#--}" ;;
        --completions)
            cat << 'COMP'
_quickstart_lite() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="--quick --custom --no-rag --no-triage --rebuild-rag
        --rebuild-triage --venv-only --opencti --mslearn
        --zeltser --registry --cpu --gpu --yes --help --completions"
    if [[ "$cur" == --remnux=* ]]; then
        return 0
    fi
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts --remnux=" -- "$cur") )
        if [[ ${#COMPREPLY[@]} -eq 1 ]] && [[ "${COMPREPLY[0]}" == *"=" ]]; then
            compopt -o nospace
        fi
    fi
}
complete -F _quickstart_lite quickstart-lite.sh
complete -F _quickstart_lite ./quickstart-lite.sh
COMP
            exit 0
            ;;
        -h|--help)
            cat << 'HELPEOF'
Usage: quickstart-lite.sh [options]

Valhuntir Lite installer. Installs forensic knowledge MCPs, discipline files,
and audit hooks for Claude Code.

Modes:
  (default)           Install everything: packages, data, config, optional MCPs
  --quick             Packages + config only, skip data + optional MCPs (~2 min)
  --custom            Interactively choose which data to download/build

Data control:
  --no-rag            Skip RAG index build
  --no-triage         Skip triage DB download
  --rebuild-rag       Force delete and rebuild RAG index from scratch
  --rebuild-triage    Force delete and re-download triage databases

Scope:
  --venv-only         Update Python packages only (no config, no data)

PyTorch (knowledge search):
  --cpu, --gpu        PyTorch build (default: asked, or the installed build;
                      CPU on a new install). Not used on macOS.

Optional MCPs:
  --opencti           Add OpenCTI threat intelligence MCP
  --remnux=HOST:PORT  Add REMnux malware analysis MCP
  --mslearn           Add Microsoft Learn documentation MCP
  --zeltser           Add Zeltser IR Writing MCP
  --registry          Download optional registry baseline (large)

General:
  -y, --yes           Non-interactive (accept all defaults)
  --completions       Output bash completion script (eval to enable tab completion)
  -h, --help          Show this help

Examples:
  ./quickstart-lite.sh                        # Full install (default)
  ./quickstart-lite.sh --quick                # Update code + config after git pull
  ./quickstart-lite.sh --no-rag               # Full install but skip RAG build
  ./quickstart-lite.sh --rebuild-rag          # Force fresh RAG index
  ./quickstart-lite.sh --opencti --mslearn    # Add optional MCPs
  ./quickstart-lite.sh --quick --opencti      # Quick + add OpenCTI

Data can be built/downloaded later:
  python -m rag_mcp.build                              # Build RAG index
  python -m windows_triage.scripts.download_databases   # Download triage DBs
HELPEOF
            exit 0
            ;;
        *) warn "Unknown option: $arg"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Phase gating
# ---------------------------------------------------------------------------
INSTALL_RAG=true
INSTALL_TRIAGE=true
SKIP_OPTIONAL_MCPS=false

case "$MODE" in
    quick)
        INSTALL_RAG=false
        INSTALL_TRIAGE=false
        SKIP_OPTIONAL_MCPS=true
        ;;
    custom)
        if [[ "$YES" != "true" ]]; then
            echo ""
            echo -e "${BOLD}Always installed:${NC}"
            echo "  sift-common       — Shared audit and logging"
            echo ""
            echo -e "${BOLD}Optional packages + data:${NC}"
            read -rp "  Install windows-triage + databases (~1.1 GB download, ~6 GB on disk)? [Y/n] " reply
            [[ "$reply" =~ ^[Nn] ]] && INSTALL_TRIAGE=false
            read -rp "  Install forensic-rag + build index (~7 GB ML deps, ~15-25 min)? [Y/n] " reply
            [[ "$reply" =~ ^[Nn] ]] && INSTALL_RAG=false
        fi
        ;;
esac

# Skip overrides (--no-rag, --no-triage)
[[ "${NO_RAG:-}" == "true" ]]     && INSTALL_RAG=false
[[ "${NO_TRIAGE:-}" == "true" ]]  && INSTALL_TRIAGE=false

# Rebuild overrides (--rebuild-rag, --rebuild-triage) — force install
[[ "${REBUILD_RAG:-}" == "true" ]]     && INSTALL_RAG=true
[[ "${REBUILD_TRIAGE:-}" == "true" ]]  && INSTALL_TRIAGE=true

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
# Find the sift-mcp source directory (where this script lives)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# If run from a curl download, the repo must already be cloned
if [[ ! -d "$SCRIPT_DIR/packages" ]]; then
    fail "Cannot find packages/ directory. Clone the repo first:
    git clone https://github.com/AppliedIR/sift-mcp.git
    cd sift-mcp
    ./quickstart-lite.sh"
fi

PROJECT_DIR="$(pwd)"
VENV_DIR="$HOME/.vhir/venv"
VENV_PYTHON="$VENV_DIR/bin/python"
DB_DIR="$HOME/.vhir/triage-db"
INDEX_DIR="$HOME/.vhir/rag-index"

echo -e "${BOLD}Valhuntir Lite Installer${NC}"
echo "Source:  $SCRIPT_DIR"
echo "Project: $PROJECT_DIR"
echo "Venv:    $VENV_DIR"

MARKER_FILE="$HOME/.vhir/lite-install.json"
if [[ -f "$MARKER_FILE" ]]; then
    PREV_COMMIT=$(python3 -c "
import json, sys
try:
    m = json.load(open(sys.argv[1]))
    print(m.get('commit', ''))
except Exception:
    print('')
" "$MARKER_FILE" 2>/dev/null) || PREV_COMMIT=""

    if [[ -n "$PREV_COMMIT" ]]; then
        CURR_COMMIT=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null) || CURR_COMMIT=""
        if [[ "$PREV_COMMIT" == "$CURR_COMMIT" ]]; then
            echo "Status:  Up to date ($CURR_COMMIT)"
        else
            BEHIND=$(git -C "$SCRIPT_DIR" log --oneline "$PREV_COMMIT..$CURR_COMMIT" 2>/dev/null | wc -l) || BEHIND="?"
            echo "Status:  ${BEHIND} commits since last install ($PREV_COMMIT → $CURR_COMMIT)"
        fi
    fi
fi

if [[ "$YES" != "true" ]]; then
    echo ""
    read -rp "Continue? [Y/n] " reply
    [[ "$reply" =~ ^[Nn] ]] && exit 0
fi

# --- PyTorch build: knowledge search (forensic-rag) embeds with PyTorch ---
# The flag, else the build already in the venv, else CPU. Asked only when
# interactive and either the venv has PyTorch but was never asked (the record
# is in lite-install.json) or RAG is being installed without it. macOS has one
# build (PyPI's, no CUDA) and is never asked.
TORCH_INSTALLED=""
if [[ -x "$VENV_PYTHON" ]]; then
    TORCH_INSTALLED=$("$VENV_PYTHON" -c \
        'import importlib.metadata as m; print(m.version("torch"))' 2>/dev/null) || true
fi
TORCH_RECORD=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("torch_variant", ""))' \
    "$MARKER_FILE" 2>/dev/null) || true
if [[ "$(uname -s)" == "Darwin" ]]; then
    if [[ -n "$TORCH_FLAG" ]]; then
        echo "  --$TORCH_FLAG is not applicable on macOS (PyPI's PyTorch has no CUDA)."
    fi
    TORCH_VARIANT=pypi
    TORCH_RECORD=""
elif [[ -n "$TORCH_FLAG" ]]; then
    TORCH_VARIANT=$TORCH_FLAG
    TORCH_RECORD=$TORCH_FLAG
else
    if [[ "$TORCH_INSTALLED" == *+cpu ]]; then
        TORCH_VARIANT=cpu
    elif [[ -n "$TORCH_INSTALLED" ]]; then
        TORCH_VARIANT=gpu
    else
        TORCH_VARIANT=cpu
    fi
    if [[ "$YES" != "true" ]] && { { [[ -n "$TORCH_INSTALLED" && -z "$TORCH_RECORD" ]]; } \
        || { [[ "$INSTALL_RAG" == "true" && -z "$TORCH_INSTALLED" ]]; }; }; then
        if command -v nvidia-smi &>/dev/null && timeout 10 nvidia-smi -L 2>/dev/null | grep -q '^GPU'; then
            gpu_found="an NVIDIA GPU was found"
        else
            gpu_found="no NVIDIA GPU was found"
        fi
        echo ""
        echo -e "${BOLD}PyTorch for knowledge search${NC} ($gpu_found):"
        if [[ -n "$TORCH_INSTALLED" ]]; then
            echo "  Installed now: the $(tr a-z A-Z <<< "$TORCH_VARIANT") build (torch $TORCH_INSTALLED)."
            echo "  Choosing the other build replaces it; CUDA packages it leaves are listed after the install."
        fi
        echo "  cpu  about 0.2 GB download, 0.7 GB on disk; slower index builds"
        echo "  gpu  about 3 GB download, 5.4 GB on disk; much faster index builds; needs an NVIDIA GPU"
        while true; do
            read -rp "  PyTorch build (cpu/gpu) [cpu]: " reply
            reply=$(tr A-Z a-z <<< "${reply:-cpu}")
            case "$reply" in
                cpu|gpu) TORCH_VARIANT=$reply; break ;;
                *) echo "  Please enter cpu or gpu." ;;
            esac
        done
        TORCH_RECORD=$TORCH_VARIANT
    else
        echo "  PyTorch build: $TORCH_VARIANT (switch with --cpu or --gpu)."
    fi
fi

# ==========================================================================
# Phase 1: Python Environment
# ==========================================================================
header "Phase 1: Python Environment"

# Ensure uv is available
if ! command -v uv &>/dev/null; then
    echo "  Installing uv package manager..."
    if ! curl -LsSf https://astral.sh/uv/install.sh | sh 2>/dev/null; then
        fail "uv installation failed. Install manually: curl -LsSf https://astral.sh/uv/install.sh | sh"
    fi
    export PATH="$HOME/.local/bin:$PATH"
fi

# Older uv installs from the lock without checking its hashes, and says
# nothing; --torch-backend (the CPU PyTorch lock) first appears in 0.6.9.
UV_VERSION=$(uv --version 2>/dev/null | awk '{print $2}')
if ! awk -v v="${UV_VERSION:-0}" 'BEGIN { split(v, p, "."); a = p[1] + 0; b = p[2] + 0; c = p[3] + 0
        exit !(a > 0 || b > 6 || (b == 6 && c >= 9)) }'; then
    fail "uv ${UV_VERSION:-unknown} is older than 0.6.9, which this installer needs for --torch-backend and hash checks. Update it: uv self update (or reinstall: curl -LsSf https://astral.sh/uv/install.sh | sh)"
fi

# Third-party packages install at the versions and hashes in the lock. The
# CPU PyTorch lock pins torch from the PyTorch CPU index, which only
# --torch-backend reaches; 2.14.0+cpu satisfies the GPU lock's ==2.14.0, so a
# switch to GPU has to reinstall it.
LOCK="$SCRIPT_DIR/deps/vhir.lock"
if [[ "$TORCH_VARIANT" == cpu ]]; then
    LOCK="$SCRIPT_DIR/deps/vhir-cpu.lock"
fi
[[ -f "$LOCK" ]] || fail "Dependency lock not found: $LOCK"
LOCKED=(-c "$LOCK" -b "$LOCK")
if [[ "$TORCH_VARIANT" == cpu ]]; then
    LOCKED+=(--torch-backend cpu)
elif [[ "$TORCH_VARIANT" == gpu && "$TORCH_INSTALLED" == *+cpu ]]; then
    LOCKED+=(--reinstall-package torch)
fi
torch_index_hint() {
    if [[ "$TORCH_VARIANT" == cpu ]]; then
        echo "  CPU PyTorch comes from download.pytorch.org; if you use a package mirror, re-run with --gpu."
    fi
}

# Bridge existing pip mirror config
[ -n "${PIP_INDEX_URL:-}" ] && export UV_INDEX_URL="$PIP_INDEX_URL"

# Verify Python 3.10+ (required by all packages)
PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
PY_MAJOR=${PY_VERSION%%.*}
PY_MINOR=${PY_VERSION##*.}
if (( PY_MAJOR < 3 || (PY_MAJOR == 3 && PY_MINOR < 10) )); then
    fail "Python 3.10+ required (found $PY_VERSION). Install Python 3.10 or later."
fi

if [[ ! -f "$VENV_PYTHON" ]]; then
    uv venv "$VENV_DIR" --seed --quiet
    ok "Created venv at $VENV_DIR (Python $PY_VERSION)"
else
    ok "Venv exists at $VENV_DIR"
fi

# Packages already in the venv that the lock names (pip's seeds, or what an
# earlier OpenCTI install pulled in) join the first locked install, so it
# moves them to the lock too.
LOCK_HELD_LIST=$("$VENV_PYTHON" "$SCRIPT_DIR/deps/check-lock.py" --installed --lock "$LOCK") \
    || fail "Cannot read the venv's packages against the dependency lock."
read -ra LOCK_HELD <<< "$LOCK_HELD_LIST"

# sift-common always installed
pkg_dir="$SCRIPT_DIR/packages/sift-common"
if [[ -d "$pkg_dir" ]]; then
    uv pip install --python "$VENV_PYTHON" --quiet "${LOCKED[@]}" ${LOCK_HELD[@]+"${LOCK_HELD[@]}"} -e "$pkg_dir" \
        || { torch_index_hint; fail "Failed to install sift-common"; }
    ok "Installed sift-common"
else
    warn "sift-common not found at $pkg_dir"
fi

if [[ "$INSTALL_RAG" == "true" ]]; then
    pkg_dir="$SCRIPT_DIR/packages/forensic-rag"
    if [[ -d "$pkg_dir" ]]; then
        echo "  Installing forensic-rag (downloads ML dependencies, may take several minutes)..."
        uv pip install --python "$VENV_PYTHON" --quiet "${LOCKED[@]}" -e "$pkg_dir" \
            || { torch_index_hint; fail "Failed to install forensic-rag"; }
        ok "Installed forensic-rag"
    else
        warn "forensic-rag not found at $pkg_dir"
    fi
fi

if [[ "$INSTALL_TRIAGE" == "true" ]]; then
    pkg_dir="$SCRIPT_DIR/packages/windows-triage"
    if [[ -d "$pkg_dir" ]]; then
        uv pip install --python "$VENV_PYTHON" --quiet "${LOCKED[@]}" -e "$pkg_dir"
        ok "Installed windows-triage"
    else
        warn "windows-triage not found at $pkg_dir"
    fi
fi

"$VENV_PYTHON" "$SCRIPT_DIR/deps/check-lock.py" --strict --lock "$LOCK" \
    || fail "Installed packages differ from the dependency lock (listed above)."

# OpenCTI's client installs unlocked, after the locked packages: pycti pins
# its own. Reinstalled whenever it's already there, since the locked installs
# above may have moved what it pins, even on a run that didn't select it.
_install_opencti_pkg() {
    [[ "${OPENCTI_PKG_DONE:-}" == "true" ]] && return 0
    local pkg_dir="$SCRIPT_DIR/packages/opencti"
    if [[ ! -d "$pkg_dir" ]]; then
        warn "opencti-mcp not found at $pkg_dir"
        return 0
    fi
    uv pip install --python "$VENV_PYTHON" --quiet -e "$pkg_dir"
    ok "Installed opencti-mcp"
    OPENCTI_PKG_DONE=true
}
# The packages must agree with each other, whether or not OpenCTI's step ran
# (a leftover pycti is skipped by --strict); what pycti moved is listed.
_final_check() {
    "$VENV_PYTHON" "$SCRIPT_DIR/deps/check-lock.py" --final --lock "$LOCK" \
        || fail "Installed packages conflict (listed above)."
}
if [[ "$INSTALL_OPENCTI" == "true" ]] || uv pip show --python "$VENV_PYTHON" opencti-mcp &>/dev/null; then
    _install_opencti_pkg
fi
_final_check

if [[ "${VENV_ONLY:-}" == "true" ]]; then
    echo ""
    _write_install_marker
    ok "Venv updated. Packages installed."
    exit 0
fi

# ==========================================================================
# Phase 2: Triage Databases
# ==========================================================================
header "Phase 2: Triage Databases"

if [[ "$INSTALL_TRIAGE" == "true" ]]; then
    mkdir -p "$DB_DIR"

    if [[ "${REBUILD_TRIAGE:-}" == "true" ]]; then
        warn "Force rebuilding triage databases..."
        rm -f "$DB_DIR/known_good.db" "$DB_DIR/context.db"
    fi

    if [[ -s "$DB_DIR/known_good.db" ]] && [[ -s "$DB_DIR/context.db" ]]; then
        ok "Triage databases already present"
    else
        "$VENV_PYTHON" -m windows_triage.scripts.download_databases --dest "$DB_DIR" || \
            warn "Database download failed. Run manually: $VENV_PYTHON -m windows_triage.scripts.download_databases --dest $DB_DIR"
    fi

    # Validate
    for db in known_good.db context.db; do
        db_path="$DB_DIR/$db"
        if [[ -s "$db_path" ]]; then
            if "$VENV_PYTHON" -c "import sqlite3; sqlite3.connect('$db_path').execute('SELECT 1')" 2>/dev/null; then
                ok "$db valid"
            else
                warn "$db exists but is not valid SQLite"
            fi
        else
            warn "$db missing or empty"
        fi
    done
else
    ok "Triage databases skipped"
fi

# ==========================================================================
# Phase 3: RAG Index
# ==========================================================================
header "Phase 3: RAG Index"

RAG_METHOD="skipped"

if [[ "$INSTALL_RAG" == "true" ]]; then
    mkdir -p "$INDEX_DIR"

    if [[ "${REBUILD_RAG:-}" == "true" ]]; then
        warn "Force rebuilding RAG index..."
        rm -rf "$INDEX_DIR"
        mkdir -p "$INDEX_DIR"
    fi

    # Check if index already exists
    INDEX_COUNT=$(RAG_INDEX_DIR="$INDEX_DIR" "$VENV_PYTHON" -m rag_mcp.status --json --no-check 2>/dev/null | \
        "$VENV_PYTHON" -c "import sys,json; print(json.load(sys.stdin).get('document_count',0))" 2>/dev/null) || INDEX_COUNT=0

    if [[ "${REBUILD_RAG:-}" == "true" ]] || [[ "$INDEX_COUNT" -eq 0 ]] 2>/dev/null; then
        # Try download first (unless rebuild requested)
        if [[ "${REBUILD_RAG:-}" != "true" ]]; then
            echo "  Downloading pre-built RAG index..."
            if RAG_INDEX_DIR="$INDEX_DIR" ANONYMIZED_TELEMETRY=False \
                    "$VENV_PYTHON" -m rag_mcp.scripts.download_index --dest "$INDEX_DIR" 2>&1; then
                RAG_METHOD="download"
                ok "RAG index downloaded"
            else
                warn "Download failed, building from source..."
            fi
        fi
        # Build from source (rebuild or download fallback)
        if [[ "$RAG_METHOD" != "download" ]]; then
            echo "  Building RAG index (this takes 15 minutes to 3 hours)..."
            if RAG_INDEX_DIR="$INDEX_DIR" ANONYMIZED_TELEMETRY=False \
                    "$VENV_PYTHON" -m rag_mcp.build 2>/dev/null; then
                RAG_METHOD="build"
                ok "RAG index built"
            else
                warn "RAG index build failed. Run manually: $VENV_PYTHON -m rag_mcp.build"
            fi
        fi
    else
        RAG_METHOD="exists"
        ok "RAG index already built ($INDEX_COUNT records)"
    fi
else
    ok "RAG index skipped"
fi

# ==========================================================================
# Phase 4: Deploy Config Files
# ==========================================================================
header "Phase 4: Deploy Config Files"

ASSETS_DIR="$SCRIPT_DIR/claude-code"
SHARED_DIR="$ASSETS_DIR/shared"
LITE_DIR="$ASSETS_DIR/lite"

# Validate source directories exist
if [[ ! -d "$SHARED_DIR" ]] || [[ ! -d "$LITE_DIR" ]]; then
    fail "Cannot find claude-code/shared/ and claude-code/lite/ directories in $SCRIPT_DIR"
fi

# Deploy doc files to project root
for doc in CLAUDE.md FORENSIC_DISCIPLINE.md TOOL_REFERENCE.md; do
    src="$LITE_DIR/$doc"
    if [[ -f "$src" ]]; then
        _deploy_file "$src" "$PROJECT_DIR/$doc" "$src" "$doc"
    fi
done

for doc in FORENSIC_TOOLS.md; do
    src="$SHARED_DIR/$doc"
    if [[ -f "$src" ]]; then
        _deploy_file "$src" "$PROJECT_DIR/$doc" "$src" "$doc (shared)"
    fi
done

# Deploy hooks
mkdir -p "$PROJECT_DIR/hooks"
hook_src="$SHARED_DIR/hooks/forensic-audit.sh"
if [[ -f "$hook_src" ]]; then
    _deploy_file "$hook_src" "$PROJECT_DIR/hooks/forensic-audit.sh" "$hook_src" forensic-audit.sh
    if cmp -s "$hook_src" "$PROJECT_DIR/hooks/forensic-audit.sh"; then
        chmod +x "$PROJECT_DIR/hooks/forensic-audit.sh"
    fi
fi

# Deploy settings.json with path fixup
mkdir -p "$PROJECT_DIR/.claude"
settings_src="$LITE_DIR/settings.json"
if [[ -f "$settings_src" ]]; then
    # compared after the path is filled in, so a re-run finds it identical
    sed "s|\\\$CLAUDE_PROJECT_DIR|$PROJECT_DIR|g" "$settings_src" > "$PROJECT_DIR/.claude/settings.json.vhir-new"
    _deploy_file "$PROJECT_DIR/.claude/settings.json.vhir-new" "$PROJECT_DIR/.claude/settings.json" "" \
        "settings.json (hook path resolved)"
    rm -f "$PROJECT_DIR/.claude/settings.json.vhir-new"
fi

# Deploy skills
mkdir -p "$PROJECT_DIR/.claude/commands"
if [[ -d "$LITE_DIR/commands" ]]; then
    for skill in "$LITE_DIR/commands/"*.md; do
        [[ -f "$skill" ]] || continue
        _deploy_file "$skill" "$PROJECT_DIR/.claude/commands/$(basename "$skill")" "$skill" \
            "skill: $(basename "$skill")"
    done
fi
if (( ${#UNDO_LINES[@]} )); then
    warn "To undo the replacements above, run:"
    printf '      %s\n' "${UNDO_LINES[@]}"
fi

# Deploy case templates
mkdir -p "$PROJECT_DIR/cases/.templates"
if [[ -d "$LITE_DIR/case-templates" ]]; then
    for tmpl in "$LITE_DIR/case-templates/"*.md; do
        [[ -f "$tmpl" ]] || continue
        cp "$tmpl" "$PROJECT_DIR/cases/.templates/"
    done
    ok "Deployed case templates"
fi

# Deploy case manager script
if [[ -f "$LITE_DIR/scripts/case-manager.sh" ]]; then
    mkdir -p "$HOME/.vhir/bin"
    cp "$LITE_DIR/scripts/case-manager.sh" "$HOME/.vhir/bin/"
    chmod +x "$HOME/.vhir/bin/case-manager.sh"
    ok "Deployed case manager script"
fi

# Generate .mcp.json — merge managed entries into existing config
MCP_JSON="$PROJECT_DIR/.mcp.json"

# Build server list based on what was actually installed
_MANAGED_LIST=""
[[ "$INSTALL_RAG" == "true" ]] && _MANAGED_LIST="$_MANAGED_LIST\"forensic-rag\","
[[ "$INSTALL_TRIAGE" == "true" ]] && _MANAGED_LIST="$_MANAGED_LIST\"windows-triage\","
_MANAGED_LIST="${_MANAGED_LIST%,}"  # strip trailing comma
_MANAGED_SERVERS="[$_MANAGED_LIST]"

_NEW_CORE=$(sed -e "s|__VENV__|$VENV_DIR|g" \
    -e "s|__SRC__|$SCRIPT_DIR|g" \
    -e "s|__INDEX_DIR__|$INDEX_DIR|g" \
    -e "s|__DB_DIR__|$DB_DIR|g" \
    -e "s|__CASE_DIR__|$PROJECT_DIR|g" \
    "$LITE_DIR/mcp.json.example")

# Filter template to only include managed servers
_NEW_CORE=$("$VENV_PYTHON" -c "
import json, sys
core = json.loads(sys.argv[1])
managed = json.loads(sys.argv[2])
filtered = {k: v for k, v in core.get('mcpServers', {}).items() if k in managed}
print(json.dumps({'mcpServers': filtered}))
" "$_NEW_CORE" "$_MANAGED_SERVERS")

"$VENV_PYTHON" -c "
import json, sys, os

managed = json.loads(sys.argv[1])
new_core = json.loads(sys.argv[2])
mcp_path = sys.argv[3]

# Load existing config (if any); an unreadable one is left as it is
existing = {}
if os.path.isfile(mcp_path):
    try:
        with open(mcp_path) as f:
            data = json.load(f) if os.path.getsize(mcp_path) else {}
    except (ValueError, OSError):
        sys.exit(3)
    existing = data.get('mcpServers', {}) if isinstance(data, dict) else None
    if not isinstance(existing, dict):
        sys.exit(3)

# Start with existing servers, remove managed ones, add fresh managed
merged = {k: v for k, v in existing.items() if k not in managed}
merged.update(new_core.get('mcpServers', {}))

with open(mcp_path, 'w') as f:
    json.dump({'mcpServers': merged}, f, indent=2)
    f.write('\n')
" "$_MANAGED_SERVERS" "$_NEW_CORE" "$MCP_JSON" || MCP_RC=$?
if [[ "${MCP_RC:-0}" -eq 3 ]]; then
    warn "$MCP_JSON isn't valid JSON: NOT changed. Add these to its \"mcpServers\" by hand:"
    echo "$_NEW_CORE"
elif [[ "${MCP_RC:-0}" -ne 0 ]]; then
    fail "Could not update $MCP_JSON"
else
    chmod 600 "$MCP_JSON"
    ok "Updated .mcp.json (preserved non-managed servers)"
fi

# ==========================================================================
# Phase 5: Optional MCPs
# ==========================================================================
header "Phase 5: Optional MCPs"

_add_mcp_server() {
    # Add a server entry to .mcp.json
    local name="$1" json_fragment="$2"
    "$VENV_PYTHON" -c "
import json, sys
with open('$MCP_JSON') as f:
    data = json.load(f)
data.setdefault('mcpServers', {})[sys.argv[1]] = json.loads(sys.argv[2])
with open('$MCP_JSON', 'w') as f:
    json.dump(data, f, indent=2)
    f.write('\n')
" "$name" "$json_fragment"
}

INSTALLED_OPENCTI=false
INSTALLED_REMNUX=false
INSTALLED_MSLEARN=false
INSTALLED_ZELTSER=false

# --- OpenCTI ---
if [[ "$INSTALL_OPENCTI" != "true" ]] && [[ "$YES" != "true" ]] && [[ "$SKIP_OPTIONAL_MCPS" != "true" ]]; then
    echo ""
    echo "  OpenCTI provides live threat intelligence from your OpenCTI instance."
    echo "  Requires OpenCTI URL and API token."
    read -rp "  Install OpenCTI MCP? [y/N] " reply
    [[ "$reply" =~ ^[Yy] ]] && INSTALL_OPENCTI=true
fi

if [[ "$INSTALL_OPENCTI" == "true" ]]; then
    if [[ "${OPENCTI_PKG_DONE:-}" != "true" ]]; then  # chosen just now
        _install_opencti_pkg
        _final_check
    fi

    OPENCTI_URL=""
    OPENCTI_TOKEN=""
    if [[ "$YES" != "true" ]]; then
        read -rp "  OpenCTI URL (e.g., https://opencti.example.com): " OPENCTI_URL
        if [[ -n "$OPENCTI_URL" ]]; then
            if ! _validate_credential "$OPENCTI_URL" "OpenCTI URL"; then
                OPENCTI_URL=""
            else
                read -rsp "  OpenCTI API token: " OPENCTI_TOKEN
                echo ""
                if ! _validate_credential "$OPENCTI_TOKEN" "OpenCTI token"; then
                    OPENCTI_URL=""
                    OPENCTI_TOKEN=""
                fi
            fi
        fi
    fi
    if [[ -n "$OPENCTI_URL" ]] && [[ -n "$OPENCTI_TOKEN" ]]; then
        _add_mcp_server "opencti-mcp" "{
            \"command\": \"$VENV_DIR/bin/python\",
            \"args\": [\"-I\", \"-m\", \"opencti_mcp.server\"],
            \"env\": {
                \"PYTHONPATH\": \"$SCRIPT_DIR/packages/opencti/src\",
                \"OPENCTI_URL\": \"$OPENCTI_URL\",
                \"OPENCTI_TOKEN\": \"$OPENCTI_TOKEN\",
                \"VHIR_CASE_DIR\": \"$PROJECT_DIR\"
            }
        }"
        ok "Added opencti-mcp to .mcp.json"
        INSTALLED_OPENCTI=true
    else
        warn "OpenCTI URL or token not provided. Skipped."
    fi
fi

# --- REMnux ---
if [[ -n "$REMNUX_ADDR" ]]; then
    if ! _validate_credential "$REMNUX_ADDR" "REMnux address"; then
        REMNUX_ADDR=""
    fi
fi

if [[ -z "$REMNUX_ADDR" ]] && [[ "$YES" != "true" ]] && [[ "$SKIP_OPTIONAL_MCPS" != "true" ]]; then
    echo ""
    echo "  REMnux provides automated malware analysis from a REMnux workstation."
    echo "  Requires REMnux address (HOST:PORT) and bearer token."
    read -rp "  Install REMnux MCP? [y/N] " reply
    if [[ "$reply" =~ ^[Yy] ]]; then
        read -rp "  REMnux address (HOST:PORT): " REMNUX_ADDR
        if [[ -n "$REMNUX_ADDR" ]] && ! _validate_credential "$REMNUX_ADDR" "REMnux address"; then
            REMNUX_ADDR=""
        fi
    fi
fi

if [[ -n "$REMNUX_ADDR" ]]; then
    REMNUX_TOKEN=""
    if [[ "$YES" != "true" ]]; then
        read -rsp "  REMnux bearer token: " REMNUX_TOKEN
        echo ""
        if [[ -n "$REMNUX_TOKEN" ]] && ! _validate_credential "$REMNUX_TOKEN" "REMnux token"; then
            REMNUX_TOKEN=""
        fi
    fi
    if [[ -n "$REMNUX_TOKEN" ]]; then
        _add_mcp_server "remnux-mcp" "{
            \"type\": \"http\",
            \"url\": \"http://$REMNUX_ADDR/mcp\",
            \"headers\": {\"Authorization\": \"Bearer $REMNUX_TOKEN\"}
        }"
        ok "Added remnux-mcp to .mcp.json"
        INSTALLED_REMNUX=true
    elif [[ "$YES" == "true" ]]; then
        warn "REMnux token cannot be provided non-interactively. Run without -y to configure."
    else
        warn "REMnux token not provided. Skipped."
    fi
fi

# --- Microsoft Learn ---
if [[ "$INSTALL_MSLEARN" != "true" ]] && [[ "$YES" != "true" ]] && [[ "$SKIP_OPTIONAL_MCPS" != "true" ]]; then
    echo ""
    echo "  Microsoft Learn provides documentation search (requires Internet)."
    read -rp "  Install Microsoft Learn MCP? [Y/n] " reply
    [[ ! "$reply" =~ ^[Nn] ]] && INSTALL_MSLEARN=true
fi

if [[ "$INSTALL_MSLEARN" == "true" ]]; then
    _add_mcp_server "microsoft-learn" "{
        \"type\": \"http\",
        \"url\": \"https://learn.microsoft.com/api/mcp\"
    }"
    ok "Added microsoft-learn to .mcp.json"
    INSTALLED_MSLEARN=true
fi

# --- Zeltser IR Writing ---
if [[ "$INSTALL_ZELTSER" != "true" ]] && [[ "$YES" != "true" ]] && [[ "$SKIP_OPTIONAL_MCPS" != "true" ]]; then
    echo ""
    echo "  Zeltser IR Writing provides IR report writing guidelines (requires Internet)."
    read -rp "  Install Zeltser IR Writing MCP? [Y/n] " reply
    [[ ! "$reply" =~ ^[Nn] ]] && INSTALL_ZELTSER=true
fi

if [[ "$INSTALL_ZELTSER" == "true" ]]; then
    _add_mcp_server "zeltser-ir-writing" "{
        \"type\": \"http\",
        \"url\": \"https://website-mcp.zeltser.com/mcp\"
    }"
    ok "Added zeltser-ir-writing to .mcp.json"
    INSTALLED_ZELTSER=true
fi

# --- Registry baseline (deferred) ---
if [[ "$INSTALL_REGISTRY" == "true" ]]; then
    warn "Registry baseline download is not yet available. Flag accepted for forward compatibility."
fi

# ==========================================================================
# Post-install: RAG freshness check
# ==========================================================================
if [[ "$INSTALL_RAG" == "true" ]] && [[ "$RAG_METHOD" != "skipped" ]]; then
    STALE_COUNT=$(timeout 60 bash -c "RAG_INDEX_DIR=\"$INDEX_DIR\" \"$VENV_PYTHON\" -m rag_mcp.status --json 2>/dev/null" | \
        "$VENV_PYTHON" -c "
import sys, json
data = json.load(sys.stdin)
print(sum(1 for s in data.get('online_sources', []) if s.get('has_update')))
" 2>/dev/null) || STALE_COUNT=""

    if [[ -n "$STALE_COUNT" ]] && [[ "$STALE_COUNT" -gt 0 ]] 2>/dev/null; then
        echo ""
        echo "── RAG Knowledge Base ──────────────────────────────────────────"
        echo "The RAG index relies on online sources (Sigma rules, MITRE ATT&CK,"
        echo "LOLBAS, etc.) that update frequently. You can refresh at any time:"
        echo ""
        echo "    $VENV_PYTHON -m rag_mcp.refresh"
        echo ""
        echo "Currently, $STALE_COUNT of 23 sources have updates available."
        echo "Depending on the number of sources, internet speed, and available"
        echo "CPU, this could take several minutes to a couple of hours."
        if [[ "$YES" != "true" ]]; then
            read -rp "  Would you like to refresh now? [y/N] " reply
            if [[ "$reply" =~ ^[Yy] ]]; then
                RAG_INDEX_DIR="$INDEX_DIR" ANONYMIZED_TELEMETRY=False \
                    "$VENV_PYTHON" -m rag_mcp.refresh
            fi
        fi
    elif [[ -n "$STALE_COUNT" ]] && [[ "$STALE_COUNT" -eq 0 ]] 2>/dev/null; then
        ok "RAG knowledge base is up to date (23 sources current)"
    fi
fi

# ==========================================================================
# Summary
# ==========================================================================
_write_install_marker
header "Installation Complete"

echo ""
echo "Installed:"
ok "sift-common (audit and logging)"
[[ "$INSTALL_RAG" == "true" ]] && ok "forensic-rag (knowledge search)"
[[ "$INSTALL_TRIAGE" == "true" ]] && ok "windows-triage (baseline validation)"
[[ "$INSTALLED_OPENCTI" == "true" ]] && ok "opencti-mcp (threat intelligence)"
[[ "$INSTALLED_REMNUX" == "true" ]] && ok "remnux-mcp (malware analysis)"
[[ "$INSTALLED_MSLEARN" == "true" ]] && ok "microsoft-learn (documentation)"
[[ "$INSTALLED_ZELTSER" == "true" ]] && ok "zeltser-ir-writing (IR writing)"

echo ""
echo "Project directory: $PROJECT_DIR"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo "  1. cd $PROJECT_DIR"
echo "  2. claude                    # Launch Claude Code"
echo "  3. /welcome                  # Verify setup, get oriented"
echo ""

# The undo block, repeated as the last output so it isn't scrolled away.
if (( ${#UNDO_LINES[@]} )); then
    echo -e "${BOLD}${RED}=== Files in $PROJECT_DIR were replaced (backups kept) ===${NC}"
    printf '  %s\n' "${UNDO_LINES[@]}"
    echo ""
fi
