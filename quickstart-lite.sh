#!/usr/bin/env bash
#
# quickstart-lite.sh — AIIR Lite Installer
#
# Installs AIIR Lite: forensic knowledge MCPs + discipline files + audit hook.
# No gateway, no sandbox, no deny rules. Claude runs tools directly via Bash.
#
# Usage:
#   ./quickstart-lite.sh                          # Core install
#   ./quickstart-lite.sh --opencti                # Add OpenCTI MCP
#   ./quickstart-lite.sh --remnux=HOST:PORT       # Add REMnux MCP
#   ./quickstart-lite.sh --mslearn                # Add Microsoft Learn MCP
#   ./quickstart-lite.sh --zeltser                # Add Zeltser IR Writing MCP
#   ./quickstart-lite.sh --registry               # Download registry baseline
#   ./quickstart-lite.sh -y                       # Non-interactive (skip prompts)
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
header() { echo -e "\n${BOLD}=== $1 ===${NC}"; }

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
INSTALL_OPENCTI=false
INSTALL_MSLEARN=false
INSTALL_ZELTSER=false
INSTALL_REGISTRY=false
REMNUX_ADDR=""

for arg in "$@"; do
    case "$arg" in
        -y|--yes) YES=true ;;
        --opencti) INSTALL_OPENCTI=true ;;
        --mslearn) INSTALL_MSLEARN=true ;;
        --zeltser) INSTALL_ZELTSER=true ;;
        --registry) INSTALL_REGISTRY=true ;;
        --remnux=*) REMNUX_ADDR="${arg#--remnux=}" ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -y, --yes            Non-interactive (skip prompts)"
            echo "  --opencti            Add OpenCTI threat intelligence MCP"
            echo "  --remnux=HOST:PORT   Add REMnux malware analysis MCP"
            echo "  --mslearn            Add Microsoft Learn documentation MCP"
            echo "  --zeltser            Add Zeltser IR Writing MCP"
            echo "  --registry           Download optional registry baseline (large)"
            echo "  -h, --help           Show this help"
            exit 0
            ;;
        *) warn "Unknown option: $arg" ;;
    esac
done

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
VENV_DIR="$HOME/.aiir/venv"
VENV_PYTHON="$VENV_DIR/bin/python"
DB_DIR="$HOME/.aiir/triage-db"
INDEX_DIR="$HOME/.aiir/rag-index"

echo -e "${BOLD}AIIR Lite Installer${NC}"
echo "Source:  $SCRIPT_DIR"
echo "Project: $PROJECT_DIR"
echo "Venv:    $VENV_DIR"

if [[ "$YES" != "true" ]]; then
    echo ""
    read -rp "Continue? [Y/n] " reply
    [[ "$reply" =~ ^[Nn] ]] && exit 0
fi

# ==========================================================================
# Phase 1: Python Environment
# ==========================================================================
header "Phase 1: Python Environment"

if [[ ! -f "$VENV_PYTHON" ]]; then
    python3 -m venv "$VENV_DIR"
    ok "Created venv at $VENV_DIR"
else
    ok "Venv exists at $VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --quiet --upgrade pip

for pkg in sift-common forensic-rag windows-triage; do
    pkg_dir="$SCRIPT_DIR/packages/$pkg"
    if [[ -d "$pkg_dir" ]]; then
        if [[ "$pkg" == "forensic-rag" ]]; then
            echo "  Installing $pkg (downloads ML dependencies, may take several minutes)..."
        fi
        "$VENV_DIR/bin/pip" install --quiet -e "$pkg_dir"
        ok "Installed $pkg"
    else
        warn "$pkg not found at $pkg_dir"
    fi
done

# ==========================================================================
# Phase 2: Triage Databases
# ==========================================================================
header "Phase 2: Triage Databases"

mkdir -p "$DB_DIR"

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

# ==========================================================================
# Phase 3: RAG Index
# ==========================================================================
header "Phase 3: RAG Index"

mkdir -p "$INDEX_DIR"

# Check if index already exists
INDEX_COUNT=$(RAG_INDEX_DIR="$INDEX_DIR" "$VENV_PYTHON" -m rag_mcp.status --json --no-check 2>/dev/null | \
    "$VENV_PYTHON" -c "import sys,json; print(json.load(sys.stdin).get('document_count',0))" 2>/dev/null) || INDEX_COUNT=0

if [[ "$INDEX_COUNT" -gt 0 ]] 2>/dev/null; then
    ok "RAG index already built ($INDEX_COUNT records)"
else
    echo "  Building RAG index (this takes 15-25 minutes)..."
    if RAG_INDEX_DIR="$INDEX_DIR" ANONYMIZED_TELEMETRY=False "$VENV_PYTHON" -m rag_mcp.build 2>/dev/null; then
        INDEX_COUNT=$(RAG_INDEX_DIR="$INDEX_DIR" "$VENV_PYTHON" -m rag_mcp.status --json --no-check 2>/dev/null | \
            "$VENV_PYTHON" -c "import sys,json; print(json.load(sys.stdin).get('document_count',0))" 2>/dev/null) || INDEX_COUNT=0
        if [[ "$INDEX_COUNT" -gt 0 ]] 2>/dev/null; then
            ok "RAG index built ($INDEX_COUNT records)"
        else
            warn "RAG index appears empty. Run: $VENV_PYTHON -m rag_mcp.build"
        fi
    else
        warn "RAG index build failed. Run manually: $VENV_PYTHON -m rag_mcp.build"
    fi
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
        cp "$src" "$PROJECT_DIR/$doc"
        ok "Deployed $doc"
    fi
done

for doc in FORENSIC_TOOLS.md; do
    src="$SHARED_DIR/$doc"
    if [[ -f "$src" ]]; then
        cp "$src" "$PROJECT_DIR/$doc"
        ok "Deployed $doc (shared)"
    fi
done

# Deploy hooks
mkdir -p "$PROJECT_DIR/hooks"
hook_src="$SHARED_DIR/hooks/forensic-audit.sh"
if [[ -f "$hook_src" ]]; then
    cp "$hook_src" "$PROJECT_DIR/hooks/forensic-audit.sh"
    chmod +x "$PROJECT_DIR/hooks/forensic-audit.sh"
    ok "Deployed forensic-audit.sh"
fi

# Deploy settings.json with path fixup
mkdir -p "$PROJECT_DIR/.claude"
settings_src="$LITE_DIR/settings.json"
if [[ -f "$settings_src" ]]; then
    sed "s|\\\$CLAUDE_PROJECT_DIR|$PROJECT_DIR|g" "$settings_src" > "$PROJECT_DIR/.claude/settings.json"
    ok "Deployed settings.json (hook path resolved)"
fi

# Deploy skills
mkdir -p "$PROJECT_DIR/.claude/commands"
if [[ -d "$LITE_DIR/commands" ]]; then
    for skill in "$LITE_DIR/commands/"*.md; do
        [[ -f "$skill" ]] || continue
        cp "$skill" "$PROJECT_DIR/.claude/commands/"
        ok "Deployed skill: $(basename "$skill")"
    done
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

# Generate .mcp.json from template
MCP_JSON="$PROJECT_DIR/.mcp.json"
sed -e "s|__VENV__|$VENV_DIR|g" \
    -e "s|__SRC__|$SCRIPT_DIR|g" \
    -e "s|__INDEX_DIR__|$INDEX_DIR|g" \
    -e "s|__DB_DIR__|$DB_DIR|g" \
    -e "s|__CASE_DIR__|$PROJECT_DIR|g" \
    "$LITE_DIR/mcp.json.example" > "$MCP_JSON"
chmod 600 "$MCP_JSON"
ok "Generated .mcp.json"

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
if [[ "$INSTALL_OPENCTI" != "true" ]] && [[ "$YES" != "true" ]]; then
    echo ""
    echo "  OpenCTI provides live threat intelligence from your OpenCTI instance."
    echo "  Requires OpenCTI URL and API token."
    read -rp "  Install OpenCTI MCP? [y/N] " reply
    [[ "$reply" =~ ^[Yy] ]] && INSTALL_OPENCTI=true
fi

if [[ "$INSTALL_OPENCTI" == "true" ]]; then
    # Install opencti package
    pkg_dir="$SCRIPT_DIR/packages/opencti"
    if [[ -d "$pkg_dir" ]]; then
        "$VENV_DIR/bin/pip" install --quiet -e "$pkg_dir"
        ok "Installed opencti-mcp"
    else
        warn "opencti-mcp not found at $pkg_dir"
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
            \"args\": [\"-m\", \"opencti_mcp.server\"],
            \"env\": {
                \"PYTHONPATH\": \"$SCRIPT_DIR/packages/opencti/src\",
                \"OPENCTI_URL\": \"$OPENCTI_URL\",
                \"OPENCTI_TOKEN\": \"$OPENCTI_TOKEN\",
                \"AIIR_CASE_DIR\": \"$PROJECT_DIR\"
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

if [[ -z "$REMNUX_ADDR" ]] && [[ "$YES" != "true" ]]; then
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
            \"type\": \"streamable-http\",
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
if [[ "$INSTALL_MSLEARN" != "true" ]] && [[ "$YES" != "true" ]]; then
    echo ""
    echo "  Microsoft Learn provides documentation search (requires Internet)."
    read -rp "  Install Microsoft Learn MCP? [y/N] " reply
    [[ "$reply" =~ ^[Yy] ]] && INSTALL_MSLEARN=true
fi

if [[ "$INSTALL_MSLEARN" == "true" ]]; then
    _add_mcp_server "microsoft-learn" "{
        \"type\": \"streamable-http\",
        \"url\": \"https://learn.microsoft.com/api/mcp\"
    }"
    ok "Added microsoft-learn to .mcp.json"
    INSTALLED_MSLEARN=true
fi

# --- Zeltser IR Writing ---
if [[ "$INSTALL_ZELTSER" != "true" ]] && [[ "$YES" != "true" ]]; then
    echo ""
    echo "  Zeltser IR Writing provides IR report writing guidelines (requires Internet)."
    read -rp "  Install Zeltser IR Writing MCP? [y/N] " reply
    [[ "$reply" =~ ^[Yy] ]] && INSTALL_ZELTSER=true
fi

if [[ "$INSTALL_ZELTSER" == "true" ]]; then
    _add_mcp_server "zeltser-ir-writing" "{
        \"type\": \"streamable-http\",
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
# Summary
# ==========================================================================
header "Installation Complete"

echo ""
echo "Installed:"
ok "forensic-rag (knowledge search)"
ok "windows-triage (baseline validation)"
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
