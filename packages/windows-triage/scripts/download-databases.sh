#!/usr/bin/env bash
#
# download-databases.sh - Download pre-built triage databases from GitHub Releases
#
# Downloads known_good.db and context.db instead of building from source (6-8+ hours).
# Databases are zstd-compressed GitHub Release assets.
#
# Usage:
#   ./scripts/download-databases.sh              # Download latest release
#   ./scripts/download-databases.sh --full       # Include registry database (~500MB)
#   ./scripts/download-databases.sh v2025.02     # Download specific version
#
# Requirements: curl, zstd, sha256sum
#
set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

REPO="AppliedIR/sift-mcp"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data"
FULL_INSTALL=false
VERSION="latest"

for arg in "$@"; do
    case "$arg" in
        --full) FULL_INSTALL=true ;;
        *)      VERSION="$arg" ;;
    esac
done

# Expected files in the release
ASSETS=("known_good.db.zst" "context.db.zst" "checksums.sha256")
if $FULL_INSTALL; then
    ASSETS=("known_good.db.zst" "context.db.zst" "known_good_registry.db.zst" "checksums.sha256")
fi

# Colors (only when stdout is a terminal)
if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BOLD='' NC=''
fi

# =============================================================================
# Preflight Checks
# =============================================================================

echo -e "${BOLD}Windows Triage Database Download${NC}"
echo "════════════════════════════════════════"
if $FULL_INSTALL; then
    echo -e "Mode: ${BOLD}Full${NC} (includes registry database)"
fi
echo ""

# Check dependencies
for cmd in curl zstd sha256sum; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${RED}Error: $cmd is required but not installed${NC}"
        exit 1
    fi
done

# Check for existing databases
if [[ -f "${DATA_DIR}/known_good.db" ]]; then
    existing_size=$(stat -c%s "${DATA_DIR}/known_good.db" 2>/dev/null || echo "0")
    existing_mb=$((existing_size / 1024 / 1024))
    echo -e "${YELLOW}Warning: known_good.db already exists (${existing_mb}MB)${NC}"
    read -p "Overwrite? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

if $FULL_INSTALL && [[ -f "${DATA_DIR}/known_good_registry.db" ]]; then
    existing_size=$(stat -c%s "${DATA_DIR}/known_good_registry.db" 2>/dev/null || echo "0")
    existing_mb=$((existing_size / 1024 / 1024))
    echo -e "${YELLOW}Note: known_good_registry.db already exists (${existing_mb}MB) — will be overwritten${NC}"
fi

# =============================================================================
# Resolve Release URL
# =============================================================================

echo "Resolving release..."

if [[ "$VERSION" == "latest" ]]; then
    RELEASE_URL="https://api.github.com/repos/${REPO}/releases/latest"
else
    RELEASE_URL="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
fi

# Fetch release metadata
AUTH_ARGS=(-H "Accept: application/vnd.github+json")
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    AUTH_ARGS+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

RELEASE_JSON=$(curl -sL "${AUTH_ARGS[@]}" "$RELEASE_URL" 2>/dev/null) || {
    echo -e "${RED}Error: Could not fetch release info${NC}"
    echo "Check: https://github.com/${REPO}/releases"
    exit 1
}

# Check for errors
if echo "$RELEASE_JSON" | grep -q '"message"'; then
    MSG=$(echo "$RELEASE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('message','Unknown error'))" 2>/dev/null || echo "Unknown error")
    echo -e "${RED}Error: ${MSG}${NC}"
    echo "Check: https://github.com/${REPO}/releases"
    exit 1
fi

TAG=$(echo "$RELEASE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tag_name','unknown'))" 2>/dev/null)
echo -e "Release: ${GREEN}${TAG}${NC}"
echo ""

# =============================================================================
# Download Assets
# =============================================================================

mkdir -p "$DATA_DIR"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "Downloading assets..."
echo ""

download_assets() {
    local attempt="${1:-1}"
    if [[ "$attempt" -gt 1 ]]; then
        echo ""
        echo "Retrying downloads (attempt ${attempt})..."
        echo ""
    fi

    for asset in "${ASSETS[@]}"; do
        # Use API URL for higher rate limits (browser_download_url may 404 under throttling)
        ASSET_URL=$(echo "$RELEASE_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for a in data.get('assets', []):
    if a['name'] == '${asset}':
        print(a['url'])
        break
" 2>/dev/null)

        if [[ -z "$ASSET_URL" ]]; then
            if [[ "$asset" == "checksums.sha256" ]]; then
                echo -e "  ${YELLOW}checksums.sha256 not found (skipping verification)${NC}"
                continue
            fi
            echo -e "  ${RED}Error: ${asset} not found in release${NC}"
            return 1
        fi

        echo -n "  Downloading ${asset}..."

        # API URL requires Accept: application/octet-stream to get the binary
        local curl_args=(-sL -H "Accept: application/octet-stream" -o "${TEMP_DIR}/${asset}")
        if [[ -n "${GITHUB_TOKEN:-}" ]]; then
            curl_args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
        fi

        if ! curl "${curl_args[@]}" "$ASSET_URL"; then
            echo -e " ${RED}FAILED${NC}"
            return 1
        fi

        size=$(stat -c%s "${TEMP_DIR}/${asset}" 2>/dev/null || echo "0")
        size_mb=$((size / 1024 / 1024))
        echo -e " ${GREEN}done${NC} (${size_mb}MB)"
    done
    return 0
}

verify_checksums() {
    if [[ ! -f "${TEMP_DIR}/checksums.sha256" ]]; then
        echo -e "  ${YELLOW}No checksums file — skipping verification${NC}"
        return 0
    fi

    echo "Verifying checksums..."
    cd "$TEMP_DIR"
    local failed=false
    while IFS= read -r line; do
        local expected_hash file_name
        expected_hash=$(echo "$line" | awk '{print $1}')
        file_name=$(echo "$line" | awk '{print $2}')
        if [[ ! -f "$file_name" ]]; then
            echo -e "  ${YELLOW}SKIP: ${file_name} (not downloaded)${NC}"
            continue
        fi
        local actual_hash
        actual_hash=$(sha256sum "$file_name" | awk '{print $1}')
        if [[ "$actual_hash" == "$expected_hash" ]]; then
            echo -e "  ${GREEN}OK: ${file_name}${NC}"
        else
            echo -e "  ${RED}FAILED: ${file_name}${NC}"
            echo "    expected: ${expected_hash}"
            echo "    got:      ${actual_hash}"
            failed=true
        fi
    done < checksums.sha256
    cd - >/dev/null

    if [[ "$failed" == true ]]; then
        return 1
    fi
    return 0
}

# Download with retry loop
MAX_ATTEMPTS=3
for attempt in $(seq 1 $MAX_ATTEMPTS); do
    if download_assets "$attempt"; then
        echo ""
        if verify_checksums; then
            echo ""
            break
        else
            echo ""
            echo -e "  ${RED}Checksum verification FAILED${NC}"
        fi
    else
        echo ""
        echo -e "  ${RED}Download failed${NC}"
    fi

    if [[ "$attempt" -lt "$MAX_ATTEMPTS" ]]; then
        if [[ "$attempt" -eq 1 ]]; then
            # First retry is automatic
            echo "  Retrying automatically..."
        else
            # Subsequent retries ask
            echo ""
            read -p "  Retry download? [Y/n] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Nn]$ ]]; then
                echo "  Aborted. Try again later or build from source."
                exit 1
            fi
        fi
        # Clean temp for retry
        rm -f "${TEMP_DIR}"/*.zst "${TEMP_DIR}"/checksums.sha256
    else
        echo "  All ${MAX_ATTEMPTS} attempts failed. Try again later or build from source."
        exit 1
    fi
done

# =============================================================================
# Decompress
# =============================================================================

echo "Decompressing..."

DBS=("known_good.db.zst" "context.db.zst")
if $FULL_INSTALL; then
    DBS+=("known_good_registry.db.zst")
fi

for asset in "${DBS[@]}"; do
    if [[ -f "${TEMP_DIR}/${asset}" ]]; then
        db_name="${asset%.zst}"
        echo -n "  ${db_name}..."
        zstd -d --no-progress -f -o "${DATA_DIR}/${db_name}" "${TEMP_DIR}/${asset}" 2>/dev/null
        size=$(stat -c%s "${DATA_DIR}/${db_name}" 2>/dev/null || echo "0")
        size_mb=$((size / 1024 / 1024))
        echo -e " ${GREEN}done${NC} (${size_mb}MB)"
    fi
done

echo ""

# =============================================================================
# Verify Databases
# =============================================================================

echo "Verifying databases..."

ERRORS=0

# Check known_good.db
if [[ -f "${DATA_DIR}/known_good.db" ]]; then
    count=$(sqlite3 "${DATA_DIR}/known_good.db" "SELECT COUNT(*) FROM baseline_files" 2>/dev/null || echo "0")
    if [[ "$count" -gt 1000000 ]]; then
        echo -e "  ${GREEN}known_good.db: ${count} files${NC}"
    else
        echo -e "  ${RED}known_good.db: only ${count} files (expected 1M+)${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "  ${RED}known_good.db: missing${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check known_good_registry.db (full install only)
if $FULL_INSTALL; then
    if [[ -f "${DATA_DIR}/known_good_registry.db" ]]; then
        count=$(sqlite3 "${DATA_DIR}/known_good_registry.db" "SELECT COUNT(*) FROM baseline_registry" 2>/dev/null || echo "0")
        if [[ "$count" -gt 1000000 ]]; then
            echo -e "  ${GREEN}known_good_registry.db: ${count} entries${NC}"
        else
            echo -e "  ${RED}known_good_registry.db: only ${count} entries (expected 1M+)${NC}"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "  ${RED}known_good_registry.db: missing${NC}"
        ERRORS=$((ERRORS + 1))
    fi
fi

# Check context.db
if [[ -f "${DATA_DIR}/context.db" ]]; then
    lolbins=$(sqlite3 "${DATA_DIR}/context.db" "SELECT COUNT(*) FROM lolbins" 2>/dev/null || echo "0")
    drivers=$(sqlite3 "${DATA_DIR}/context.db" "SELECT COUNT(*) FROM vulnerable_drivers" 2>/dev/null || echo "0")
    if [[ "$lolbins" -gt 100 ]] && [[ "$drivers" -gt 100 ]]; then
        echo -e "  ${GREEN}context.db: ${lolbins} LOLBins, ${drivers} drivers${NC}"
    else
        echo -e "  ${RED}context.db: ${lolbins} LOLBins, ${drivers} drivers (low counts)${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "  ${RED}context.db: missing${NC}"
    ERRORS=$((ERRORS + 1))
fi

echo ""

# =============================================================================
# Summary
# =============================================================================

if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Download complete! Databases ready.${NC}"
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo ""
    echo "To stay current, run periodically:"
    echo "  python scripts/update_sources.py"
else
    echo -e "${RED}════════════════════════════════════════${NC}"
    echo -e "${RED}  Download completed with ${ERRORS} error(s)${NC}"
    echo -e "${RED}════════════════════════════════════════${NC}"
    echo ""
    echo "Consider building from source instead:"
    echo "  python scripts/import_all.py"
    exit 1
fi
