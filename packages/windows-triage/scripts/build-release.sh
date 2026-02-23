#!/usr/bin/env bash
#
# build-release.sh - Create compressed database assets for GitHub Release
#
# Compresses known_good.db and context.db with zstd, generates checksums.
# Output goes to release/ directory ready for upload.
#
# Usage:
#   ./scripts/build-release.sh                    # Build release assets
#   ./scripts/build-release.sh --output /tmp/rel   # Custom output directory
#
# Upload with gh CLI:
#   gh release create v2025.02 release/*.zst release/checksums.sha256 \
#     --title "Triage Databases v2025.02" \
#     --notes "Pre-built triage databases for windows-triage"
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data"
OUTPUT_DIR="${SCRIPT_DIR}/../release"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}Building Release Assets${NC}"
echo "════════════════════════════════════════"
echo ""

# Check databases exist
for db in known_good.db context.db; do
    if [[ ! -f "${DATA_DIR}/${db}" ]]; then
        echo -e "${RED}Error: ${DATA_DIR}/${db} not found${NC}"
        echo "Build databases first: python scripts/import_all.py"
        exit 1
    fi
done

# Check zstd
if ! command -v zstd &>/dev/null; then
    echo -e "${RED}Error: zstd is required${NC}"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Compress databases
for db in known_good.db context.db; do
    echo -n "  Compressing ${db}..."
    original_size=$(stat -c%s "${DATA_DIR}/${db}")
    original_mb=$((original_size / 1024 / 1024))

    zstd -3 --no-progress -f -o "${OUTPUT_DIR}/${db}.zst" "${DATA_DIR}/${db}" 2>/dev/null

    compressed_size=$(stat -c%s "${OUTPUT_DIR}/${db}.zst")
    compressed_mb=$((compressed_size / 1024 / 1024))
    ratio=$((compressed_size * 100 / original_size))

    echo -e " ${GREEN}done${NC} (${original_mb}MB -> ${compressed_mb}MB, ${ratio}%)"
done

echo ""

# Generate checksums
echo -n "  Generating checksums..."
cd "$OUTPUT_DIR"
sha256sum *.zst > checksums.sha256
cd - >/dev/null
echo -e " ${GREEN}done${NC}"

# Record database metadata
echo -n "  Generating metadata..."
DATA_DIR="${DATA_DIR}" OUTPUT_DIR="${OUTPUT_DIR}" python3 -c "
import json, sqlite3, os
from datetime import datetime

data_dir = os.environ['DATA_DIR']
output_dir = os.environ['OUTPUT_DIR']

meta = {
    'created': datetime.now().isoformat(),
    'databases': {}
}

for db in ['known_good.db', 'context.db']:
    db_path = os.path.join(data_dir, db)
    size = os.path.getsize(db_path)
    conn = sqlite3.connect(db_path)
    tables = {}
    for (table,) in conn.execute(\"SELECT name FROM sqlite_master WHERE type='table'\").fetchall():
        (count,) = conn.execute(f'SELECT COUNT(*) FROM [{table}]').fetchone()
        tables[table] = count
    conn.close()
    meta['databases'][db] = {
        'size_bytes': size,
        'tables': tables
    }

with open(os.path.join(output_dir, 'metadata.json'), 'w') as f:
    json.dump(meta, f, indent=2)
" 2>/dev/null
echo -e " ${GREEN}done${NC}"

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Release assets ready in: ${OUTPUT_DIR}/${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "Files:"
ls -lh "${OUTPUT_DIR}/"
echo ""
echo "To create a GitHub release:"
echo "  gh release create vYYYY.MM ${OUTPUT_DIR}/*.zst ${OUTPUT_DIR}/checksums.sha256 ${OUTPUT_DIR}/metadata.json \\"
echo "    --title 'Triage Databases vYYYY.MM' \\"
echo "    --notes-file RELEASE_NOTES.md"
