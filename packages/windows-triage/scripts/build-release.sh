#!/usr/bin/env bash
#
# build-release.sh - Pack the triage databases and licence files for a GitHub Release
#
# Building a triage data release, from a clean checkout of the repository, in
# packages/windows-triage/, with the package installed in a virtual environment at
# $VENV and zstd on PATH:
#
#     export VENV=/path/to/venv
#     "$VENV/bin/python" scripts/init_databases.py
#     "$VENV/bin/python" scripts/import_all.py --fetch
#     bash scripts/build-release.sh
#
# The second command downloads every upstream source and fails if any source cannot
# be fetched or any table is under its floor; it needs network, several hours and
# tens of GiB of free disk. The third command only packs the databases and the
# licence files: it fails if a default database is missing, a table is under its
# floor or a source has no licence file, before any release file is written. The
# release files are written to release/ (or the --output dir).
#
# Upload with the gh CLI; the tag is triage-db-v followed by the UTC build date:
#
#     TAG="triage-db-v$(date -u +%Y.%m.%d)"
#     gh release create "$TAG" --latest=false release/*.zst release/checksums.sha256 --title "Triage Databases $TAG" --notes "Pre-built triage databases for windows-triage"
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

# Check zstd
if ! command -v zstd &>/dev/null; then
    echo -e "${RED}Error: zstd is required${NC}"
    exit 1
fi

# Every Python step runs the package's virtual environment's python
if [[ -z "${VENV:-}" || ! -x "${VENV}/bin/python" ]]; then
    echo -e "${RED}Error: set VENV to the package's virtual environment (no python at ${VENV:-<unset>}/bin/python)${NC}" >&2
    exit 1
fi

# The release file list decides which DBs are packed: every default DB must be
# present, and every other listed DB is packed when present. Each packed DB must
# reach its tables' floors before anything is written.
if ! PACK_DBS=$(DATA_DIR="${DATA_DIR}" "$VENV/bin/python" -c "
import os, sys
from pathlib import Path
from windows_triage import release_manifest as m

data = Path(os.environ['DATA_DIR'])
names, errors = [], []
for name, default in m.DATABASES.items():
    path = data / name
    if not path.is_file():
        if default:
            errors.append(f'{path} not found')
        continue
    errors.extend(m.check_floors(name, path))
    names.append(name)
for error in errors:
    print(f'  {error}', file=sys.stderr)
if errors:
    sys.exit(1)
print(' '.join(names))
"); then
    echo -e "${RED}Error: the databases do not pass the release checks; nothing written${NC}"
    echo "Build databases first: python scripts/import_all.py --fetch"
    exit 1
fi
echo "  Databases checked against the release floors: ${PACK_DBS}"

# Each source in the triage source table needs a licence file in
# data/licenses/<repo name>/ before anything is written.
if ! SCRIPT_DIR="${SCRIPT_DIR}" DATA_DIR="${DATA_DIR}" "$VENV/bin/python" -c "
import importlib.util, os, sys
from pathlib import Path
from windows_triage import release_manifest as m

spec = importlib.util.spec_from_file_location(
    'update_sources', Path(os.environ['SCRIPT_DIR']) / 'update_sources.py'
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
base = Path(os.environ['DATA_DIR']) / m.LICENCE_DIR
missing = []
for name in sorted({mod.clone_dir(e) for e in mod.SOURCES.values()}):
    d = base / name
    if d.is_symlink() or not any(
        p.is_file() and not p.is_symlink() for p in (d.iterdir() if d.is_dir() else ())
    ):
        missing.append(name)
for name in missing:
    print(f'  {name}: no licence file in {base / name}', file=sys.stderr)
sys.exit(1 if missing else 0)
"; then
    echo -e "${RED}Error: a source has no licence file; nothing written${NC}"
    echo "Fetch the sources first: python scripts/import_all.py --fetch"
    exit 1
fi

LICENCE_ASSET=$("$VENV/bin/python" -c "from windows_triage import release_manifest as m; print(m.LICENCE_ASSET)")

mkdir -p "$OUTPUT_DIR"
WRITTEN=()

# Compress databases
for db in $PACK_DBS; do
    echo -n "  Compressing ${db}..."
    original_size=$(stat -c%s "${DATA_DIR}/${db}")
    original_mb=$((original_size / 1024 / 1024))

    zstd -3 --no-progress -f -q -o "${OUTPUT_DIR}/${db}.zst" "${DATA_DIR}/${db}"
    WRITTEN+=("${db}.zst")

    compressed_size=$(stat -c%s "${OUTPUT_DIR}/${db}.zst")
    compressed_mb=$((compressed_size / 1024 / 1024))
    ratio=$((compressed_size * 100 / (original_size > 0 ? original_size : 1)))

    echo -e " ${GREEN}done${NC} (${original_mb}MB -> ${compressed_mb}MB, ${ratio}%)"
done

# Pack the licence files: data/licenses/<source>/<file>, regular files only
echo -n "  Packing licences..."
DATA_DIR="${DATA_DIR}" ASSET_PATH="${OUTPUT_DIR}/${LICENCE_ASSET}" "$VENV/bin/python" -c "
import os, tarfile, zstandard
from pathlib import Path
from windows_triage import release_manifest as m

base = Path(os.environ['DATA_DIR']) / m.LICENCE_DIR
files = sorted(
    p for p in base.glob('*/*')
    if p.is_file() and not p.is_symlink() and not p.parent.is_symlink()
)
with open(os.environ['ASSET_PATH'], 'wb') as raw:
    with zstandard.ZstdCompressor().stream_writer(raw, closefd=False) as out:
        with tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            for path in files:
                info = tarfile.TarInfo(path.relative_to(base).as_posix())
                info.size = path.stat().st_size
                info.mode = 0o644
                with open(path, 'rb') as f:
                    tar.addfile(info, f)
"
WRITTEN+=("${LICENCE_ASSET}")
echo -e " ${GREEN}done${NC}"

echo ""

# Generate checksums of the files this run wrote
echo -n "  Generating checksums..."
(cd "$OUTPUT_DIR" && sha256sum -- "${WRITTEN[@]}" > checksums.sha256)
echo -e " ${GREEN}done${NC}"

# Record database metadata
echo -n "  Generating metadata..."
DATA_DIR="${DATA_DIR}" OUTPUT_DIR="${OUTPUT_DIR}" PACK_DBS="${PACK_DBS}" "$VENV/bin/python" -c "
import json, os
from datetime import datetime, timezone
from pathlib import Path
from windows_triage import release_manifest as m

data_dir = Path(os.environ['DATA_DIR'])
meta = {'created': datetime.now(timezone.utc).isoformat(), 'databases': {}}
for db in os.environ['PACK_DBS'].split():
    path = data_dir / db
    meta['databases'][db] = {
        'size_bytes': path.stat().st_size,
        'tables': m.table_counts(path),
    }
with open(Path(os.environ['OUTPUT_DIR']) / 'metadata.json', 'w') as f:
    json.dump(meta, f, indent=2)
"
echo -e " ${GREEN}done${NC}"

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Release assets ready in: ${OUTPUT_DIR}/${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "Files:"
ls -lh "${OUTPUT_DIR}/"
echo ""
echo "To create a GitHub release (the tag is triage-db-v followed by the UTC build date):"
echo "  TAG=\"triage-db-v\$(date -u +%Y.%m.%d)\""
echo "  gh release create \"\$TAG\" --latest=false ${OUTPUT_DIR}/*.zst ${OUTPUT_DIR}/checksums.sha256 \\"
echo "    --title \"Triage Databases \$TAG\" \\"
echo "    --notes \"Pre-built triage databases for windows-triage\""
