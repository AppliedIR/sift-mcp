"""Build a release-ready RAG index bundle for GitHub Releases.

Creates a compressed tarball of the RAG index that can be uploaded as a
GitHub Release asset for fast download by the installer.

Usage:
    python -m rag_mcp.scripts.build_release [--output-dir DIR]

The script:
1. Builds the full index from source (force-fetches all online sources)
2. Verifies record count > 20,000
3. Creates rag-index.tar.zst (zstd level 1 compression)
4. Generates rag-checksums.sha256
5. Prints upload instructions
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import zstandard as zstd

from .. import constants
from ..utils import resolve_data_dir

MIN_RECORD_COUNT = 20000

# The one bundle member packed from the package root, not the data dir
ATTRIBUTION = "ATTRIBUTION.md"
ATTRIBUTION_SRC = Path(__file__).resolve().parents[3] / ATTRIBUTION


def _member_path(data_dir: Path, name: str) -> Path:
    return ATTRIBUTION_SRC if name == ATTRIBUTION else data_dir / name


def _build_index(data_dir: Path) -> int:
    """Build the full RAG index and return record count."""
    from ..build import build

    os.environ["ANONYMIZED_TELEMETRY"] = "False"
    result = build(force_fetch=True, data_dir=data_dir, strict_sources=True)

    if result.status != "success":
        print(f"Build failed: {result.errors}")
        return 0

    return result.total_records


def _create_tarball(data_dir: Path, output_path: Path) -> None:
    """Create a zstd-compressed tarball of the bundle members.

    Exits 1 naming each member of constants.BUNDLE_MEMBERS that is missing
    (ATTRIBUTION.md from the package root, the rest from data_dir). Of the
    source JSONLs, only the enabled sources' are packed.
    """
    from ..sources import SOURCES, load_disabled_sources

    members = constants.BUNDLE_MEMBERS
    missing = [name for name in members if not _member_path(data_dir, name).exists()]
    if missing:
        for name in missing:
            where = ATTRIBUTION_SRC.parent if name == ATTRIBUTION else data_dir
            print(f"ERROR: Bundle member not found in {where}: {name}")
        sys.exit(1)

    disabled = load_disabled_sources(data_dir)
    enabled = {name for name in SOURCES if name not in disabled}

    def packed(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        parts = info.name.split("/")
        if (
            len(parts) == 2
            and parts[0] == constants.SOURCES_DIR_NAME
            and parts[1].endswith(".jsonl")
            and parts[1][: -len(".jsonl")] not in enabled
        ):
            print(f"  Skipped (not an enabled source): {info.name}")
            return None
        return info

    print(f"Creating {output_path.name}...")

    # Create uncompressed tar in memory, then compress with zstd
    tar_tmp = output_path.with_suffix(".tar")
    with tarfile.open(tar_tmp, "w") as tar:
        for subpath in members:
            # a member under another one (sources/licenses) is packed with it
            if any(subpath.startswith(f"{other}/") for other in members):
                continue
            tar.add(_member_path(data_dir, subpath), arcname=subpath, filter=packed)
            print(f"  Added: {subpath}")

    # Compress with zstd level 1 (fast, good enough)
    cctx = zstd.ZstdCompressor(level=1)
    with open(tar_tmp, "rb") as fin, open(output_path, "wb") as fout:
        cctx.copy_stream(fin, fout)

    tar_tmp.unlink()

    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"  Compressed: {size_mb:.1f} MB")


def _generate_checksums(output_dir: Path) -> None:
    """Generate SHA-256 checksums file."""
    checksum_path = output_dir / "rag-checksums.sha256"
    tarball_path = output_dir / "rag-index.tar.zst"

    lines = []
    if tarball_path.exists():
        sha = hashlib.sha256(tarball_path.read_bytes()).hexdigest()
        lines.append(f"{sha} rag-index.tar.zst")

    checksum_path.write_text("\n".join(lines) + "\n")
    print(f"  Generated: {checksum_path.name}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a release-ready RAG index bundle.",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory for output files (default: current directory)",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip building, use existing data/ directory",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    data_dir = resolve_data_dir()

    if not args.skip_build:
        print("=" * 60)
        print("Step 1: Building full index from source")
        print("=" * 60)
        record_count = _build_index(data_dir)
        if record_count < MIN_RECORD_COUNT:
            print(f"\nERROR: Only {record_count:,} records (expected 20,000+)")
            sys.exit(1)
        print(f"\nBuild complete: {record_count:,} records")
    else:
        # Verify existing index
        metadata_path = data_dir / "metadata.json"
        if not metadata_path.exists():
            print("ERROR: No metadata.json found. Run without --skip-build.")
            sys.exit(1)
        with open(metadata_path, encoding="utf-8") as f:
            metadata = json.load(f)
        record_count = metadata.get("record_count", 0)
        if record_count < MIN_RECORD_COUNT:
            print(f"ERROR: Only {record_count:,} records (expected 20,000+)")
            sys.exit(1)
        print(f"Using existing index: {record_count:,} records")

    print("")
    print("=" * 60)
    print("Step 2: Creating release bundle")
    print("=" * 60)

    tarball_path = output_dir / "rag-index.tar.zst"
    _create_tarball(data_dir, tarball_path)
    _generate_checksums(output_dir)

    # Copy ATTRIBUTION.md to output directory
    attr_dest = output_dir / ATTRIBUTION
    if ATTRIBUTION_SRC.exists():
        shutil.copy2(ATTRIBUTION_SRC, attr_dest)
        print("  Copied: ATTRIBUTION.md")
    else:
        print("  WARNING: ATTRIBUTION.md not found in package root")

    # Suggested tag
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    tag = f"rag-index-v{today}"

    print("")
    print("=" * 60)
    print("Bundle ready!")
    print("=" * 60)
    print(f"  Tarball:    {tarball_path}")
    print(f"  Checksums:  {output_dir / 'rag-checksums.sha256'}")
    if attr_dest.exists():
        print(f"  Attribution: {attr_dest}")
    print(f"  Records:    {record_count:,}")
    print("")
    print("Upload to GitHub Release:")
    print(f"  gh release create {tag} --latest=false \\")
    print(f"    {tarball_path} \\")
    print(f"    {output_dir / 'rag-checksums.sha256'} \\")
    if attr_dest.exists():
        print(f"    {attr_dest} \\")
    print(f'    --title "RAG Index {today}" \\')
    print(f'    --notes "Pre-built RAG index with {record_count:,} records"')


if __name__ == "__main__":
    main()
