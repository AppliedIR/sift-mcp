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


def _build_index(data_dir: Path) -> int:
    """Build the full RAG index and return record count."""
    from ..build import build

    os.environ["ANONYMIZED_TELEMETRY"] = "False"
    result = build(force_fetch=True, data_dir=data_dir)

    if result.status != "success":
        print(f"Build failed: {result.errors}")
        return 0

    return result.total_records


def _create_tarball(data_dir: Path, output_path: Path) -> None:
    """Create a zstd-compressed tarball of the index data."""
    print(f"Creating {output_path.name}...")

    # Create uncompressed tar in memory, then compress with zstd
    tar_tmp = output_path.with_suffix(".tar")
    with tarfile.open(tar_tmp, "w") as tar:
        for subpath in ("chroma", "sources", "metadata.json", "user_state.json"):
            full_path = data_dir / subpath
            if full_path.exists():
                tar.add(full_path, arcname=subpath)
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

    # Data dir is relative to the package
    pkg_root = Path(__file__).resolve().parent.parent.parent.parent
    data_dir = Path(os.environ.get("RAG_INDEX_DIR", pkg_root / "data"))

    if not args.skip_build:
        print("=" * 60)
        print("Step 1: Building full index from source")
        print("=" * 60)
        record_count = _build_index(data_dir)
        if record_count < 20000:
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
        if record_count < 20000:
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
    attr_src = Path(__file__).resolve().parent.parent.parent.parent / "ATTRIBUTION.md"
    attr_dest = output_dir / "ATTRIBUTION.md"
    if attr_src.exists():
        shutil.copy2(attr_src, attr_dest)
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
