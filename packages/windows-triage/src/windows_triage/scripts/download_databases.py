"""Download pre-built triage databases from GitHub releases.

Replaces the shell script ``download-databases.sh`` with a cross-platform
Python implementation that works inside the AIIR venv.

Usage:
    python -m windows_triage.scripts.download_databases [--dest DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = "AppliedIR/sift-mcp"
ASSETS = ("known_good.db.zst", "context.db.zst", "checksums.sha256")
MAX_ATTEMPTS = 3
CHUNK_SIZE = 1024 * 1024  # 1 MB


def _github_headers() -> dict[str, str]:
    """Build HTTP headers for GitHub API, including token if available."""
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_release(tag: str = "latest") -> dict:
    """Fetch release metadata from GitHub API."""
    if tag == "latest":
        url = f"https://api.github.com/repos/{REPO}/releases/latest"
    else:
        url = f"https://api.github.com/repos/{REPO}/releases/tags/{tag}"

    req = urllib.request.Request(url, headers=_github_headers())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _get_asset_url(release: dict, asset_name: str) -> str | None:
    """Extract the API download URL for a named asset."""
    for asset in release.get("assets", []):
        if asset["name"] == asset_name:
            return asset["url"]
    return None


def _download_asset(url: str, dest: Path) -> None:
    """Download a single asset to dest with progress indication."""
    headers = _github_headers()
    headers["Accept"] = "application/octet-stream"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=300) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    pct = downloaded * 100 // total
                    mb = downloaded / (1024 * 1024)
                    print(f"\r  {dest.name}: {mb:.1f} MB ({pct}%)", end="", flush=True)
        print()


def _verify_checksums(temp_dir: Path) -> bool:
    """Verify SHA-256 checksums of downloaded compressed files."""
    checksum_file = temp_dir / "checksums.sha256"
    if not checksum_file.is_file():
        print("  No checksums file. Skipping verification.")
        return True

    ok = True
    for line in checksum_file.read_text().strip().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        expected_hash = parts[0]
        file_name = parts[1]
        file_path = temp_dir / file_name
        if not file_path.is_file():
            print(f"  MISSING: {file_name}")
            ok = False
            continue
        actual_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if actual_hash == expected_hash:
            print(f"  OK: {file_name}")
        else:
            print(f"  FAILED: {file_name}")
            print(f"    expected: {expected_hash}")
            print(f"    got:      {actual_hash}")
            ok = False
    return ok


def _decompress_zst(src: Path, dest: Path) -> None:
    """Decompress a .zst file using the zstandard library."""
    import zstandard as zstd

    dctx = zstd.ZstdDecompressor()
    with open(src, "rb") as fin, open(dest, "wb") as fout:
        dctx.copy_stream(fin, fout)


def _verify_database(db_path: Path, table: str, min_rows: int, label: str) -> bool:
    """Check that a database table has at least min_rows rows."""
    if not db_path.is_file():
        print(f"  {label}: missing")
        return False
    try:
        conn = sqlite3.connect(str(db_path))
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        conn.close()
        if count >= min_rows:
            print(f"  {label}: {count:,} rows")
            return True
        else:
            print(f"  {label}: only {count:,} rows (expected {min_rows:,}+)")
            return False
    except Exception as e:
        print(f"  {label}: verification error ({e})")
        return False


def download_databases(dest_dir: str | Path, tag: str = "latest") -> bool:
    """Download and verify triage databases.

    Args:
        dest_dir: Directory to place the decompressed .db files.
        tag: GitHub release tag (default: "latest").

    Returns:
        True on success, False on failure.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)

    print(f"Fetching release info from {REPO}...")
    try:
        release = _fetch_release(tag)
    except Exception as e:
        print(f"Failed to fetch release: {e}")
        return False

    tag_name = release.get("tag_name", tag)
    print(f"Release: {tag_name}")

    for attempt in range(1, MAX_ATTEMPTS + 1):
        temp_dir = Path(tempfile.mkdtemp(prefix="triage-db-"))
        try:
            # Download assets
            print(f"\nDownloading (attempt {attempt}/{MAX_ATTEMPTS})...")
            download_ok = True
            for asset_name in ASSETS:
                url = _get_asset_url(release, asset_name)
                if not url:
                    print(f"  Asset not found in release: {asset_name}")
                    download_ok = False
                    continue
                try:
                    _download_asset(url, temp_dir / asset_name)
                except Exception as e:
                    print(f"  Download failed for {asset_name}: {e}")
                    download_ok = False

            if not download_ok:
                if attempt < MAX_ATTEMPTS:
                    wait = attempt * 5
                    print(f"  Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                print("All download attempts failed.")
                return False

            # Verify checksums
            print("\nVerifying checksums...")
            if not _verify_checksums(temp_dir):
                if attempt < MAX_ATTEMPTS:
                    wait = attempt * 5
                    print(f"  Checksum mismatch. Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                print("Checksum verification failed after all attempts.")
                return False

            # Decompress
            print("\nDecompressing...")
            for zst_name in ("known_good.db.zst", "context.db.zst"):
                zst_path = temp_dir / zst_name
                db_name = zst_name.removesuffix(".zst")
                db_path = dest / db_name
                print(f"  {db_name}...", end="", flush=True)
                _decompress_zst(zst_path, db_path)
                size_mb = db_path.stat().st_size / (1024 * 1024)
                print(f" {size_mb:.1f} MB")

            # Verify databases
            print("\nVerifying databases...")
            ok = True
            ok &= _verify_database(dest / "known_good.db", "baseline_files", 1_000_000, "known_good.db")
            ok &= _verify_database(dest / "context.db", "lolbins", 100, "context.db (lolbins)")
            ok &= _verify_database(dest / "context.db", "vulnerable_drivers", 100, "context.db (drivers)")

            if ok:
                print("\nDatabases installed successfully.")
                return True
            else:
                print("\nDatabase verification failed.")
                return False

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download pre-built triage databases from GitHub releases.",
    )
    parser.add_argument(
        "--dest",
        default=None,
        help="Destination directory (default: data/ relative to package)",
    )
    parser.add_argument(
        "--tag",
        default="latest",
        help="Release tag to download (default: latest)",
    )
    args = parser.parse_args()

    if args.dest:
        dest = Path(args.dest)
    else:
        # Default: data/ directory relative to the windows-triage package
        pkg_root = Path(__file__).resolve().parent.parent.parent.parent
        dest = pkg_root / "data"

    if download_databases(dest, args.tag):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
