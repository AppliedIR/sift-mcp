"""Download pre-built triage databases from GitHub releases.

Replaces the shell script ``download-databases.sh`` with a cross-platform
Python implementation that works inside the Valhuntir venv.

Usage:
    python -m windows_triage.scripts.download_databases [--dest DIR] [--tag TAG]

Authentication:
    For private repos, set GITHUB_TOKEN or have ``gh`` CLI authenticated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from windows_triage import release_manifest

REPO = "AppliedIR/sift-mcp"
CHECKSUMS = "checksums.sha256"
ASSETS = (
    *(f"{name}.zst" for name in release_manifest.default_databases()),
    CHECKSUMS,
)
TAG_FILE = "installed_release.json"
MAX_ATTEMPTS = 3
CHUNK_SIZE = 1024 * 1024  # 1 MB


def _github_headers() -> dict[str, str]:
    """Build HTTP headers for GitHub API, including token if available.

    Token sources (in order): GITHUB_TOKEN env var, ``gh auth token`` CLI.
    """
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                token = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_release(tag: str = "latest") -> dict:
    """Fetch release metadata from GitHub API.

    When tag is "latest", finds the most recent triage-db-* release
    that contains .db.zst assets. Otherwise fetches the exact tag.
    """
    headers = _github_headers()

    if tag == "latest":
        # Find most recent triage DB release by tag prefix.
        # per_page=100 prevents pagination issues as code releases
        # accumulate (default is 30).
        url = f"https://api.github.com/repos/{REPO}/releases?per_page=100"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            releases = json.loads(resp.read())
            matching = [
                r
                for r in releases
                if r["tag_name"].startswith("triage-db-")
                and any(a["name"].endswith(".db.zst") for a in r.get("assets", []))
            ]
            if matching:
                return matching[0]  # GitHub returns most recent first
            raise ValueError(
                "No triage database releases found. "
                "Expected releases with tag prefix 'triage-db-' "
                "containing .db.zst assets."
            )
    else:
        url = f"https://api.github.com/repos/{REPO}/releases/tags/{tag}"
        req = urllib.request.Request(url, headers=headers)
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


def _listed_checksums(temp_dir: Path) -> set[str]:
    """The file names ``checksums.sha256`` lists."""
    checksum_file = temp_dir / CHECKSUMS
    if not checksum_file.is_file():
        return set()
    names = set()
    for line in checksum_file.read_text().strip().splitlines():
        parts = line.split()
        if len(parts) >= 2:
            names.add(parts[1])
    return names


def _verify_checksums(temp_dir: Path) -> bool:
    """Verify SHA-256 checksums of downloaded compressed files."""
    checksum_file = temp_dir / CHECKSUMS
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
            # Skip files not in our download list (e.g. registry DB)
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


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _remove_tag(dest: Path) -> None:
    """Remove the installed-release tag file, if there is one."""
    try:
        (dest / TAG_FILE).unlink()
    except FileNotFoundError:
        pass


def _write_tag(dest: Path, tag_name: str, names: list[str]) -> None:
    """Write the installed-release tag file: the release tag, the install time and
    each installed DB's sha256."""
    tag = {
        "tag_name": tag_name,
        "installed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "databases": {name: _file_sha256(dest / name) for name in names},
    }
    tmp = dest / f".{TAG_FILE}.tmp"
    tmp.write_text(json.dumps(tag, indent=2) + "\n")
    os.replace(tmp, dest / TAG_FILE)


def read_installed_tag(dest_dir: str | Path) -> str | None:
    """The installed release's tag, or None.

    The tag is returned only while every DB the tag file lists is on disk with the
    sha256 recorded at install; a DB replaced or changed since gives None. Each call
    hashes every listed DB in full.
    """
    dest = Path(dest_dir)
    try:
        tag = json.loads((dest / TAG_FILE).read_text())
        tag_name = tag["tag_name"]
        databases = tag["databases"]
        if not isinstance(tag_name, str) or not tag_name:
            return None
        if not isinstance(databases, dict) or not databases:
            return None
        for name, digest in databases.items():
            if PurePosixPath(name).name != name:
                return None
            if _file_sha256(dest / name) != digest:
                return None
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return tag_name


def _licence_members(tar: tarfile.TarFile):
    """Yield (relative path, bytes) for each licence file in the asset; raise
    ValueError naming any member that is not a plain ``<source>/<file>``."""
    for member in tar:
        parts = PurePosixPath(member.name).parts
        bad = (
            not parts
            or PurePosixPath(member.name).is_absolute()
            or any(p in ("", ".", "..") for p in parts)
        )
        if member.isdir() and not bad and len(parts) == 1:
            continue
        if bad or not member.isfile() or len(parts) != 2:
            raise ValueError(f"unexpected member in licence asset: {member.name}")
        cap = release_manifest.LICENCE_FILE_MAX
        if member.size > cap:
            raise ValueError(f"licence file over {cap} bytes: {member.name}")
        data = tar.extractfile(member).read()
        yield PurePosixPath(*parts), data


def _install_licences(asset: Path, dest: Path) -> None:
    """Extract the licence asset to ``dest/licenses/<source>/``, replacing the dir
    only once every member is read and checked."""
    import zstandard as zstd

    licence_dir = release_manifest.LICENCE_DIR
    with open(asset, "rb") as fin:
        reader = zstd.ZstdDecompressor().stream_reader(fin)
        with tarfile.open(fileobj=reader, mode="r|") as tar:
            files = list(_licence_members(tar))
    staging = Path(tempfile.mkdtemp(prefix=f".{licence_dir}-", dir=dest))
    try:
        for rel, data in files:
            path = staging.joinpath(*rel.parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        final = dest / licence_dir
        if final.is_dir() and not final.is_symlink():
            shutil.rmtree(final)
        elif final.exists() or final.is_symlink():
            final.unlink()
        os.replace(staging, final)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


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

    # The licence asset is fetched when the release has it.
    wanted = list(ASSETS)
    if _get_asset_url(release, release_manifest.LICENCE_ASSET):
        wanted.append(release_manifest.LICENCE_ASSET)
    db_names = [a.removesuffix(".zst") for a in ASSETS if a.endswith(".db.zst")]

    for attempt in range(1, MAX_ATTEMPTS + 1):
        temp_dir = Path(tempfile.mkdtemp(prefix="triage-db-"))
        try:
            # Download assets
            print(f"\nDownloading (attempt {attempt}/{MAX_ATTEMPTS})...")
            download_ok = True
            for asset_name in wanted:
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

            listed = _listed_checksums(temp_dir)
            unlisted = [a for a in wanted if a != CHECKSUMS and a not in listed]

            # Decompress. The old tag file goes first: from the first write to
            # the install dir on, only a verified install leaves a tag file.
            _remove_tag(dest)
            print("\nDecompressing...")
            for db_name in db_names:
                zst_path = temp_dir / f"{db_name}.zst"
                db_path = dest / db_name
                print(f"  {db_name}...", end="", flush=True)
                _decompress_zst(zst_path, db_path)
                size_mb = db_path.stat().st_size / (1024 * 1024)
                print(f" {size_mb:.1f} MB")

            # Verify databases
            print("\nVerifying databases...")
            ok = True
            for db_name in db_names:
                errors = release_manifest.check_downloaded(db_name, dest / db_name)
                for error in errors:
                    print(f"  {error}")
                if not errors:
                    print(f"  {db_name}: every table matches the release's counts")
                ok &= not errors

            if not ok:
                print("\nDatabase verification failed.")
                return False

            licence_asset = temp_dir / release_manifest.LICENCE_ASSET
            if release_manifest.LICENCE_ASSET in wanted:
                try:
                    _install_licences(licence_asset, dest)
                except (OSError, ValueError, tarfile.TarError) as e:
                    print(f"\nLicence install failed: {e}")
                    return False
                print(f"  Licences installed in {dest / release_manifest.LICENCE_DIR}")

            if unlisted:
                print(
                    f"\n{CHECKSUMS} does not list: {', '.join(unlisted)}. "
                    "Not a verified install; no installed-release tag written."
                )
                return False

            _write_tag(dest, tag_name, db_names)
            print("\nDatabases installed successfully.")
            return True

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
