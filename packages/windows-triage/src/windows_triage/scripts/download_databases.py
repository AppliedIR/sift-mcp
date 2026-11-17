"""Download pre-built triage databases from GitHub releases.

Replaces the shell script ``download-databases.sh`` with a cross-platform
Python implementation that works inside the Valhuntir venv.

Usage:
    python -m windows_triage.scripts.download_databases [--dest DIR] [--tag TAG]
    python -m windows_triage.scripts.download_databases --check [--dest DIR]

It installs the newest non-prerelease triage-db-* release with this version's
asset names (or --tag's): RELEASE_TAG's DBs must match its counts exactly, any
other release's must reach the floors. Everything is downloaded and checked in a
staging dir inside DEST and only then swapped in, so a failed download or check
leaves the installed databases as they were.

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
METADATA = "metadata.json"  # its size_bytes are the unpacked sizes: a hint only
ASSETS = (
    *(f"{name}.zst" for name in release_manifest.default_databases()),
    CHECKSUMS,
)
TAG_FILE = "installed_release.json"
STAGE_PREFIX = ".triage-db-new-"  # the verify-then-swap dir, in the install dir
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


def _fetch_release(tag: str) -> dict:
    """Fetch the metadata of the release with this exact tag from the GitHub API."""
    url = f"https://api.github.com/repos/{REPO}/releases/tags/{tag}"
    req = urllib.request.Request(url, headers=_github_headers())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _usable(release: dict) -> bool:
    """Not a prerelease, with every asset this version fetches (a format change
    renames them, so older code never selects that release)."""
    names = {a.get("name") for a in release.get("assets", [])}
    return not release.get("prerelease") and all(a in names for a in ASSETS)


def _newest_release() -> dict | None:
    """The newest usable release (GitHub lists the newest first), or None."""
    url = f"https://api.github.com/repos/{REPO}/releases?per_page=100"
    req = urllib.request.Request(url, headers=_github_headers())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return next((r for r in json.loads(resp.read()) if _usable(r)), None)


def _sizes(release: dict, names: list[str]) -> int:
    return sum(
        a.get("size", 0) for a in release.get("assets", []) if a.get("name") in names
    )


def _unpacked_bytes(release: dict, db_names: list[str]) -> int:
    """A size hint: an unreadable metadata.json gives 0 rather than failing an install
    the download's checks would pass; the pre-check then covers the download only."""
    url = _get_asset_url(release, METADATA)
    if not url:
        return 0
    headers = {**_github_headers(), "Accept": "application/octet-stream"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            dbs = json.loads(resp.read(CHUNK_SIZE))["databases"]
        return sum(int(dbs[name]["size_bytes"]) for name in db_names)
    except (OSError, ValueError, KeyError, TypeError):
        return 0


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


def _verify_checksums(temp_dir: Path) -> set[str] | None:
    """Verify SHA-256 checksums of downloaded compressed files.

    Returns the file names ``checksums.sha256`` lists, or None on a mismatch.
    """
    checksum_file = temp_dir / CHECKSUMS
    if not checksum_file.is_file():
        print("  No checksums file. Skipping verification.")
        return set()

    ok = True
    names = set()
    for line in checksum_file.read_text().strip().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        expected_hash = parts[0]
        file_name = parts[1]
        names.add(file_name)
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
    return names if ok else None


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


def check(dest_dir: str | Path) -> dict:
    """What --check prints; a GitHub error raises."""
    dest = Path(dest_dir)
    release = _newest_release() or {}
    paths = [dest / name for name in release_manifest.default_databases()]
    return {
        "installed": read_installed_tag(dest) or "unknown",
        "absent": any(not p.is_file() or p.stat().st_size == 0 for p in paths),
        "newest": release.get("tag_name"),
        "download_bytes": _sizes(
            release, [*ASSETS, release_manifest.LICENCE_ASSET, METADATA]
        ),
    }


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


def _stage_licences(asset: Path, stage: Path) -> None:
    """Extract the licence asset to ``stage/licenses/<source>/`` once every member
    is read and checked; the swap moves it into place."""
    import zstandard as zstd

    with open(asset, "rb") as fin:
        reader = zstd.ZstdDecompressor().stream_reader(fin)
        with tarfile.open(fileobj=reader, mode="r|") as tar:
            files = list(_licence_members(tar))
    staged = stage / release_manifest.LICENCE_DIR
    staged.mkdir()
    for rel, data in files:
        path = staged.joinpath(*rel.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _clean_stages(dest: Path) -> None:
    """Remove each stage dir a stopped install left in ``dest``. One holding old/
    (the files a failed undo kept) is named and left in place."""
    for stage in sorted(dest.glob(f"{STAGE_PREFIX}*")):
        if stage.is_symlink() or not stage.is_dir():
            continue
        if _exists(stage / "old"):
            print(
                f"  {stage} holds files an earlier install could not put back "
                "(in old/); it is left in place."
            )
            continue
        print(f"  Removing {stage}, left by an install that stopped")
        shutil.rmtree(stage, ignore_errors=True)


def _swap_in(
    dest: Path, stage: Path, db_names: list[str], tag_name: str, licences: bool
) -> str:
    """Move the verified files in ``stage`` into ``dest``, each old one into
    ``stage/old``, then write the tag file. The old tag file goes first, so an
    install stopped part way leaves no tag file. A failed move undoes every move
    made. Returns "installed", "undone", or "kept" when the undo failed too (the
    old files are left in ``stage/old``)."""
    old = stage / "old"
    old.mkdir()
    done = []  # (from, to) for each move made, in order

    def move(src: Path, dst: Path) -> None:
        os.replace(src, dst)
        done.append((src, dst))

    try:
        if _exists(dest / TAG_FILE):
            move(dest / TAG_FILE, old / TAG_FILE)
        for name in db_names:
            for side in (dest / f"{name}-wal", dest / f"{name}-shm"):
                if _exists(side):  # an old DB's journal must not meet the new DB
                    move(side, old / side.name)
            if _exists(dest / name):
                move(dest / name, old / name)
            move(stage / name, dest / name)
        if licences:
            final = dest / release_manifest.LICENCE_DIR
            if _exists(final):
                move(final, old / final.name)
            move(stage / final.name, final)
        try:
            _write_tag(dest, tag_name, db_names)
        except OSError:
            (dest / f".{TAG_FILE}.tmp").unlink(missing_ok=True)
            raise
    except OSError as e:
        failed = f"\ninstalling into {dest} failed: {e}"
        try:
            for src, dst in reversed(done):
                os.replace(dst, src)
        except OSError as undo:
            print(failed)
            print(
                f"undoing it failed too: {undo}. The files it replaced are kept in "
                f"{old}; {dest} may be partly changed."
            )
            return "kept"
        print(f"{failed}; the installed databases were not changed.")
        return "undone"
    return "installed"


def download_databases(dest_dir: str | Path, tag: str | None = None) -> bool:
    """Download and verify triage databases.

    Args:
        dest_dir: Directory to place the decompressed .db files.
        tag: GitHub release tag; by default the newest triage-db-* release that
            is not a prerelease and carries this version's asset names. A tag
            naming any other release is refused before anything is downloaded.

    Returns:
        True on success, False on failure. On failure the installed databases,
        tag and licences are unchanged, unless undoing a failed swap failed
        too: then the replaced files are kept in the staging dir's old/ and
        the output names it.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)

    print(f"Fetching release info from {REPO}...")
    try:
        release = _newest_release() if tag is None else _fetch_release(tag)
    except Exception as e:
        print(f"Failed to fetch release: {e}")
        return False
    if release is None or not _usable(release):
        which = "No release is" if tag is None else f"Release {tag} is not"
        print(
            f"{which} a triage-db-* release with this version's files (not a "
            "prerelease). Nothing was downloaded or changed."
        )
        return False

    tag_name = release["tag_name"]
    print(f"Release: {tag_name}")
    check_db = release_manifest.check_floors
    if tag_name == release_manifest.RELEASE_TAG:
        check_db = release_manifest.check_downloaded  # RELEASE_TAG: its exact counts

    _clean_stages(dest)

    # The licence asset is fetched when the release has it.
    wanted = list(ASSETS)
    if _get_asset_url(release, release_manifest.LICENCE_ASSET):
        wanted.append(release_manifest.LICENCE_ASSET)
    db_names = [a.removesuffix(".zst") for a in ASSETS if a.endswith(".db.zst")]
    need = _sizes(release, wanted) + _unpacked_bytes(release, db_names)
    if shutil.disk_usage(dest).free < need:
        print(f"Not enough free space ({need:,} bytes). Nothing was changed.")
        return False

    for attempt in range(1, MAX_ATTEMPTS + 1):
        # All in a stage dir in dest: the swap is renames, the next run's
        # _clean_stages removes a killed run's files, and the installed files are
        # untouched until every DB and the licences pass.
        stage = Path(tempfile.mkdtemp(prefix=STAGE_PREFIX, dir=dest))
        swap = None
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
                    _download_asset(url, stage / asset_name)
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
            listed = _verify_checksums(stage)
            if listed is None:
                if attempt < MAX_ATTEMPTS:
                    wait = attempt * 5
                    print(f"  Checksum mismatch. Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                print("Checksum verification failed after all attempts.")
                return False

            unlisted = [a for a in wanted if a != CHECKSUMS and a not in listed]
            if unlisted:
                print(
                    f"\n{CHECKSUMS} does not list: {', '.join(unlisted)}. "
                    "Not a verified install; the installed databases were not changed."
                )
                return False

            print("\nDecompressing...")
            for db_name in db_names:
                zst_path = stage / f"{db_name}.zst"
                db_path = stage / db_name
                print(f"  {db_name}...", end="", flush=True)
                _decompress_zst(zst_path, db_path)
                size_mb = db_path.stat().st_size / (1024 * 1024)
                print(f" {size_mb:.1f} MB")

            # Verify databases
            print("\nVerifying databases...")
            ok = True
            for db_name in db_names:
                errors = check_db(db_name, stage / db_name)
                for error in errors:
                    print(f"  {error}")
                if not errors:
                    print(f"  {db_name}: every table passed")
                ok &= not errors

            if not ok:
                print("\nDatabase verification failed.")
                return False

            licences = release_manifest.LICENCE_ASSET in wanted
            if licences:
                try:
                    _stage_licences(stage / release_manifest.LICENCE_ASSET, stage)
                except (OSError, ValueError, tarfile.TarError) as e:
                    print(f"\nLicence install failed: {e}")
                    return False

            swap = _swap_in(dest, stage, db_names, tag_name, licences)
            if swap != "installed":
                return False
            if licences:
                print(f"  Licences installed in {dest / release_manifest.LICENCE_DIR}")
            print("\nDatabases installed successfully.")
            return True

        finally:
            if swap != "kept":
                shutil.rmtree(stage, ignore_errors=True)

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
        default=None,
        help=(
            "Release tag to download, a triage-db-* release with this version's "
            "files (default: the newest)"
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Print the installed and newest release as JSON; download nothing",
    )
    args = parser.parse_args()

    if args.dest:
        dest = Path(args.dest)
    else:
        # Default: data/ directory relative to the windows-triage package
        pkg_root = Path(__file__).resolve().parent.parent.parent.parent
        dest = pkg_root / "data"

    if args.check:
        try:
            print(json.dumps(check(dest)))
        except Exception as e:  # GitHub unreachable or rate-limited, a bad reply
            sys.exit(f"Could not check for newer triage databases: {e}")
        sys.exit(0)
    if download_databases(dest, args.tag):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
