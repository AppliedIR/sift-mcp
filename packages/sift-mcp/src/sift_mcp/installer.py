"""Hayabusa auto-installer — download if not present."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import subprocess
from pathlib import Path

from sift_mcp.config import get_config

logger = logging.getLogger(__name__)

HAYABUSA_VERSION = "2.18.0"


def install_hayabusa() -> str | None:
    """Attempt to install Hayabusa. Returns binary path or None.

    Downloads the pinned release (v{HAYABUSA_VERSION}) from GitHub,
    verifies the SHA-256 hash against the release SHA256SUMS file,
    and installs to the configured hayabusa_dir.
    """
    config = get_config()
    install_dir = Path(config.hayabusa_dir)
    binary = install_dir / "hayabusa"

    if binary.is_file() and os.access(binary, os.X_OK):
        return str(binary)

    try:
        install_dir.mkdir(parents=True, exist_ok=True)

        # Detect architecture
        arch = platform.machine().lower()
        if arch in ("x86_64", "amd64"):
            arch_suffix = "x86_64"
        elif arch in ("aarch64", "arm64"):
            arch_suffix = "aarch64"
        else:
            logger.warning("Unsupported architecture for Hayabusa: %s", arch)
            return None

        # Use GitHub API to find pinned release
        release_url = (
            "https://api.github.com/repos/Yamato-Security/hayabusa/releases/tags/"
            f"v{HAYABUSA_VERSION}"
        )
        result = subprocess.run(
            ["curl", "-sL", release_url],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.warning("Cannot reach GitHub API for Hayabusa install")
            return None

        try:
            release = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.warning("GitHub API response is not valid JSON: %s", e)
            return None
        assets = release.get("assets", [])

        # Find Linux musl binary
        target_name = None
        for asset in assets:
            name = asset["name"]
            if (
                "linux" in name.lower()
                and arch_suffix in name
                and "musl" in name.lower()
            ):
                target_name = name
                download_url = asset["browser_download_url"]
                break

        if not target_name:
            logger.warning(
                "No matching Hayabusa binary found for linux/%s", arch_suffix
            )
            return None

        # Download archive
        archive_path = install_dir / target_name
        dl_result = subprocess.run(
            ["curl", "-sL", "-o", str(archive_path), download_url],
            capture_output=True,
            timeout=120,
        )
        if dl_result.returncode != 0:
            return None

        # Download SHA256SUMS from the same release
        sums_url = (
            "https://github.com/Yamato-Security/hayabusa/releases/download/"
            f"v{HAYABUSA_VERSION}/SHA256SUMS"
        )
        sums_result = subprocess.run(
            ["curl", "-sL", sums_url],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if sums_result.returncode != 0 or not sums_result.stdout.strip():
            archive_path.unlink(missing_ok=True)
            logger.warning("Cannot download SHA256SUMS for Hayabusa verification")
            return None

        # Parse expected hash from SHA256SUMS
        expected_hash = None
        for line in sums_result.stdout.strip().splitlines():
            # Format: "<hash>  <filename>" or "<hash> <filename>"
            parts = line.split()
            if len(parts) >= 2 and parts[-1] == target_name:
                expected_hash = parts[0].lower()
                break

        if not expected_hash:
            archive_path.unlink(missing_ok=True)
            logger.warning(
                "No SHA-256 entry for %s in SHA256SUMS",
                target_name,
            )
            return None

        # Compute actual hash of downloaded archive
        sha256 = hashlib.sha256()
        with open(archive_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        actual_hash = sha256.hexdigest().lower()

        if actual_hash != expected_hash:
            archive_path.unlink(missing_ok=True)
            logger.warning(
                "Hayabusa hash mismatch: expected %s, got %s",
                expected_hash,
                actual_hash,
            )
            raise ValueError(
                f"Hayabusa archive hash verification failed: "
                f"expected {expected_hash}, got {actual_hash}"
            )

        # Extract
        if target_name.endswith(".zip"):
            extract_result = subprocess.run(
                ["unzip", "-o", str(archive_path), "-d", str(install_dir)],
                capture_output=True,
                timeout=60,
            )
            if extract_result.returncode != 0:
                logger.warning(
                    "unzip failed for %s: exit code %d",
                    archive_path,
                    extract_result.returncode,
                )
                return None
        elif ".tar" in target_name:
            extract_result = subprocess.run(
                ["tar", "xf", str(archive_path), "-C", str(install_dir)],
                capture_output=True,
                timeout=60,
            )
            if extract_result.returncode != 0:
                logger.warning(
                    "tar extract failed for %s: exit code %d",
                    archive_path,
                    extract_result.returncode,
                )
                return None

        # Find the binary
        try:
            candidates = list(install_dir.rglob("hayabusa*"))
        except OSError as e:
            logger.warning(
                "Failed to search for hayabusa binary in %s: %s", install_dir, e
            )
            candidates = []
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)

        # Make executable if not already
        if binary.exists():
            binary.chmod(0o755)
            return str(binary)

        return None

    except (
        subprocess.TimeoutExpired,
        FileNotFoundError,
        PermissionError,
        json.JSONDecodeError,
        ValueError,
    ) as e:
        logger.warning("Hayabusa install failed: %s", e)
        return None
