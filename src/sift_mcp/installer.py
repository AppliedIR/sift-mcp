"""Hayabusa auto-installer — download if not present."""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from pathlib import Path

from sift_mcp.config import get_config

logger = logging.getLogger(__name__)


def install_hayabusa() -> str | None:
    """Attempt to install Hayabusa. Returns binary path or None.

    Downloads the latest release from GitHub if network is available.
    Installs to the configured hayabusa_dir.
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

        # Use GitHub API to find latest release
        result = subprocess.run(
            [
                "curl", "-sL",
                "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest",
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            logger.warning("Cannot reach GitHub API for Hayabusa install")
            return None

        import json
        release = json.loads(result.stdout)
        assets = release.get("assets", [])

        # Find Linux musl binary
        target_name = None
        for asset in assets:
            name = asset["name"]
            if "linux" in name.lower() and arch_suffix in name and "musl" in name.lower():
                target_name = name
                download_url = asset["browser_download_url"]
                break

        if not target_name:
            logger.warning("No matching Hayabusa binary found for linux/%s", arch_suffix)
            return None

        # Download
        archive_path = install_dir / target_name
        dl_result = subprocess.run(
            ["curl", "-sL", "-o", str(archive_path), download_url],
            capture_output=True, timeout=120,
        )
        if dl_result.returncode != 0:
            return None

        # Extract
        if target_name.endswith(".zip"):
            subprocess.run(
                ["unzip", "-o", str(archive_path), "-d", str(install_dir)],
                capture_output=True, timeout=60,
            )
        elif ".tar" in target_name:
            subprocess.run(
                ["tar", "xf", str(archive_path), "-C", str(install_dir)],
                capture_output=True, timeout=60,
            )

        # Find the binary
        for candidate in install_dir.rglob("hayabusa*"):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)

        # Make executable if not already
        if binary.exists():
            binary.chmod(0o755)
            return str(binary)

        return None

    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, json.JSONDecodeError) as e:
        logger.warning("Hayabusa install failed: %s", e)
        return None
