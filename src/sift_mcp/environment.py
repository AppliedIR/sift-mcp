"""Environment detection: WSL, SIFT version, tool availability."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def is_wsl() -> bool:
    """Detect if running under WSL."""
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower()
    except (FileNotFoundError, PermissionError):
        return False


def get_sift_version() -> str | None:
    """Detect SIFT workstation version if installed."""
    version_file = Path("/etc/sift-version")
    if version_file.exists():
        return version_file.read_text().strip()
    # Check cast package
    try:
        result = subprocess.run(
            ["cast", "--version"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def find_binary(name: str, extra_paths: list[str] | None = None) -> str | None:
    """Find a binary on PATH or in common forensic tool locations."""
    # shutil.which checks PATH
    found = shutil.which(name)
    if found:
        return found

    # Check extra paths
    search_paths = extra_paths or [
        "/usr/local/bin",
        "/opt/zimmerman",
        "/opt/volatility3",
        "/opt/hayabusa",
    ]
    for d in search_paths:
        candidate = Path(d) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    return None


def get_environment_info() -> dict:
    """Collect environment information for diagnostics."""
    return {
        "wsl": is_wsl(),
        "sift_version": get_sift_version(),
        "platform": os.uname().sysname,
        "python": os.sys.version,
    }
