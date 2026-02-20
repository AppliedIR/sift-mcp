"""Subprocess executor — shell=False, timeout, output capture.

All forensic tool execution goes through this module.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sift_mcp.config import get_config
from sift_mcp.exceptions import ExecutionError, TimeoutError

logger = logging.getLogger(__name__)


def execute(
    cmd_list: list[str],
    *,
    timeout: int | None = None,
    cwd: str | None = None,
    save_output: bool = False,
    save_dir: str | None = None,
) -> dict[str, Any]:
    """Execute a command as a subprocess (shell=False).

    Args:
        cmd_list: Command and arguments as a list.
        timeout: Seconds before timeout. Defaults to config value.
        cwd: Working directory.
        save_output: If True, write stdout/stderr to files with SHA-256 hashes.
        save_dir: Directory for saved output (defaults to cwd/extracted/).

    Returns:
        Dict with exit_code, stdout, stderr, elapsed_seconds, and optional saved file info.
    """
    config = get_config()
    timeout = timeout or config.default_timeout

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        elapsed = time.monotonic() - start

        response: dict[str, Any] = {
            "exit_code": result.returncode,
            "stdout": _truncate(result.stdout, config.max_output_bytes),
            "stderr": _truncate(result.stderr, config.max_output_bytes // 2),
            "elapsed_seconds": round(elapsed, 2),
            "command": cmd_list,
        }

        if result.stdout and len(result.stdout) > config.max_output_bytes:
            response["stdout_truncated"] = True
            response["stdout_total_bytes"] = len(result.stdout)

        if save_output and (result.stdout or result.stderr):
            _save_output(
                cmd_list, result.stdout, result.stderr,
                save_dir or (str(Path(cwd) / "extracted") if cwd else None),
                response,
            )

        return response

    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        raise TimeoutError(
            f"Command timed out after {timeout}s: {' '.join(cmd_list)}"
        )
    except FileNotFoundError:
        raise ExecutionError(f"Binary not found: {cmd_list[0]}")
    except PermissionError:
        raise ExecutionError(f"Permission denied: {cmd_list[0]}")


def _truncate(text: str, max_bytes: int) -> str:
    """Truncate text to max_bytes."""
    if len(text) <= max_bytes:
        return text
    return text[:max_bytes] + f"\n... [truncated at {max_bytes} bytes]"


def _save_output(
    cmd_list: list[str],
    stdout: str,
    stderr: str,
    save_dir: str | None,
    response: dict,
) -> None:
    """Save stdout/stderr to files with SHA-256 hashes."""
    if not save_dir:
        return

    out_dir = Path(save_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_cmd = "".join(c if c.isalnum() or c in "-_" else "_" for c in cmd_list[0])[:40]
    prefix = f"{ts}_{safe_cmd}"

    if stdout:
        stdout_path = out_dir / f"{prefix}_stdout.txt"
        stdout_bytes = stdout.encode("utf-8")
        stdout_path.write_bytes(stdout_bytes)
        response["output_file"] = str(stdout_path)
        response["output_sha256"] = hashlib.sha256(stdout_bytes).hexdigest()

    if stderr:
        stderr_path = out_dir / f"{prefix}_stderr.txt"
        stderr_bytes = stderr.encode("utf-8")
        stderr_path.write_bytes(stderr_bytes)
        response["stderr_file"] = str(stderr_path)
        response["stderr_sha256"] = hashlib.sha256(stderr_bytes).hexdigest()
