"""Subprocess executor — shell=False, timeout, output capture.

All forensic tool execution goes through this module.
"""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sift_mcp.config import get_config
from sift_mcp.exceptions import ExecutionError, ExecutionTimeoutError

logger = logging.getLogger(__name__)


def _read_pipe(pipe, chunks: list[bytes], limit: int, total: list[int]) -> None:
    """Read from a pipe incrementally, respecting byte limit."""
    while True:
        remaining = limit - total[0]
        if remaining <= 0:
            break
        data = pipe.read(min(65536, remaining))
        if not data:
            break
        chunks.append(data)
        total[0] += len(data)


def execute(
    cmd_list: list[str],
    *,
    timeout: int | None = None,
    cwd: str | None = None,
    save_output: bool = False,
    save_dir: str | None = None,
) -> dict[str, Any]:
    """Execute a command as a subprocess (shell=False).

    Uses Popen with incremental pipe reading to enforce max_output_bytes
    at capture time, preventing OOM from runaway processes.

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
    max_bytes = config.max_output_bytes

    start = time.monotonic()
    truncated = False
    try:
        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
        )

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        total = [0]  # shared mutable counter across both pipes

        # Read both pipes in threads to avoid deadlock and allow
        # proc.wait() in the main thread to enforce the timeout.
        stdout_thread = threading.Thread(
            target=_read_pipe,
            args=(proc.stdout, stdout_chunks, max_bytes, total),
        )
        stderr_thread = threading.Thread(
            target=_read_pipe,
            args=(proc.stderr, stderr_chunks, max_bytes, total),
        )
        stdout_thread.start()
        stderr_thread.start()

        # Poll for completion, checking byte limit periodically
        deadline = start + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                proc.wait(timeout=5)
                raise subprocess.TimeoutExpired(cmd_list, timeout)
            if total[0] >= max_bytes:
                truncated = True
                proc.kill()
                proc.wait(timeout=5)
                break
            try:
                proc.wait(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                continue

        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

        # Check truncation after threads finish (process may have
        # exited before the polling loop detected the byte limit)
        if total[0] >= max_bytes:
            truncated = True

        elapsed = time.monotonic() - start

        stdout_raw = b"".join(stdout_chunks)
        stderr_raw = b"".join(stderr_chunks)
        stdout = stdout_raw.decode("utf-8", errors="replace")
        stderr = stderr_raw.decode("utf-8", errors="replace")
        stdout_byte_count = len(stdout_raw)

        response: dict[str, Any] = {
            "exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": _truncate(stderr, config.max_output_bytes // 10),
            "elapsed_seconds": round(elapsed, 2),
            "command": cmd_list,
            "stdout_total_bytes": stdout_byte_count,
        }
        if truncated:
            response["truncated"] = True

        # Threshold-based save: auto-save when output exceeds response budget
        case_dir = os.environ.get("AIIR_CASE_DIR", "")
        exceeds_budget = stdout_byte_count > config.response_byte_budget

        if exceeds_budget and case_dir:
            _save_output(
                cmd_list,
                stdout,
                stderr,
                save_dir or os.path.join(case_dir, "extractions"),
                response,
            )
        elif save_output and (stdout or stderr):
            _save_output(
                cmd_list,
                stdout,
                stderr,
                save_dir or (str(Path(cwd) / "extracted") if cwd else None),
                response,
            )

        return response

    except subprocess.TimeoutExpired as exc:
        raise ExecutionTimeoutError(
            f"Command timed out after {timeout}s: {' '.join(cmd_list)}"
        ) from exc
    except FileNotFoundError as exc:
        raise ExecutionError(f"Binary not found: {cmd_list[0]}") from exc
    except PermissionError as exc:
        raise ExecutionError(f"Permission denied: {cmd_list[0]}") from exc
    except OSError as e:
        raise ExecutionError(f"OS error executing {cmd_list[0]}: {e}") from e


def _truncate(text: str, max_chars: int) -> str:
    """Truncate text to max_chars."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... [truncated at {max_chars} chars]"


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

    try:
        out_dir = Path(save_dir).resolve()
    except OSError as e:
        logger.warning("Cannot resolve save_dir path %s: %s", save_dir, e)
        return

    # Block writes to system directories
    _blocked_prefixes = (
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/boot",
        "/proc",
        "/sys",
        "/dev",
    )
    if any(
        str(out_dir) == p or str(out_dir).startswith(p + "/") for p in _blocked_prefixes
    ):
        raise ExecutionError(f"Refusing to write output to system directory: {out_dir}")

    # When AIIR_CASE_DIR is set, restrict save_dir to within the case directory
    case_dir = os.environ.get("AIIR_CASE_DIR")
    if case_dir:
        try:
            case_resolved = Path(case_dir).resolve()
            out_dir.relative_to(case_resolved)
        except ValueError as exc:
            raise ExecutionError(
                f"save_dir '{out_dir}' is outside the case directory '{case_resolved}'"
            ) from exc

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("Cannot create output directory %s: %s", out_dir, e)
        return

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_cmd = "".join(c if c.isalnum() or c in "-_" else "_" for c in cmd_list[0])[:40]
    prefix = f"{ts}_{safe_cmd}"

    if stdout:
        try:
            stdout_path = out_dir / f"{prefix}_stdout.txt"
            stdout_bytes = stdout.encode("utf-8", errors="replace")
            with open(stdout_path, "wb") as f:
                f.write(stdout_bytes)
                f.flush()
                os.fsync(f.fileno())
            response["output_file"] = str(stdout_path)
            response["output_sha256"] = hashlib.sha256(stdout_bytes).hexdigest()
        except OSError as e:
            logger.warning("Failed to save stdout to %s: %s", stdout_path, e)

    if stderr:
        try:
            stderr_path = out_dir / f"{prefix}_stderr.txt"
            stderr_bytes = stderr.encode("utf-8", errors="replace")
            with open(stderr_path, "wb") as f:
                f.write(stderr_bytes)
                f.flush()
                os.fsync(f.fileno())
            response["stderr_file"] = str(stderr_path)
            response["stderr_sha256"] = hashlib.sha256(stderr_bytes).hexdigest()
        except OSError as e:
            logger.warning("Failed to save stderr to %s: %s", stderr_path, e)
