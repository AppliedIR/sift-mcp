"""Shared utilities for SIFT-platform MCP servers."""

from __future__ import annotations

import asyncio
import functools
import inspect
import os
from pathlib import Path

# The system's folders and Valhuntir's own keys: never read as evidence, even
# through a registered link (sift-mcp blocks them for every tool's input too)
SYSTEM_DIRS = ("/etc", "/proc", "/sys", "/dev", "/boot", "/var/lib/vhir")


def resolve_case_dir() -> str:
    """Resolve the active case directory.

    Resolution order: VHIR_CASE_DIR env var → ~/.vhir/active_case file → "".
    VHIR_CASE_DIR must be a directory containing CASE.yaml to be valid.
    If set but invalid, falls through to active_case.
    """
    case_dir = os.environ.get("VHIR_CASE_DIR", "").strip()
    if case_dir:
        p = Path(case_dir)
        if p.is_dir() and (p / "CASE.yaml").exists():
            return case_dir
        # Set but invalid — fall through to active_case
    active_file = Path.home() / ".vhir" / "active_case"
    if active_file.is_file():
        try:
            content = active_file.read_text().strip()
        except OSError:
            return ""
        if content:
            p = Path(content)
            if p.is_dir() and (p / "CASE.yaml").exists():
                return content
    return ""


def resolve_share_path(relative_path: str) -> Path | None:
    """Resolve a share-relative extraction path to a local mount point.

    When wintools-mcp writes an extraction file, it strips the VHIR_SHARE_ROOT
    prefix to produce a share-relative path (e.g., "extractions/output.csv").
    On the SIFT side, VHIR_SHARE_ROOT points to where the same SMB share is
    mounted locally (e.g., /mnt/wintools). This function joins the two to
    produce the full local path.

    Returns None if VHIR_SHARE_ROOT is not set.
    """
    share_root = os.environ.get("VHIR_SHARE_ROOT", "")
    if not share_root:
        return None
    return Path(share_root) / relative_path


def offload(fn, limiter: asyncio.Lock | None = None):
    """A sync tool runs in a worker thread, so the server's event loop keeps
    answering pings and other calls while it runs. Under ``limiter`` its calls
    run one at a time, and the limiter is held until the thread ends: a
    cancelled caller returns at once, but a later call never overlaps the
    thread it left running. An async tool is returned as it is."""
    if inspect.iscoroutinefunction(fn):
        return fn

    def release(worker):
        if not worker.cancelled():
            worker.exception()  # retrieved here: its caller may be gone
        limiter.release()

    @functools.wraps(fn)
    async def run(*args, **kwargs):
        call = functools.partial(fn, *args, **kwargs)
        if limiter is None:
            return await asyncio.to_thread(call)
        await limiter.acquire()
        worker = asyncio.ensure_future(asyncio.to_thread(call))
        worker.add_done_callback(release)  # when the thread ends, not the caller
        return await asyncio.shield(worker)

    return run
