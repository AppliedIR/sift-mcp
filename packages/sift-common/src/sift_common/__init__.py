"""Shared utilities for SIFT-platform MCP servers."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

# The system's folders and Valhuntir's own keys: never read as evidence, even
# through a registered link (sift-mcp blocks them for every tool's input too)
SYSTEM_DIRS = ("/etc", "/proc", "/sys", "/dev", "/boot", "/var/lib/vhir")

_transport_isolated = False


def isolate_stdio_transport() -> None:
    """Keep a stdio server's MCP channel away from its child processes.

    The channel arrives on fd 0 and fd 1, which every child inherits unless
    its spawn site says otherwise; a child that reads stdin would read the
    client's requests. This moves the channel onto new descriptors that are
    closed on exec, rebinds sys.stdin and sys.stdout to them (the MCP stdio
    transport reads and writes those), and leaves /dev/null on fd 0 and
    stderr on fd 1. A spawner can also leave inheritable copies of the channel
    at higher descriptors (uvloop's does); those are marked closed on exec and
    left open. Call it first in the server's entry point. A second call
    changes nothing.
    """
    global _transport_isolated
    if _transport_isolated:
        return
    # The channel is the pipe or socket on fd 0 and fd 1, known only now:
    # afterwards they hold /dev/null and stderr.
    channel = set()
    for fd in (0, 1):
        st = os.fstat(fd)
        if stat.S_ISSOCK(st.st_mode) or stat.S_ISFIFO(st.st_mode):
            channel.add((st.st_dev, st.st_ino))
    sys.stdout.flush()
    # os.dup makes descriptors that are not inherited (closed on exec).
    transport_in = os.dup(0)
    transport_out = os.dup(1)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    os.dup2(2, 1)
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = open(transport_in, encoding=old_in.encoding, errors=old_in.errors)
    sys.stdout = open(
        transport_out, "w", encoding=old_out.encoding, errors=old_out.errors
    )
    # The copies share the channel's open file: closing one, or changing
    # anything but its close-on-exec flag, would change the channel itself.
    for fd in _open_descriptors() if channel else ():
        if fd < 3 or fd in (transport_in, transport_out):
            continue
        try:
            st = os.fstat(fd)
        except OSError:
            continue
        if (st.st_dev, st.st_ino) in channel:
            os.set_inheritable(fd, False)
    _transport_isolated = True


def _open_descriptors():
    """The descriptors this process has open, from Linux's listing; elsewhere,
    or failing it, every number below the soft limit on open files. Other
    systems' /dev/fd can list only 0-2 (FreeBSD's, without fdescfs)."""
    if sys.platform.startswith("linux"):
        try:
            return [int(name) for name in os.listdir("/proc/self/fd")]
        except OSError:
            pass
    import resource

    soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    if soft == resource.RLIM_INFINITY:
        soft = os.sysconf("SC_OPEN_MAX")
    return range(soft)


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
