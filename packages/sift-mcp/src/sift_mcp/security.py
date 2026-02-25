"""Security utilities — argument sanitization, binary validation, path validation."""

from __future__ import annotations

import os
import re
from pathlib import Path

from sift_mcp.catalog import load_security_policy

_DANGEROUS_PATTERNS = [";", "&&", "||", "`", "$(", "${"]


def _get_policy() -> dict:
    """Lazy-load security policy from YAML catalog."""
    return load_security_policy()


# awk can execute arbitrary commands via language syntax (not flags).
# Scan program text for dangerous constructs.
_AWK_DANGEROUS_RE = re.compile(
    r"system\s*\(|getline|\".*\||\|.*\"|>\s*\"|>>\s*\"", re.IGNORECASE
)

# Tools whose positional args are program text and need content scanning
_PROGRAM_TEXT_TOOLS = {"awk", "gawk", "mawk", "nawk"}


def sanitize_extra_args(extra_args: list[str], tool_name: str = "") -> list[str]:
    """Validate extra_args to block dangerous flags and shell metacharacters.

    Raises ValueError if a dangerous flag or pattern is detected.
    """
    if not extra_args:
        return []

    policy = _get_policy()
    tool_allowed = policy["tool_allowed_flags"].get(tool_name, set())
    tool_blocked = policy["tool_blocked_flags"].get(tool_name, set())

    sanitized = []
    for arg in extra_args:
        if not isinstance(arg, str):
            raise ValueError(f"Non-string argument in extra_args: {type(arg).__name__}")
        flag = arg.lower().split("=")[0]
        if flag in tool_blocked:
            raise ValueError(f"Blocked dangerous flag '{arg}' for {tool_name}")
        if flag in policy["dangerous_flags"] and flag not in tool_allowed:
            raise ValueError(
                f"Blocked dangerous flag '{arg}' in extra_args for {tool_name}"
            )
        for pattern in _DANGEROUS_PATTERNS:
            if pattern in arg:
                raise ValueError(
                    f"Blocked shell metacharacter in extra_args for {tool_name}"
                )
        sanitized.append(arg)

    # Scan awk program text for dangerous constructs (system(), getline, pipes)
    if tool_name in _PROGRAM_TEXT_TOOLS:
        for arg in sanitized:
            if arg.startswith("-"):
                continue  # skip flags
            if _AWK_DANGEROUS_RE.search(arg):
                raise ValueError(
                    f"Blocked dangerous awk construct in program text for {tool_name}: "
                    f"system(), getline, and pipe operators are not allowed"
                )

    return sanitized


# Directories where rm is blocked (evidence storage, case data)
_RM_PROTECTED_DIRS = (
    "/cases",
    "/evidence",
)


def is_denied(binary_name: str) -> bool:
    """Check if a binary is on the hard denylist."""
    return binary_name.lower() in _get_policy()["denied_binaries"]


def validate_rm_targets(args: list[str]) -> None:
    """Block rm from targeting evidence storage directories.

    rm is allowed for general cleanup but blocked inside evidence
    storage locations. Also blocks rm -rf / patterns.
    """
    path_args = [a for a in args if not a.startswith("-")]
    for arg in path_args:
        resolved = str(Path(arg).resolve())
        if resolved == "/":
            raise ValueError("Blocked: rm targeting filesystem root")
        # Block evidence storage directories
        for protected in _RM_PROTECTED_DIRS:
            if resolved == protected or resolved.startswith(protected + "/"):
                raise ValueError(
                    f"Blocked: rm targeting protected evidence directory '{protected}'"
                )
        case_dir = os.environ.get("AIIR_CASE_DIR", "")
        if case_dir:
            case_resolved = str(Path(case_dir).resolve())
            if resolved == case_resolved or resolved.startswith(case_resolved + "/"):
                raise ValueError("Blocked: rm targeting case evidence directory")


_BLOCKED_DIRECTORIES = (
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    os.path.expanduser("~/.aiir"),
)


def get_output_flags() -> frozenset:
    """Return the set of flags that take output path values."""
    return _get_policy()["output_flags"]


# Directories blocked for output (superset of _BLOCKED_DIRECTORIES)
_OUTPUT_BLOCKED_DIRECTORIES = _BLOCKED_DIRECTORIES + (
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/var",
    "/home",
)


def validate_output_path(path: str) -> str:
    """Validate that an output path is safe to write to.

    Stricter than validate_input_path. When AIIR_CASE_DIR is set, the
    output path must be inside the case directory. When not set, only
    /tmp and the current working directory are allowed.

    Case-dir containment is checked first so that case directories
    under /home are allowed.
    """
    resolved = str(Path(path).resolve())

    # Case-dir containment: if inside case dir, it's allowed
    case_dir = os.environ.get("AIIR_CASE_DIR", "")
    if case_dir:
        case_resolved = str(Path(case_dir).resolve())
        if resolved == case_resolved or resolved.startswith(case_resolved + "/"):
            return resolved
        raise ValueError(
            f"Output path '{path}' resolves to '{resolved}' which is "
            f"outside the case directory '{case_resolved}'"
        )

    # No case dir: allow /tmp and cwd before checking blocked dirs
    if resolved.startswith("/tmp/") or resolved == "/tmp":
        return resolved
    cwd = str(Path.cwd().resolve())
    if resolved == cwd or resolved.startswith(cwd + "/"):
        return resolved

    # Block system directories
    for blocked in _OUTPUT_BLOCKED_DIRECTORIES:
        if resolved == blocked or resolved.startswith(blocked + "/"):
            raise ValueError(
                f"Output denied: path '{path}' resolves to '{resolved}' "
                f"which is inside blocked directory '{blocked}'"
            )

    raise ValueError(
        f"Output denied: path '{path}' resolves to '{resolved}'. "
        f"Without an active case, output is only allowed in /tmp or "
        f"the current working directory"
    )


def validate_input_path(path: str) -> str:
    """Validate that an input file path is not in a blocked system directory.

    Resolves symlinks, then checks against a blocklist of sensitive system
    directories. Also parses flag=value arguments and validates the value
    portion as a path. Raises ValueError if the resolved path falls within
    a blocked directory. Returns the resolved path string if valid.
    """
    # Handle flag=value arguments: validate the value portion as a path
    if "=" in path and path.startswith("-"):
        value = path.split("=", 1)[1]
        if value and (value.startswith("/") or value.startswith("..") or "/" in value):
            return validate_input_path(value)
        return path

    resolved = str(Path(path).resolve())
    for blocked in _BLOCKED_DIRECTORIES:
        if resolved == blocked or resolved.startswith(blocked + "/"):
            raise ValueError(
                f"Access denied: path '{path}' resolves to '{resolved}' "
                f"which is inside blocked system directory '{blocked}'"
            )
    return resolved
