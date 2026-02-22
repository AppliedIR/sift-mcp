"""Security utilities — argument sanitization, binary validation, path validation."""

from __future__ import annotations

import re
from pathlib import Path

from sift_mcp.catalog import is_in_catalog

# Flags that could be abused for data exfiltration or code execution
_DANGEROUS_FLAGS = {
    "-e", "--exec", "--command", "-enc", "-encodedcommand",
    "--script", "--invoke",
}

_DANGEROUS_PATTERNS = [";", "&&", "||", "`", "$(", "${"]

# Per-tool overrides: flags that are dangerous globally but safe for specific tools
_TOOL_ALLOWED_FLAGS: dict[str, set[str]] = {
    "run_bulk_extractor": {"-e", "-x"},  # -e enables scanner, -x disables
}

# Per-tool blocked flags: flags that are safe globally but dangerous for specific tools
_TOOL_BLOCKED_FLAGS: dict[str, set[str]] = {
    "find": {"-exec", "-execdir", "-delete", "-fls", "-fprint", "-fprint0", "-fprintf"},
    "sed": {"-i", "--in-place"},               # in-place evidence modification
    "tar": {"-x", "--extract", "--get", "-c", "--create", "--delete", "--append"},
    "unzip": {"-o", "-n"},                     # block overwrite modes; list/test only
}

# awk can execute arbitrary commands via language syntax (not flags).
# Scan program text for dangerous constructs.
_AWK_DANGEROUS_RE = re.compile(r"system\s*\(|getline|\".*\||\|.*\"", re.IGNORECASE)

# Tools whose positional args are program text and need content scanning
_PROGRAM_TEXT_TOOLS = {"awk", "gawk", "mawk", "nawk"}


def sanitize_extra_args(extra_args: list[str], tool_name: str = "") -> list[str]:
    """Validate extra_args to block dangerous flags and shell metacharacters.

    Raises ValueError if a dangerous flag or pattern is detected.
    """
    if not extra_args:
        return []

    tool_allowed = _TOOL_ALLOWED_FLAGS.get(tool_name, set())
    tool_blocked = _TOOL_BLOCKED_FLAGS.get(tool_name, set())

    sanitized = []
    for arg in extra_args:
        if not isinstance(arg, str):
            raise ValueError(f"Non-string argument in extra_args: {type(arg).__name__}")
        flag = arg.lower().split("=")[0]
        if flag in tool_blocked:
            raise ValueError(
                f"Blocked dangerous flag '{arg}' for {tool_name}"
            )
        if flag in _DANGEROUS_FLAGS and flag not in tool_allowed:
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


_BLOCKED_DIRECTORIES = (
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/var/run",
    "/var/log",
    "/proc",
    "/sys",
    "/dev",
    "/root",
    "/home",
    "/tmp",
    "/boot",
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


def verify_catalog(binary_name: str) -> None:
    """Verify a binary is in the approved catalog. Raises ValueError if not."""
    name = binary_name.split("/")[-1]
    if not is_in_catalog(name):
        raise ValueError(f"Binary '{name}' is not in the approved catalog")
