"""Security utilities — argument sanitization, binary validation."""

from __future__ import annotations

from sift_mcp.catalog import is_in_catalog

# Flags that could be abused for data exfiltration or code execution
_DANGEROUS_FLAGS = {
    "-e", "--exec", "--command", "-enc", "-encodedcommand",
    "--script", "--invoke",
}

_DANGEROUS_PATTERNS = [";", "&&", "||", "`", "$(", "${"]


def sanitize_extra_args(extra_args: list[str], tool_name: str = "") -> list[str]:
    """Validate extra_args to block dangerous flags and shell metacharacters.

    Raises ValueError if a dangerous flag or pattern is detected.
    """
    if not extra_args:
        return []

    sanitized = []
    for arg in extra_args:
        flag = arg.lower().split("=")[0]
        if flag in _DANGEROUS_FLAGS:
            raise ValueError(
                f"Blocked dangerous flag '{arg}' in extra_args for {tool_name}"
            )
        for pattern in _DANGEROUS_PATTERNS:
            if pattern in arg:
                raise ValueError(
                    f"Blocked shell metacharacter in extra_args for {tool_name}"
                )
        sanitized.append(arg)
    return sanitized


def verify_catalog(binary_name: str) -> None:
    """Verify a binary is in the approved catalog. Raises ValueError if not."""
    name = binary_name.split("/")[-1]
    if not is_in_catalog(name):
        raise ValueError(f"Binary '{name}' is not in the approved catalog")
