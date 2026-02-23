"""Generic run_command: denylist-protected execution of forensic tools."""

from __future__ import annotations

from sift_mcp.catalog import get_tool_def
from sift_mcp.environment import find_binary
from sift_mcp.executor import execute
from sift_mcp.exceptions import DeniedBinaryError, ExecutionError
from sift_mcp.security import (
    is_denied,
    sanitize_extra_args,
    validate_input_path,
    validate_rm_targets,
)


def run_command(
    command: list[str],
    *,
    purpose: str = "",
    timeout: int | None = None,
    save_output: bool = False,
    save_dir: str | None = None,
    cwd: str | None = None,
) -> dict:
    """Execute a command if its binary is not on the denylist.

    Args:
        command: Command as list of strings.
        purpose: Reason for running (audit trail).
        timeout: Override timeout.
        save_output: Save stdout/stderr to files.
        save_dir: Directory for saved output.
        cwd: Working directory.

    Raises:
        DeniedBinaryError: Binary is on the hard denylist.
        ExecutionError: Binary not found on system.
    """
    if not command:
        raise ValueError("Empty command")

    binary = command[0].split("/")[-1]  # Strip path prefix

    # Denylist check — hard block on catastrophic binaries
    if is_denied(binary):
        raise DeniedBinaryError(
            f"Binary '{binary}' is blocked (system-destructive operation). "
            f"This restriction cannot be overridden."
        )

    # rm-specific: allow execution but protect evidence directories
    if binary == "rm":
        validate_rm_targets(command[1:])

    # Validate any arguments that look like file paths
    for arg in command[1:]:
        # Check flag=value arguments for path values
        if "=" in arg and arg.startswith("-"):
            value = arg.split("=", 1)[1]
            if value and (value.startswith("/") or value.startswith("..") or "/" in value):
                validate_input_path(value)
            continue
        if arg.startswith("--"):
            continue
        if arg.startswith("/") or arg.startswith("..") or "/" in arg:
            validate_input_path(arg)

    # Resolve binary via find_binary to prevent absolute path bypass
    resolved = find_binary(binary)
    if not resolved:
        raise ExecutionError(
            f"Binary '{binary}' not found on this system."
        )
    command = [resolved] + command[1:]

    # Sanitize any args after the binary
    sanitize_extra_args(command[1:], tool_name=binary)

    return execute(
        command,
        timeout=timeout,
        cwd=cwd,
        save_output=save_output,
        save_dir=save_dir,
    )
