"""Generic run_command: catalog-gated execution of any approved tool."""

from __future__ import annotations

from sift_mcp.catalog import is_in_catalog, get_tool_def
from sift_mcp.environment import find_binary
from sift_mcp.executor import execute
from sift_mcp.exceptions import ToolNotInCatalogError
from sift_mcp.security import sanitize_extra_args, validate_input_path


def run_command(
    command: list[str],
    *,
    purpose: str = "",
    timeout: int | None = None,
    save_output: bool = False,
    save_dir: str | None = None,
    cwd: str | None = None,
) -> dict:
    """Execute a command if its binary is in the approved catalog.

    Args:
        command: Command as list of strings.
        purpose: Reason for running (audit trail).
        timeout: Override timeout.
        save_output: Save stdout/stderr to files.
        save_dir: Directory for saved output.
        cwd: Working directory.

    Raises:
        ToolNotInCatalogError: Binary not in approved catalog.
    """
    if not command:
        raise ValueError("Empty command")

    binary = command[0].split("/")[-1]  # Strip path prefix
    if not is_in_catalog(binary):
        raise ToolNotInCatalogError(
            f"Binary '{binary}' is not in the approved tool catalog. "
            f"Only catalog-approved tools can be executed via sift-mcp."
        )

    # Validate any arguments that look like file paths
    for arg in command[1:]:
        if arg.startswith("--"):
            continue
        if arg.startswith("/") or arg.startswith("..") or "/" in arg:
            validate_input_path(arg)

    # Resolve binary via find_binary to prevent absolute path bypass
    resolved = find_binary(binary)
    if not resolved:
        raise ToolNotInCatalogError(
            f"Tool '{binary}' is in the catalog but not installed on this system. "
            f"Use list_missing_tools() for installation guidance."
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
