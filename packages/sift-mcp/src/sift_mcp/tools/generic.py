"""Generic run_command: denylist-protected execution of forensic tools."""

from __future__ import annotations

from sift_mcp.catalog import get_tool_def
from sift_mcp.config import get_config
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import DeniedBinaryError, ExecutionError
from sift_mcp.executor import execute
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
            if value and (
                value.startswith("/") or value.startswith("..") or "/" in value
            ):
                validate_input_path(value)
            continue
        if arg.startswith("-") and "=" not in arg:
            continue
        if arg.startswith("/") or arg.startswith("..") or "/" in arg:
            validate_input_path(arg)

    # Resolve binary via find_binary to prevent absolute path bypass
    resolved = find_binary(binary)
    if not resolved:
        raise ExecutionError(f"Binary '{binary}' not found on this system.")
    command = [resolved] + command[1:]

    # Sanitize any args after the binary
    sanitize_extra_args(command[1:], tool_name=binary)

    exec_result = execute(
        command,
        timeout=timeout,
        cwd=cwd,
        save_output=save_output,
        save_dir=save_dir,
    )

    # Parse output based on catalog format when output exceeds byte budget
    cfg = get_config()
    stdout = exec_result.get("stdout", "")
    stdout_bytes = exec_result.get("stdout_total_bytes", len(stdout.encode("utf-8")))

    td = get_tool_def(binary)
    output_format = td.output_format if td else "text"

    # Small output — return as-is (no parsing overhead)
    if stdout_bytes <= cfg.response_byte_budget:
        exec_result["_output_format"] = output_format
        return exec_result

    # Large output — parse with byte budget
    from sift_common.parsers import csv_parser, json_parser, text_parser

    if output_format == "csv":
        parsed = csv_parser.parse_csv(stdout, byte_budget=cfg.response_byte_budget)
        exec_result["_parsed"] = parsed
        exec_result["_output_format"] = "parsed_csv"
    elif output_format == "json":
        parsed = json_parser.parse_json(stdout, byte_budget=cfg.response_byte_budget)
        if parsed.get("parse_error"):
            parsed = json_parser.parse_jsonl(
                stdout, byte_budget=cfg.response_byte_budget
            )
        exec_result["_parsed"] = parsed
        exec_result["_output_format"] = "parsed_json"
    else:
        parsed = text_parser.parse_text(stdout, byte_budget=cfg.response_byte_budget)
        exec_result["_parsed"] = parsed
        exec_result["_output_format"] = "parsed_text"

    # Replace raw stdout with None — full output is on disk if saved
    exec_result["stdout"] = None

    return exec_result
