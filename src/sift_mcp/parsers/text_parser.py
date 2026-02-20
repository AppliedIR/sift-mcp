"""Text output parser — truncation, format hints, line extraction."""

from __future__ import annotations


def parse_text(stdout: str, *, max_lines: int = 500) -> dict:
    """Parse plain text output with truncation."""
    lines = stdout.split("\n")
    truncated = len(lines) > max_lines

    return {
        "lines": lines[:max_lines],
        "total_lines": len(lines),
        "truncated": truncated,
    }


def extract_lines(stdout: str, *, start: int = 0, count: int = 50) -> list[str]:
    """Extract a range of lines from output."""
    lines = stdout.split("\n")
    return lines[start:start + count]
