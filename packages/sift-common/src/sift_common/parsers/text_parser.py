"""Text output parser — truncation, format hints, line extraction."""

from __future__ import annotations


def parse_text(stdout: str, *, max_lines: int = 50000, byte_budget: int = 0) -> dict:
    """Parse plain text output with truncation.

    Args:
        stdout: Raw text output.
        max_lines: Maximum lines to return (secondary safety limit).
        byte_budget: If > 0, fill complete lines until budget exhausted.
    """
    all_lines = stdout.split("\n")
    total_lines = len(all_lines)

    preview = []
    used_bytes = 0
    for line in all_lines:
        if max_lines and len(preview) >= max_lines:
            break
        if byte_budget:
            line_bytes = len(line.encode("utf-8")) + 1  # +1 for newline
            if used_bytes + line_bytes > byte_budget and preview:
                break
            used_bytes += line_bytes
        preview.append(line)

    return {
        "lines": preview,
        "total_lines": total_lines,
        "preview_lines": len(preview),
        "preview_bytes": used_bytes,
        "truncated": total_lines > len(preview),
    }


def extract_lines(stdout: str, *, start: int = 0, count: int = 50) -> list[str]:
    """Extract a range of lines from output."""
    lines = stdout.split("\n")
    return lines[start : start + count]
