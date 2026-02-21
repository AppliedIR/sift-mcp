"""JSON output parser — Volatility, Hayabusa, and other JSON-producing tools."""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_json(text: str, *, max_entries: int = 1000) -> dict[str, Any]:
    """Parse JSON text output.

    Handles both single objects and arrays. For JSONL (one object per line),
    use parse_jsonl().

    Returns:
        {"data": parsed, "total_entries": int, "truncated": bool}
    """
    if not text.strip():
        return {"data": None, "total_entries": 0, "truncated": False}

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning("JSON parse error at position %d: %s", e.pos or 0, e)
        return {
            "data": None,
            "total_entries": 0,
            "truncated": False,
            "parse_error": f"Invalid JSON: {e}",
        }

    if isinstance(parsed, list):
        total = len(parsed)
        truncated = total > max_entries
        return {
            "data": parsed[:max_entries],
            "total_entries": total,
            "truncated": truncated,
        }

    return {"data": parsed, "total_entries": 1, "truncated": False}


def parse_jsonl(text: str, *, max_entries: int = 1000) -> dict[str, Any]:
    """Parse JSONL (newline-delimited JSON) output.

    Returns:
        {"data": [...], "total_entries": int, "truncated": bool}
    """
    entries = []
    total = 0
    for line in text.strip().split("\n"):
        if not line.strip():
            continue
        total += 1
        if total <= max_entries:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                entries.append({"_raw": line})

    return {
        "data": entries,
        "total_entries": total,
        "truncated": total > max_entries,
    }
