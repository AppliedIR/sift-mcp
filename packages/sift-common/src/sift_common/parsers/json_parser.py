"""JSON output parser — Volatility, Hayabusa, and other JSON-producing tools."""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_json(
    text: str, *, max_entries: int = 100000, byte_budget: int = 0
) -> dict[str, Any]:
    """Parse JSON text output.

    Handles both single objects and arrays. For JSONL (one object per line),
    use parse_jsonl().

    Args:
        text: Raw JSON text.
        max_entries: Maximum entries for arrays (secondary safety limit).
        byte_budget: If > 0, fill complete entries until budget exhausted.

    Returns:
        {"data": parsed, "total_entries": int, "truncated": bool}
    """
    if not text.strip():
        return {
            "data": None,
            "total_entries": 0,
            "truncated": False,
            "preview_entries": 0,
            "preview_bytes": 0,
        }

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning("JSON parse error at position %d: %s", e.pos or 0, e)
        return {
            "data": None,
            "total_entries": 0,
            "truncated": False,
            "preview_entries": 0,
            "preview_bytes": 0,
            "parse_error": f"Invalid JSON: {e}",
        }

    if isinstance(parsed, list):
        total = len(parsed)
        preview = []
        used_bytes = 0
        for entry in parsed:
            if max_entries and len(preview) >= max_entries:
                break
            if byte_budget:
                entry_bytes = len(json.dumps(entry).encode("utf-8"))
                if used_bytes + entry_bytes > byte_budget and preview:
                    break
                used_bytes += entry_bytes
            preview.append(entry)
        return {
            "data": preview,
            "total_entries": total,
            "preview_entries": len(preview),
            "preview_bytes": used_bytes,
            "truncated": total > len(preview),
        }

    return {
        "data": parsed,
        "total_entries": 1,
        "truncated": False,
        "preview_entries": 1,
        "preview_bytes": 0,
    }


def parse_jsonl(
    text: str, *, max_entries: int = 100000, byte_budget: int = 0
) -> dict[str, Any]:
    """Parse JSONL (newline-delimited JSON) output.

    Args:
        text: Raw JSONL text.
        max_entries: Maximum entries to return (secondary safety limit).
        byte_budget: If > 0, fill complete entries until budget exhausted.

    Returns:
        {"data": [...], "total_entries": int, "truncated": bool}
    """
    entries = []
    total = 0
    used_bytes = 0
    budget_hit = False
    for line in text.strip().split("\n"):
        if not line.strip():
            continue
        total += 1
        if budget_hit or (max_entries and len(entries) >= max_entries):
            continue  # keep counting total
        if byte_budget:
            line_bytes = len(line.encode("utf-8"))
            if used_bytes + line_bytes > byte_budget and entries:
                budget_hit = True
                continue
            used_bytes += line_bytes
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            entries.append({"_raw": line})

    return {
        "data": entries,
        "total_entries": total,
        "preview_entries": len(entries),
        "preview_bytes": used_bytes,
        "truncated": total > len(entries),
    }
