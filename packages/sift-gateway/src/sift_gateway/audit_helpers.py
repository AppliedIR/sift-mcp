"""Shared audit helpers for gateway proxy-side auditing."""

from __future__ import annotations

import json


def _extract_audit_id(result: list) -> str | None:
    """Extract audit_id from backend response content."""
    for item in result:
        text = getattr(item, "text", None)
        if text:
            try:
                data = json.loads(text)
                return data.get("audit_id")
            except (json.JSONDecodeError, AttributeError):
                pass
    return None


def _truncate_params(params: dict, max_len: int = 1000) -> dict:
    """Truncate large param values for audit storage."""
    truncated = {}
    for k, v in params.items():
        s = str(v)
        truncated[k] = s[:max_len] + "..." if len(s) > max_len else v
    return truncated


def _summarize_result(result: list) -> dict:
    """Extract lightweight summary from backend response."""
    for item in result:
        text = getattr(item, "text", None)
        if text:
            try:
                data = json.loads(text)
                summary = {}
                for key in ("exit_code", "success", "error", "truncated", "found"):
                    if key in data:
                        summary[key] = data[key]
                return summary
            except (json.JSONDecodeError, AttributeError):
                pass
    return {"raw_items": len(result)}
