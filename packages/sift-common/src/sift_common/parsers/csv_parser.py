"""CSV output parser — Zimmerman tools produce CSV, we convert to JSON-serializable dicts."""

from __future__ import annotations

import csv
import io
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def parse_csv(
    text: str, *, max_rows: int = 10000, byte_budget: int = 0
) -> dict[str, Any]:
    """Parse CSV text into a list of row dicts.

    Args:
        text: Raw CSV text.
        max_rows: Maximum rows to return (secondary safety limit).
        byte_budget: If > 0, fill complete rows until budget exhausted.

    Returns:
        {"rows": [...], "total_rows": int, "truncated": bool, "columns": [...]}
    """
    if not text.strip():
        return {
            "rows": [],
            "total_rows": 0,
            "truncated": False,
            "columns": [],
            "preview_rows": 0,
            "preview_bytes": 0,
        }

    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        logger.warning("CSV has no header row; returning empty result")
        return {
            "rows": [],
            "total_rows": 0,
            "truncated": False,
            "columns": [],
            "preview_rows": 0,
            "preview_bytes": 0,
        }

    rows = []
    used_bytes = 0
    budget_hit = False
    try:
        for row in reader:
            if max_rows and len(rows) >= max_rows:
                break
            row_dict = dict(row)
            if byte_budget:
                row_bytes = (
                    sum(len(v.encode("utf-8")) for v in row_dict.values())
                    + len(row_dict) * 4
                )
                if used_bytes + row_bytes > byte_budget and rows:
                    budget_hit = True
                    break
                used_bytes += row_bytes
            rows.append(row_dict)
    except csv.Error as e:
        logger.warning("CSV parse error at row %d: %s", len(rows), e)
        if not rows:
            return {
                "rows": [],
                "total_rows": 0,
                "truncated": False,
                "columns": list(reader.fieldnames or []),
                "preview_rows": 0,
                "preview_bytes": used_bytes,
                "parse_error": str(e),
            }

    # Count remaining without creating dict objects
    total = len(rows)
    if budget_hit or len(rows) == max_rows:
        try:
            remaining = sum(1 for _ in reader)
            total += remaining
        except csv.Error as e:
            logger.warning("CSV error while counting remaining rows: %s", e)

    columns = list(rows[0].keys()) if rows else (reader.fieldnames or [])

    return {
        "rows": rows,
        "total_rows": total,
        "preview_rows": len(rows),
        "preview_bytes": used_bytes,
        "truncated": total > len(rows),
        "columns": list(columns),
    }


_MAX_CSV_BYTES = 50_000_000  # 50MB


def parse_csv_file(file_path: str, *, max_rows: int = 1000) -> dict[str, Any]:
    """Parse a CSV file on disk."""
    try:
        file_size = Path(file_path).stat().st_size
        if file_size > _MAX_CSV_BYTES:
            return {
                "error": f"CSV file too large ({file_size:,} bytes, max 50MB)",
                "rows": [],
                "total_rows": 0,
            }
        with open(file_path, encoding="utf-8-sig") as f:
            text = f.read()
    except OSError as e:
        logger.warning("Failed to read CSV file %s: %s", file_path, e)
        return {
            "rows": [],
            "total_rows": 0,
            "truncated": False,
            "columns": [],
            "parse_error": f"Failed to read file: {e}",
        }
    return parse_csv(text, max_rows=max_rows)
