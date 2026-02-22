"""CSV output parser — Zimmerman tools produce CSV, we convert to JSON-serializable dicts."""

from __future__ import annotations

import csv
import io
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def parse_csv(text: str, *, max_rows: int = 1000) -> dict[str, Any]:
    """Parse CSV text into a list of row dicts.

    Returns:
        {"rows": [...], "total_rows": int, "truncated": bool, "columns": [...]}
    """
    if not text.strip():
        return {"rows": [], "total_rows": 0, "truncated": False, "columns": []}

    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        logger.warning("CSV has no header row; returning empty result")
        return {"rows": [], "total_rows": 0, "truncated": False, "columns": []}

    rows = []
    try:
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            rows.append(dict(row))
    except csv.Error as e:
        logger.warning("CSV parse error at row %d: %s", len(rows), e)
        # Return whatever rows we parsed successfully before the error
        if not rows:
            return {
                "rows": [],
                "total_rows": 0,
                "truncated": False,
                "columns": list(reader.fieldnames or []),
                "parse_error": str(e),
            }

    # Count remaining without creating dict objects
    total = len(rows)
    if len(rows) == max_rows:
        try:
            remaining = sum(1 for _ in reader)
            total += remaining
        except csv.Error as e:
            logger.warning("CSV error while counting remaining rows: %s", e)

    columns = list(rows[0].keys()) if rows else (reader.fieldnames or [])

    return {
        "rows": rows,
        "total_rows": total,
        "truncated": total > max_rows,
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
        with open(file_path, "r", encoding="utf-8-sig") as f:
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
