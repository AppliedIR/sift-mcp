"""CSV output parser — Zimmerman tools produce CSV, we convert to JSON-serializable dicts."""

from __future__ import annotations

import csv
import io
from typing import Any


def parse_csv(text: str, *, max_rows: int = 1000) -> dict[str, Any]:
    """Parse CSV text into a list of row dicts.

    Returns:
        {"rows": [...], "total_rows": int, "truncated": bool, "columns": [...]}
    """
    if not text.strip():
        return {"rows": [], "total_rows": 0, "truncated": False, "columns": []}

    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for i, row in enumerate(reader):
        if i >= max_rows:
            break
        rows.append(dict(row))

    # Count remaining
    total = len(rows)
    if len(rows) == max_rows:
        for _ in reader:
            total += 1

    columns = list(rows[0].keys()) if rows else (reader.fieldnames or [])

    return {
        "rows": rows,
        "total_rows": total,
        "truncated": total > max_rows,
        "columns": list(columns),
    }


def parse_csv_file(file_path: str, *, max_rows: int = 1000) -> dict[str, Any]:
    """Parse a CSV file on disk."""
    with open(file_path, "r", encoding="utf-8-sig") as f:
        text = f.read()
    return parse_csv(text, max_rows=max_rows)
