"""The triage data release's file list and per-table row counts.

One module owns what a release holds:

- ``DATABASES``: each DB file name, and whether ``download_databases`` fetches it by
  default (the registry DB is opt-in).
- ``COUNTS``: per DB, its data tables (every table ``schemas.py`` declares for it,
  minus ``sources``) and the row count of each in the last published release.
- ``LICENCE_ASSET``: the release file holding every source's licence files.

Two rules read ``COUNTS``. A downloaded DB is the release's own file, so its
tables must equal the counts exactly (``check_downloaded``). A local build must
reach each table's floor, half the release's count rounded down (``check_floors``).
Both read ``COUNTS`` when called, never a copy taken at import.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

DATABASES: dict[str, bool] = {
    "known_good.db": True,
    "context.db": True,
    "known_good_registry.db": False,
}

LICENCE_ASSET = "licenses.tar.zst"

# Counts of the published triage-db-v2026.02.25 release (its metadata.json).
COUNTS: dict[str, dict[str, int]] = {
    "known_good.db": {
        "baseline_autoruns": 72,
        "baseline_files": 2684993,
        "baseline_hashes": 8000186,
        "baseline_os": 254,
        "baseline_services": 4901,
        "baseline_tasks": 606,
    },
    "context.db": {
        "expected_processes": 57,
        "hijackable_dlls": 2286,
        "lolbins": 227,
        "protected_process_names": 29,
        "suspicious_filenames": 27,
        "suspicious_pipe_patterns": 8,
        "vulnerable_drivers": 1984,
        "windows_named_pipes": 18,
    },
    "known_good_registry.db": {
        "baseline_os": 242,
        "baseline_registry": 6098546,
    },
}


def default_databases() -> list[str]:
    """The DB file names ``download_databases`` fetches by default."""
    return [name for name, default in DATABASES.items() if default]


def floor(count: int) -> int:
    """A local build's floor for a table: half the release's count, rounded down."""
    return count // 2


def table_counts(db_path: Path) -> dict[str, int]:
    """Each data table's row count, read from the DB's own ``sqlite_master``."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        query = "SELECT name FROM sqlite_master WHERE type='table'"
        names = [
            r[0]
            for r in conn.execute(query)
            if r[0] != "sources" and not r[0].startswith("sqlite_")
        ]
        return {
            n: conn.execute(f'SELECT COUNT(*) FROM "{n}"').fetchone()[0] for n in names
        }
    finally:
        conn.close()


def _table_errors(name: str, found: dict[str, int]) -> list[str]:
    want = COUNTS.get(name)
    if want is None:
        return [f"{name}: not in the release file list"]
    errors = []
    for table in sorted(set(want) - set(found)):
        errors.append(f"{name}: table {table} is missing")
    for table in sorted(set(found) - set(want)):
        errors.append(f"{name}: table {table} is not in the release file list")
    return errors


def check_downloaded(name: str, db_path: Path) -> list[str]:
    """A downloaded DB against the release's counts: [] when every table matches."""
    try:
        found = table_counts(db_path)
    except sqlite3.Error as e:
        return [f"{name}: cannot be read: {e}"]
    errors = _table_errors(name, found)
    want = COUNTS.get(name, {})
    for table in sorted(set(want) & set(found)):
        if found[table] != want[table]:
            errors.append(
                f"{name}: {table} has {found[table]} rows, the release has "
                f"{want[table]}"
            )
    return errors


def check_floors(name: str, db_path: Path) -> list[str]:
    """A locally built DB against the floors: [] when every table reaches its floor."""
    try:
        found = table_counts(db_path)
    except sqlite3.Error as e:
        return [f"{name}: cannot be read: {e}"]
    errors = _table_errors(name, found)
    want = COUNTS.get(name, {})
    for table in sorted(set(want) & set(found)):
        need = floor(want[table])
        if found[table] < need:
            errors.append(
                f"{name}: {table} has {found[table]} rows, under its floor of {need}"
            )
    return errors
