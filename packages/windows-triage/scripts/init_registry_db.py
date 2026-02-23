#!/usr/bin/env python3
"""
Initialize Optional Full Registry Database

Creates known_good_registry.db for users who want full registry baseline
capabilities beyond the extracted services/tasks/autoruns.

This is OPTIONAL - most users only need the extractions in known_good.db.

Usage:
    python scripts/init_registry_db.py [--force]

After initialization, populate with:
    python scripts/import_registry_full.py
"""

import argparse
import sqlite3
import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from windows_triage.db.schemas import REGISTRY_FULL_SCHEMA


def main():
    parser = argparse.ArgumentParser(
        description="Initialize optional full registry database"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Recreate database even if it exists"
    )
    args = parser.parse_args()

    data_dir = Path(__file__).parent.parent / "data"
    db_path = data_dir / "known_good_registry.db"

    if db_path.exists() and not args.force:
        print(f"WARNING: {db_path} already exists.")
        print("Use --force to recreate or delete manually.")
        sys.exit(1)

    if db_path.exists():
        print(f"Removing existing {db_path}...")
        db_path.unlink()

    print(f"Initializing {db_path}...")
    conn = sqlite3.connect(db_path)
    conn.executescript(REGISTRY_FULL_SCHEMA)
    conn.commit()
    conn.close()

    print("Full registry database initialized.")
    print(f"\nLocation: {db_path}")
    print("\nNext step:")
    print("  python scripts/import_registry_full.py")
    print("\nNote: This will create a 2-3 GB database.")


if __name__ == "__main__":
    main()
