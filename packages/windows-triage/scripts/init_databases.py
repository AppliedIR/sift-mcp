#!/usr/bin/env python3
"""
Initialize Windows Triage Databases (v2 Hybrid Schema)

Creates the SQLite databases used by the forensic triage MCP server:

1. known_good.db - Ground truth baselines with path deduplication
   Tables: baseline_os, baseline_files, baseline_hashes, baseline_services,
           baseline_tasks, baseline_autoruns, sources

2. context.db - Risk enrichment and security context data
   Tables: lolbins, vulnerable_drivers, hijackable_dlls, expected_processes,
           suspicious_filenames, suspicious_pipe_patterns, windows_named_pipes,
           protected_process_names

3. known_good_registry.db (optional) - Full registry baseline
   Created separately via: python scripts/init_registry_db.py

Schema Changes from v1:
   - baseline_files: Now deduplicated with os_versions JSON array
   - baseline_hashes: Separate table for hash lookups (was inline)
   - baseline_services/tasks/autoruns: Now deduplicated with os_versions

Usage:
    python scripts/init_databases.py [--force]

Options:
    --force     Recreate databases even if they exist (DESTRUCTIVE)

After running this script, use import scripts to populate:
    python scripts/import_files.py        # VanillaWindowsReference
    python scripts/import_context.py      # LOLBins, drivers, etc.
"""

import argparse
import sys
from pathlib import Path

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from windows_triage.db import ContextDB, KnownGoodDB


def main():
    parser = argparse.ArgumentParser(description="Initialize forensic triage databases")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Recreate databases even if they exist (DESTRUCTIVE)",
    )
    args = parser.parse_args()

    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(exist_ok=True)

    # Initialize known_good.db
    known_good_path = data_dir / "known_good.db"

    if known_good_path.exists() and not args.force:
        print(f"WARNING: {known_good_path} already exists.")
        print("Use --force to recreate (DESTRUCTIVE) or delete manually.")
        print("Skipping known_good.db initialization.")
    else:
        if known_good_path.exists():
            print(f"Removing existing {known_good_path}...")
            known_good_path.unlink()

        print(f"Initializing {known_good_path}...")
        known_good_db = KnownGoodDB(known_good_path)
        known_good_db.init_schema()
        stats = known_good_db.get_stats()
        print(f"  Created tables. Stats: {stats}")
        known_good_db.close()

    # Initialize context.db
    context_path = data_dir / "context.db"

    if context_path.exists() and not args.force:
        print(f"\nWARNING: {context_path} already exists.")
        print("Use --force to recreate (DESTRUCTIVE) or delete manually.")
        print("Skipping context.db initialization.")
    else:
        if context_path.exists():
            print(f"Removing existing {context_path}...")
            context_path.unlink()

        print(f"\nInitializing {context_path}...")
        context_db = ContextDB(context_path)
        context_db.init_schema()
        stats = context_db.get_stats()
        print(f"  Created tables with initial data. Stats: {stats}")
        context_db.close()

    print("\n" + "=" * 60)
    print("Database initialization complete!")
    print("=" * 60)

    print("\nDatabase locations:")
    print(f"  known_good.db: {known_good_path}")
    print(f"  context.db:    {context_path}")

    print("\nNext steps:")
    print("  1. Clone data sources into data/sources/")
    print("  2. Run: python scripts/import_files.py")
    print("  3. Run: python scripts/import_context.py")
    print("  4. (Optional) Run: python scripts/import_registry_extractions.py")

    print("\nOptional full registry baseline:")
    print("  Run: python scripts/init_registry_db.py")
    print("  Then: python scripts/import_registry_full.py")


if __name__ == "__main__":
    main()
