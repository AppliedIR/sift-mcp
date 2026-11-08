#!/usr/bin/env python3
"""
Import Context Data into context.db

This script populates context.db with risk enrichment data from:
- LOLBAS (Living Off The Land Binaries)
- LOLDrivers (Vulnerable drivers)
- HijackLibs (DLL hijacking vulnerabilities)
- Process expectations (from YAML - sourced from MemProcFS + SANS Hunt Evil)

Prerequisites:
    1. Run init_databases.py first
    2. The three repositories cloned under data/sources/ (LOLBAS, LOLDrivers,
       HijackLibs): import_all.py --fetch clones them and runs this script

Usage:
    python scripts/import_context.py
    python scripts/import_context.py --sync-commit LOLBAS=<commit> ...

Each --sync-commit <clone dir name>=<commit> is recorded on that source's row
only when that source imported with no problem.
"""

import argparse
import logging
import sqlite3
import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from windows_triage.importers import (
    import_hijacklibs,
    import_lolbas,
    import_loldrivers,
    import_process_expectations,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Each git source: its clone dir name under data/sources, and its sources row
SYNC_ROWS = {
    "LOLBAS": "lolbas",
    "LOLDrivers": "loldrivers_vulnerable",
    "HijackLibs": "hijacklibs",
}


def _sync_commit(text: str) -> tuple[str, str]:
    name, sep, commit = text.partition("=")
    if not sep or name not in SYNC_ROWS or not commit:
        raise argparse.ArgumentTypeError(
            f"expected <{'|'.join(SYNC_ROWS)}>=<commit>, got {text!r}"
        )
    return name, commit


def record_sync(db_path: Path, row: str, commit: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE sources SET last_sync_commit = ?, last_sync_time = datetime('now') "
            "WHERE name = ?",
            (commit, row),
        )
        conn.commit()
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Import context data into context.db")
    parser.add_argument(
        "--db", default=None, help="context.db to import into (default: data/context.db)"
    )
    parser.add_argument(
        "--sources-dir", default=None, help="Clones dir (default: data/sources)"
    )
    parser.add_argument(
        "--sync-commit",
        action="append",
        type=_sync_commit,
        default=[],
        metavar="NAME=COMMIT",
        help="Record COMMIT for the source cloned as NAME, if it imports cleanly",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    commits = dict(args.sync_commit)

    project_root = Path(__file__).parent.parent
    data_dir = project_root / "data"
    sources_dir = Path(args.sources_dir) if args.sources_dir else data_dir / "sources"

    # Check database exists
    context_db = Path(args.db) if args.db else data_dir / "context.db"
    if not context_db.exists():
        logger.error("context.db not found. Run: python scripts/init_databases.py")
        sys.exit(1)

    total_stats = {}
    problems: list[str] = []  # an importer with errors, or nothing imported
    imported: set[str] = set()  # the git sources that imported with no problem

    # Import LOLBAS
    lolbas_dir = sources_dir / "LOLBAS"
    if lolbas_dir.exists():
        logger.info("\n=== Importing LOLBAS ===")
        stats = import_lolbas(db_path=context_db, lolbas_dir=lolbas_dir)
        logger.info(f"  LOLBins imported: {stats['lolbins_imported']}")
        total_stats["lolbins"] = stats["lolbins_imported"]
        if stats["errors"] or not stats["lolbins_imported"]:
            problems.append(
                f"LOLBAS: {stats['errors']} error(s), {stats['lolbins_imported']} imported"
            )
        else:
            imported.add("LOLBAS")
    else:
        logger.warning("LOLBAS not cloned. Skipping.")
        logger.warning(
            "  Clone: git clone https://github.com/LOLBAS-Project/LOLBAS.git"
        )

    # Import LOLDrivers
    loldrivers_dir = sources_dir / "LOLDrivers"
    if loldrivers_dir.exists():
        logger.info("\n=== Importing LOLDrivers ===")
        stats = import_loldrivers(
            db_path=context_db, loldrivers_dir=loldrivers_dir, include_malicious=True
        )
        logger.info(f"  Vulnerable drivers: {stats['vulnerable_imported']}")
        logger.info(f"  Malicious drivers:  {stats['malicious_imported']}")
        logger.info(f"  Total samples:      {stats['samples_imported']}")
        total_stats["drivers"] = stats["samples_imported"]
        if stats["errors"] or not stats["samples_imported"]:
            problems.append(
                f"LOLDrivers: {stats['errors']} error(s), {stats['samples_imported']} imported"
            )
        else:
            imported.add("LOLDrivers")
    else:
        logger.warning("LOLDrivers not cloned. Skipping.")
        logger.warning(
            "  Clone: git clone https://github.com/magicsword-io/LOLDrivers.git"
        )

    # Import HijackLibs
    hijacklibs_dir = sources_dir / "HijackLibs"
    if hijacklibs_dir.exists():
        logger.info("\n=== Importing HijackLibs ===")
        stats = import_hijacklibs(db_path=context_db, hijacklibs_dir=hijacklibs_dir)
        logger.info(f"  Hijackable DLLs:    {stats['dlls_imported']}")
        logger.info(f"  Vulnerable entries: {stats['entries_imported']}")
        total_stats["hijackable_dlls"] = stats["entries_imported"]
        if stats["skipped_files"]:
            names = ", ".join(stats["skipped_files"][:10])
            problems.append(
                f"HijackLibs: {len(stats['skipped_files'])} file(s) skipped, unreadable: {names}"
            )
        elif stats["errors"] or not stats["entries_imported"]:
            problems.append(
                f"HijackLibs: {stats['errors']} error(s), {stats['entries_imported']} entries"
            )
        else:
            imported.add("HijackLibs")
    else:
        logger.warning("HijackLibs not cloned. Skipping.")
        logger.warning("  Clone: git clone https://github.com/wietze/HijackLibs.git")

    # Import process expectations (from YAML)
    logger.info("\n=== Importing Process Expectations ===")
    stats = import_process_expectations(db_path=context_db)
    logger.info(f"  Process rules: {stats['processes_imported']}")
    total_stats["process_rules"] = stats["processes_imported"]
    if stats["errors"] or not stats["processes_imported"]:
        problems.append(
            f"Process expectations: {stats['errors']} error(s), "
            f"{stats['processes_imported']} imported"
        )

    # Record each given commit on its source's row, for a clean import only
    for name, commit in commits.items():
        if name in imported:
            record_sync(context_db, SYNC_ROWS[name], commit)
        else:
            logger.warning(f"{name}: not imported cleanly; commit not recorded")

    # Print summary
    print("\n" + "=" * 60)
    print("CONTEXT IMPORT SUMMARY")
    print("=" * 60)
    for key, value in total_stats.items():
        print(f"  {key}: {value}")

    # Show final database stats
    conn = sqlite3.connect(context_db)
    c = conn.cursor()

    print("\nFinal context.db stats:")
    for table in [
        "lolbins",
        "vulnerable_drivers",
        "hijackable_dlls",
        "expected_processes",
    ]:
        c.execute(f"SELECT COUNT(*) FROM {table}")
        count = c.fetchone()[0]
        print(f"  {table}: {count}")

    conn.close()
    if problems:  # a source that failed or found nothing never passes as imported
        print("\nIMPORT FAILED:")
        for line in problems:
            print(f"  {line}")
        sys.exit(1)


if __name__ == "__main__":
    main()
