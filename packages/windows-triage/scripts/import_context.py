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
    2. Clone repositories into data/sources/:
       cd data/sources
       git clone https://github.com/LOLBAS-Project/LOLBAS.git
       git clone https://github.com/magicsword-io/LOLDrivers.git
       git clone https://github.com/wietze/HijackLibs.git

Usage:
    python scripts/import_context.py
"""

import logging
import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from windows_triage.importers import (
    import_lolbas,
    import_loldrivers,
    import_hijacklibs,
    import_process_expectations,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    project_root = Path(__file__).parent.parent
    data_dir = project_root / "data"
    sources_dir = data_dir / "sources"

    # Check database exists
    context_db = data_dir / "context.db"
    if not context_db.exists():
        logger.error("context.db not found. Run: python scripts/init_databases.py")
        sys.exit(1)

    total_stats = {}

    # Import LOLBAS
    lolbas_dir = sources_dir / "LOLBAS"
    if lolbas_dir.exists():
        logger.info("\n=== Importing LOLBAS ===")
        stats = import_lolbas(db_path=context_db, lolbas_dir=lolbas_dir)
        logger.info(f"  LOLBins imported: {stats['lolbins_imported']}")
        total_stats['lolbins'] = stats['lolbins_imported']
    else:
        logger.warning("LOLBAS not cloned. Skipping.")
        logger.warning("  Clone: git clone https://github.com/LOLBAS-Project/LOLBAS.git")

    # Import LOLDrivers
    loldrivers_dir = sources_dir / "LOLDrivers"
    if loldrivers_dir.exists():
        logger.info("\n=== Importing LOLDrivers ===")
        stats = import_loldrivers(
            db_path=context_db,
            loldrivers_dir=loldrivers_dir,
            include_malicious=True
        )
        logger.info(f"  Vulnerable drivers: {stats['vulnerable_imported']}")
        logger.info(f"  Malicious drivers:  {stats['malicious_imported']}")
        logger.info(f"  Total samples:      {stats['samples_imported']}")
        total_stats['drivers'] = stats['samples_imported']
    else:
        logger.warning("LOLDrivers not cloned. Skipping.")
        logger.warning("  Clone: git clone https://github.com/magicsword-io/LOLDrivers.git")

    # Import HijackLibs
    hijacklibs_dir = sources_dir / "HijackLibs"
    if hijacklibs_dir.exists():
        logger.info("\n=== Importing HijackLibs ===")
        stats = import_hijacklibs(db_path=context_db, hijacklibs_dir=hijacklibs_dir)
        logger.info(f"  Hijackable DLLs:    {stats['dlls_imported']}")
        logger.info(f"  Vulnerable entries: {stats['entries_imported']}")
        total_stats['hijackable_dlls'] = stats['entries_imported']
    else:
        logger.warning("HijackLibs not cloned. Skipping.")
        logger.warning("  Clone: git clone https://github.com/wietze/HijackLibs.git")

    # Import process expectations (from YAML)
    logger.info("\n=== Importing Process Expectations ===")
    stats = import_process_expectations(db_path=context_db)
    logger.info(f"  Process rules: {stats['processes_imported']}")
    total_stats['process_rules'] = stats['processes_imported']

    # Print summary
    print("\n" + "=" * 60)
    print("CONTEXT IMPORT SUMMARY")
    print("=" * 60)
    for key, value in total_stats.items():
        print(f"  {key}: {value}")

    # Show final database stats
    import sqlite3
    conn = sqlite3.connect(context_db)
    c = conn.cursor()

    print("\nFinal context.db stats:")
    for table in ['lolbins', 'vulnerable_drivers', 'hijackable_dlls', 'expected_processes']:
        c.execute(f"SELECT COUNT(*) FROM {table}")
        count = c.fetchone()[0]
        print(f"  {table}: {count}")

    conn.close()


if __name__ == "__main__":
    main()
