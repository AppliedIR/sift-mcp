#!/usr/bin/env python3
"""
Import VanillaWindowsReference Files into known_good.db (v2 Hybrid Schema)

This script imports file baselines from all 254 individual OS-specific CSVs
with proper path deduplication and OS version tracking.

Data Source:
    VanillaWindowsReference (github.com/AndrewRathbun/VanillaWindowsReference)
    - 254 CSV files across Windows 8.1, 10, 11, Server 2016-2022
    - Each CSV contains: FullName, DirectoryName, Name, Length, MD5, SHA1, SHA256

Deduplication Strategy:
    - Each unique file path stored once in baseline_files
    - os_versions JSON array tracks which OS versions have this path
    - Hashes stored separately in baseline_hashes with file_id reference

Expected Output:
    - ~2.4M unique paths (deduplicated from ~24M total)
    - ~5M hash entries in baseline_hashes
    - ~250 OS versions in baseline_os

Prerequisites:
    1. Run init_databases.py first
    2. Clone VanillaWindowsReference:
       cd data/sources
       git clone https://github.com/AndrewRathbun/VanillaWindowsReference.git

Usage:
    python scripts/import_files.py [options]

Options:
    --limit N       Only process first N CSV files (for testing)
    --os-filter X   Only process CSVs matching pattern (e.g., "Win11")
    --dry-run       Parse CSVs but don't write to database
    --verbose       Show detailed progress
"""

import argparse
import csv
import json
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from windows_triage.db import KnownGoodDB
from windows_triage.analysis.paths import normalize_path, extract_filename, extract_directory

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_os_from_csv_path(csv_path: Path) -> Dict[str, str]:
    """
    Parse OS information from CSV file path.

    Examples:
        Windows11/21H2/W11_21H2_Pro_20230321_22000.1696/FileHashes.csv
        Windows10/21H2/W10_21H2_Enterprise_20230101_19044.1234/FileHashes.csv
        WindowsServer/2022/WS2022_21H2_Standard_20230101_20348.1234/FileHashes.csv

    Returns:
        Dict with: short_name, os_family, os_edition, os_release, build_number
    """
    parts = csv_path.parts
    filename = csv_path.parent.name  # The folder containing the CSV

    result = {
        'short_name': filename,
        'os_family': 'Windows',
        'os_edition': None,
        'os_release': None,
        'build_number': None,
        'source_csv': csv_path.name
    }

    # Parse from folder name - multiple patterns:
    # W11_21H2_Pro_20230321_22000.1696
    # W10_1507_Pro_20150729_10240
    # WindowsServer2022_21H2_Standard_20230321_20348.1607
    match = re.match(
        r'^(W\d+|WS\d+)_(\w+)_(\w+)_(\d+)_(\d+\.?\d*)',
        filename
    )
    if match:
        prefix, release, edition, date, build = match.groups()

        if prefix.startswith('WS'):
            result['os_family'] = f"Windows Server {prefix[2:]}"
        else:
            result['os_family'] = f"Windows {prefix[1:]}"

        result['os_release'] = release
        result['os_edition'] = edition
        result['build_number'] = build
    else:
        # Try WindowsServer pattern: WindowsServer2022_21H2_Standard_20230321_20348.1607
        match = re.match(
            r'^WindowsServer(\d+)_(\w+)_(\w+)_(\d+)_(\d+\.?\d*)',
            filename
        )
        if match:
            server_ver, release, edition, date, build = match.groups()
            result['os_family'] = f"Windows Server {server_ver}"
            result['os_release'] = release
            result['os_edition'] = edition
            result['build_number'] = build

    # Also check parent folders for OS version info
    for part in parts:
        if part.startswith('Windows') and not part.startswith('WindowsServer'):
            if 'Windows11' in part or 'Windows 11' in part:
                result['os_family'] = 'Windows 11'
            elif 'Windows10' in part or 'Windows 10' in part:
                result['os_family'] = 'Windows 10'
            elif 'Windows8' in part:
                result['os_family'] = 'Windows 8.1'
        elif part.startswith('WindowsServer'):
            # Extract server version
            server_match = re.search(r'(\d{4})', str(parts))
            if server_match:
                result['os_family'] = f"Windows Server {server_match.group(1)}"

    return result


def find_csv_files(sources_dir: Path) -> List[Path]:
    """
    Find all FileHashes.csv or similar CSV files in VanillaWindowsReference.

    Returns list of CSV paths sorted by OS version.
    """
    vanilla_dir = sources_dir / "VanillaWindowsReference"
    if not vanilla_dir.exists():
        logger.error(f"VanillaWindowsReference not found at {vanilla_dir}")
        logger.error("Clone it with: git clone https://github.com/AndrewRathbun/VanillaWindowsReference.git")
        return []

    csv_files = []

    # Find all CSV files with file data (not the aggregated ones)
    for csv_path in vanilla_dir.rglob("*.csv"):
        # Skip aggregated files in FIlePathHashSets
        if "FIlePathHashSets" in str(csv_path):
            continue
        # Skip any test or temp files
        if "test" in csv_path.name.lower() or "temp" in csv_path.name.lower():
            continue
        # Look for files that have hash data
        if csv_path.stat().st_size > 1000:  # Skip tiny/empty files
            csv_files.append(csv_path)

    logger.info(f"Found {len(csv_files)} CSV files to process")
    return sorted(csv_files)


def process_csv_file(
    csv_path: Path,
    db: KnownGoodDB,
    os_info: Dict[str, str],
    batch_size: int = 10000
) -> Dict[str, int]:
    """
    Process a single CSV file and import into database.

    Args:
        csv_path: Path to CSV file
        db: Database connection
        os_info: Parsed OS information
        batch_size: Number of records to process at a time

    Returns:
        Stats dict with files_processed, files_added, hashes_added
    """
    stats = {
        'files_processed': 0,
        'files_new': 0,
        'files_updated': 0,
        'hashes_added': 0,
        'errors': 0
    }

    # Register OS version
    os_id = db.add_os_version(
        short_name=os_info['short_name'],
        os_family=os_info['os_family'],
        os_edition=os_info.get('os_edition'),
        os_release=os_info.get('os_release'),
        build_number=os_info.get('build_number'),
        source_csv=os_info.get('source_csv')
    )

    batch = []

    try:
        with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)

            for row in reader:
                try:
                    # Get path - try different column names
                    full_path = row.get('FullName') or row.get('Path') or row.get('FilePath', '')
                    name = row.get('Name') or row.get('FileName', '')

                    if not full_path and not name:
                        continue

                    # If we only have name, try to construct path from DirectoryName
                    if not full_path and name:
                        directory = row.get('DirectoryName', '')
                        full_path = f"{directory}\\{name}" if directory else name

                    # Skip research artifacts
                    if 'IgnoreThisFile' in full_path or 'test.csv' in full_path:
                        continue

                    # Extract hashes
                    md5 = row.get('MD5', '').strip() or None
                    sha1 = row.get('SHA1', '').strip() or None
                    sha256 = row.get('SHA256', '').strip() or None

                    # Get file size
                    try:
                        file_size = int(row.get('Length', 0) or 0) or None
                    except (ValueError, TypeError):
                        file_size = None

                    batch.append({
                        'path': full_path,
                        'md5': md5,
                        'sha1': sha1,
                        'sha256': sha256,
                        'file_size': file_size
                    })

                    stats['files_processed'] += 1

                    if len(batch) >= batch_size:
                        result = db.upsert_files_batch(
                            batch,
                            os_info['short_name'],
                            os_info.get('source_csv')
                        )
                        stats['files_new'] += result.get('inserted', 0)
                        stats['files_updated'] += result.get('updated', 0)
                        stats['hashes_added'] += result.get('hashes_added', 0)
                        batch = []

                except Exception as e:
                    stats['errors'] += 1
                    if stats['errors'] <= 5:
                        logger.warning(f"Error processing row: {e}")

        # Final batch
        if batch:
            result = db.upsert_files_batch(
                batch,
                os_info['short_name'],
                os_info.get('source_csv')
            )
            stats['files_new'] += result.get('inserted', 0)
            stats['files_updated'] += result.get('updated', 0)
            stats['hashes_added'] += result.get('hashes_added', 0)

    except Exception as e:
        logger.error(f"Failed to process {csv_path}: {e}")
        stats['errors'] += 1

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Import VanillaWindowsReference files into known_good.db"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only process first N CSV files (for testing)"
    )
    parser.add_argument(
        "--os-filter",
        type=str,
        default=None,
        help="Only process CSVs matching pattern (e.g., 'Win11', 'Server2022')"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse CSVs but don't write to database"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed progress"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10000,
        help="Batch size for database operations"
    )
    parser.add_argument(
        "--sources-dir",
        type=str,
        default=None,
        help="Override sources directory (default: data/sources)"
    )
    parser.add_argument(
        "--only-files",
        nargs="+",
        help="Only process these specific CSV file paths (for incremental updates)"
    )
    parser.add_argument(
        "--sync-commit",
        type=str,
        default=None,
        help="Record this commit hash in sources table after import"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    project_root = Path(__file__).parent.parent
    data_dir = project_root / "data"
    sources_dir = Path(args.sources_dir) if args.sources_dir else data_dir / "sources"

    # Check database exists
    db_path = data_dir / "known_good.db"
    if not db_path.exists():
        logger.error(f"Database not found: {db_path}")
        logger.error("Run: python scripts/init_databases.py")
        sys.exit(1)

    # Find CSV files
    if args.only_files:
        csv_files = [Path(f) for f in args.only_files if Path(f).exists()]
        if not csv_files:
            logger.error("None of the specified --only-files exist")
            sys.exit(1)
        logger.info(f"Processing {len(csv_files)} specified CSV files")
    else:
        csv_files = find_csv_files(sources_dir)
        if not csv_files:
            sys.exit(1)

    # Apply filters
    if args.os_filter:
        csv_files = [f for f in csv_files if args.os_filter.lower() in str(f).lower()]
        logger.info(f"Filtered to {len(csv_files)} files matching '{args.os_filter}'")

    if args.limit > 0:
        csv_files = csv_files[:args.limit]
        logger.info(f"Limited to first {len(csv_files)} files")

    if not csv_files:
        logger.error("No CSV files to process after filtering")
        sys.exit(1)

    # Process files
    if args.dry_run:
        logger.info("DRY RUN - no database changes will be made")
        db = None
    else:
        db = KnownGoodDB(db_path)
        db.connect()

    total_stats = {
        'files_processed': 0,
        'files_new': 0,
        'files_updated': 0,
        'hashes_added': 0,
        'errors': 0,
        'csvs_processed': 0
    }

    try:
        for i, csv_path in enumerate(csv_files):
            os_info = parse_os_from_csv_path(csv_path)

            logger.info(f"\n[{i+1}/{len(csv_files)}] Processing: {os_info['short_name']}")
            logger.info(f"  OS: {os_info['os_family']} {os_info.get('os_release', '')} {os_info.get('os_edition', '')}")
            logger.info(f"  File: {csv_path.name}")

            if args.dry_run:
                # Just count rows
                with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
                    row_count = sum(1 for _ in csv.DictReader(f))
                logger.info(f"  Would process {row_count:,} rows")
                total_stats['files_processed'] += row_count
            else:
                stats = process_csv_file(csv_path, db, os_info, args.batch_size)
                logger.info(f"  Processed: {stats['files_processed']:,} files")
                logger.info(f"  New paths: {stats['files_new']:,}, Updated: {stats['files_updated']:,}")
                logger.info(f"  Hashes: {stats['hashes_added']:,}, Errors: {stats['errors']}")

                for key in total_stats:
                    if key in stats:
                        total_stats[key] += stats[key]

            total_stats['csvs_processed'] += 1

    finally:
        if db:
            # Update source tracking
            db.update_source_stats('vanilla_windows_reference', total_stats['files_new'])
            if args.sync_commit:
                import sqlite3
                conn = sqlite3.connect(db_path)
                conn.execute(
                    "UPDATE sources SET last_sync_commit = ?, last_sync_time = datetime('now') WHERE name = ?",
                    (args.sync_commit, 'vanilla_windows_reference')
                )
                if conn.execute("SELECT changes()").fetchone()[0] == 0:
                    conn.execute(
                        "INSERT INTO sources (name, source_type, url, last_sync_commit, last_sync_time) "
                        "VALUES (?, 'git', 'https://github.com/AndrewRathbun/VanillaWindowsReference', ?, datetime('now'))",
                        ('vanilla_windows_reference', args.sync_commit)
                    )
                conn.commit()
                conn.close()
            db.close()

    # Print summary
    print("\n" + "=" * 60)
    print("IMPORT SUMMARY")
    print("=" * 60)
    print(f"CSV files processed:  {total_stats['csvs_processed']}")
    print(f"Total files scanned:  {total_stats['files_processed']:,}")
    print(f"New unique paths:     {total_stats['files_new']:,}")
    print(f"Updated paths:        {total_stats['files_updated']:,}")
    print(f"Hashes indexed:       {total_stats['hashes_added']:,}")
    print(f"Errors:               {total_stats['errors']}")

    if not args.dry_run and db_path.exists():
        db = KnownGoodDB(db_path)
        db.connect()
        final_stats = db.get_stats()
        db.close()

        print("\nFinal database stats:")
        print(f"  OS versions:    {final_stats['os_versions']}")
        print(f"  Unique files:   {final_stats['files']:,}")
        print(f"  Hash entries:   {final_stats['hashes']:,}")

        # Show database size
        size_mb = db_path.stat().st_size / (1024 * 1024)
        print(f"\nDatabase size: {size_mb:.1f} MB")


if __name__ == "__main__":
    main()
