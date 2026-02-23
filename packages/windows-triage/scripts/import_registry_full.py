#!/usr/bin/env python3
"""
Import Full Registry Baseline into known_good_registry.db (OPTIONAL)

This script imports the complete registry baseline from VanillaWindowsRegistryHives,
storing all registry keys and values with OS version tracking.

WARNING: This creates a 2-3 GB database. Most users don't need this.
         Use import_registry_extractions.py instead for services/tasks/autoruns.

Use Case:
    - Deep registry forensics ("is this arbitrary registry key expected?")
    - Registry diff analysis against baseline
    - Comprehensive registry validation

Prerequisites:
    1. Run init_registry_db.py first
    2. Clone VanillaWindowsRegistryHives

Usage:
    python scripts/import_registry_full.py [options]

Options:
    --limit N       Only process first N JSON files
    --os-filter X   Only process files matching pattern
    --hive X        Only process specific hive (SYSTEM, SOFTWARE, NTUSER)
    --dry-run       Parse but don't write
    --verbose       Detailed output
"""

import argparse
import hashlib
import json
import logging
import re
import sqlite3
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Any


class RegistryJsonSource(NamedTuple):
    """Represents a registry JSON file, either on disk or inside a zip."""
    path: Path          # JSON file path (disk) or zip file path (zip)
    zip_entry: str      # "" for disk files, entry name for zip files
    os_folder: str      # OS version folder name (e.g. "W10_22H2_Pro_20221115_19045.2251")
    hive_type: str      # SYSTEM, SOFTWARE, NTUSER, SAM, SECURITY, DEFAULT

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_os_from_source(source: RegistryJsonSource) -> Dict[str, str]:
    """
    Parse OS info from a RegistryJsonSource.

    Uses source.os_folder (the OS version directory name) and source.hive_type.

    Folder name examples:
        W10_1507_Edu_20150729_10240
        W2016_1607_Standard_20161108_14393.447
        WindowsServer2008_SP2_Standard_20090526_6002
    """
    os_folder = source.os_folder

    result = {
        'short_name': os_folder,
        'os_family': 'Windows',
        'os_edition': None,
        'os_release': None,
        'hive_type': source.hive_type,
    }

    # Pattern: W10_1507_Edu_20150729_10240 or W2016_1607_Standard_20161108_14393
    match = re.match(r'^(W\d+|W2\d+)_(\w+)_(\w+)', os_folder)
    if match:
        prefix, release, edition = match.groups()
        if prefix.startswith('W2'):
            # Server version like W2016 -> Windows Server 2016
            result['os_family'] = f"Windows Server {prefix[1:]}"
        else:
            # Desktop version like W10 -> Windows 10
            result['os_family'] = f"Windows {prefix[1:]}"
        result['os_release'] = release
        result['os_edition'] = edition
    elif 'WindowsServer' in os_folder:
        # Pattern: WindowsServer2008_SP2_Standard_20090526_6002
        match2 = re.match(r'WindowsServer(\d+)_(\w+)_(\w+)', os_folder)
        if match2:
            version, release, edition = match2.groups()
            result['os_family'] = f"Windows Server {version}"
            result['os_release'] = release
            result['os_edition'] = edition

    return result


def flatten_registry_keys(
    data: Dict,
    current_path: str = "",
    results: List[Dict] = None
) -> List[Dict]:
    """
    Recursively flatten registry JSON into key/value records.

    Registry Explorer JSON format uses arrays:
        "SubKeys": [{"KeyName": "subkey1", ...}, {"KeyName": "subkey2", ...}]
        "Values": [{"ValueName": "name", "ValueType": "RegSz", "ValueData": "..."}, ...]

    Args:
        data: Registry JSON data
        current_path: Current key path being processed
        results: Accumulator for results

    Returns:
        List of dicts with: key_path, value_name, value_type, value_data
    """
    if results is None:
        results = []

    if not isinstance(data, dict):
        return results

    # Get key path from this node (use KeyName for relative path construction)
    key_name = data.get('KeyName', '')
    if not current_path and key_name:
        # Use the KeyPath from root, but normalize it
        key_path = data.get('KeyPath', key_name)
        # Extract just the registry path portion (after the hive identifier)
        if '\\' in key_path:
            # Remove the hive/GUID prefix, keep path after first backslash
            parts = key_path.split('\\', 1)
            current_path = parts[1] if len(parts) > 1 else ''
        else:
            current_path = ''
    elif key_name:
        current_path = f"{current_path}\\{key_name}" if current_path else key_name

    # Process values at this level (array format)
    values = data.get('Values', [])
    if isinstance(values, list):
        for value_entry in values:
            if isinstance(value_entry, dict):
                value_name = value_entry.get('ValueName', '')
                val_type = value_entry.get('ValueType', 'REG_SZ')
                val = value_entry.get('ValueData', '')

                # Convert value to string representation
                if isinstance(val, bytes):
                    val_str = val.hex()
                elif isinstance(val, (list, dict)):
                    val_str = json.dumps(val)
                else:
                    val_str = str(val) if val is not None else ''

                results.append({
                    'key_path': current_path,
                    'value_name': value_name,
                    'value_type': str(val_type),
                    'value_data': val_str
                })

    # Process subkeys (array format)
    subkeys = data.get('SubKeys', [])
    if isinstance(subkeys, list):
        for subkey_data in subkeys:
            if isinstance(subkey_data, dict):
                flatten_registry_keys(subkey_data, current_path, results)

    return results


def get_or_create_os_id(conn: sqlite3.Connection, os_info: Dict) -> int:
    """Get or create OS version entry."""
    cursor = conn.execute(
        "SELECT id FROM baseline_os WHERE short_name = ?",
        (os_info['short_name'],)
    )
    row = cursor.fetchone()
    if row:
        return row[0]

    cursor = conn.execute(
        """
        INSERT INTO baseline_os (short_name, os_family, os_edition, os_release, source_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        (os_info['short_name'], os_info['os_family'],
         os_info.get('os_edition'), os_info.get('os_release'),
         os_info.get('hive_type'))
    )
    conn.commit()
    return cursor.lastrowid


def import_registry_data(
    conn: sqlite3.Connection,
    records: List[Dict],
    hive: str,
    os_short_name: str,
    batch_size: int = 5000
) -> Dict[str, int]:
    """
    Import registry records with deduplication.

    Returns stats dict.
    """
    stats = {'inserted': 0, 'updated': 0, 'errors': 0}

    batch = []

    for record in records:
        try:
            key_path_lower = record['key_path'].lower()
            value_name = record['value_name']
            value_type = record['value_type']
            value_data = record['value_data']

            # Hash value_data for deduplication
            value_data_hash = hashlib.sha256(value_data.encode('utf-8', errors='replace')).hexdigest()[:32]

            batch.append((
                hive,
                key_path_lower,
                value_name,
                value_type,
                value_data,
                value_data_hash,
                os_short_name
            ))

            if len(batch) >= batch_size:
                _insert_batch(conn, batch, stats)
                batch = []

        except Exception as e:
            stats['errors'] += 1
            if stats['errors'] <= 5:
                logger.debug(f"Error processing record: {e}")

    if batch:
        _insert_batch(conn, batch, stats)

    return stats


def _insert_batch(conn: sqlite3.Connection, batch: List, stats: Dict):
    """Insert a batch of registry records with upsert logic."""
    for record in batch:
        hive, key_path, value_name, value_type, value_data, value_hash, os_name = record

        try:
            # Check if exists
            cursor = conn.execute(
                """
                SELECT id, os_versions FROM baseline_registry
                WHERE hive = ? AND key_path_lower = ?
                  AND (value_name = ? OR (value_name IS NULL AND ? IS NULL))
                  AND value_data_hash = ?
                """,
                (hive, key_path, value_name, value_name, value_hash)
            )
            row = cursor.fetchone()

            if row:
                # Update os_versions
                reg_id, os_versions_json = row
                os_versions = json.loads(os_versions_json)
                if os_name not in os_versions:
                    os_versions.append(os_name)
                    conn.execute(
                        "UPDATE baseline_registry SET os_versions = ? WHERE id = ?",
                        (json.dumps(os_versions), reg_id)
                    )
                    stats['updated'] += 1
            else:
                # Insert new
                conn.execute(
                    """
                    INSERT INTO baseline_registry
                        (hive, key_path_lower, value_name, value_type, value_data, value_data_hash, os_versions)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (hive, key_path, value_name, value_type, value_data, value_hash, json.dumps([os_name]))
                )
                stats['inserted'] += 1

        except sqlite3.IntegrityError:
            stats['updated'] += 1  # Duplicate, already exists
        except Exception as e:
            stats['errors'] += 1

    conn.commit()


def _hive_from_filename(filename: str) -> str:
    """Extract hive type from a filename like 'SYSTEM_ROOT.json'."""
    # Handle both forward and backslash paths from zip entries
    basename = filename.rsplit('/', 1)[-1].rsplit('\\', 1)[-1]
    return basename.replace('_ROOT.json', '').upper()


def find_registry_json_files(sources_dir: Path, hive_filter: Optional[str] = None) -> List[RegistryJsonSource]:
    """Find registry JSON files, checking disk first then falling back to zips."""
    registry_dir = sources_dir / "VanillaWindowsRegistryHives"
    if not registry_dir.exists():
        return []

    sources = []

    # First: scan for on-disk *_ROOT.json files (backward compat with extracted zips)
    for json_path in registry_dir.rglob("*_ROOT.json"):
        hive_type = _hive_from_filename(json_path.name)
        if hive_filter and hive_filter.upper() != hive_type:
            continue
        # OS folder is 3 levels up: KapeResearch -> mout -> OS_Version_Folder
        os_folder = json_path.parent.parent.parent.name
        sources.append(RegistryJsonSource(
            path=json_path,
            zip_entry="",
            os_folder=os_folder,
            hive_type=hive_type,
        ))

    if sources:
        logger.info(f"Found {len(sources)} on-disk registry JSON files")
        return sorted(sources, key=lambda s: (s.os_folder, s.hive_type))

    # Fallback: scan for RegistryHivesJSON.zip files
    for zip_path in registry_dir.rglob("RegistryHivesJSON.zip"):
        # OS folder is the parent of the zip file
        os_folder = zip_path.parent.name
        try:
            with zipfile.ZipFile(zip_path) as zf:
                for entry in zf.namelist():
                    if entry.endswith('_ROOT.json'):
                        hive_type = _hive_from_filename(entry)
                        if hive_filter and hive_filter.upper() != hive_type:
                            continue
                        sources.append(RegistryJsonSource(
                            path=zip_path,
                            zip_entry=entry,
                            os_folder=os_folder,
                            hive_type=hive_type,
                        ))
        except (zipfile.BadZipFile, OSError) as e:
            logger.warning(f"Skipping bad zip {zip_path}: {e}")

    if sources:
        logger.info(f"Found {len(sources)} registry JSON entries across zip files")

    return sorted(sources, key=lambda s: (s.os_folder, s.hive_type))


def load_registry_json(source: RegistryJsonSource) -> dict:
    """Load JSON data from a RegistryJsonSource (disk file or zip entry)."""
    if source.zip_entry:
        with zipfile.ZipFile(source.path) as zf:
            with zf.open(source.zip_entry) as f:
                return json.load(f)
    else:
        with open(source.path, 'r', encoding='utf-8', errors='replace') as f:
            return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description="Import full registry baseline (OPTIONAL - creates 2-3GB database)"
    )
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--os-filter", type=str)
    parser.add_argument("--hive", type=str, help="SYSTEM, SOFTWARE, or NTUSER")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--batch-size", type=int, default=5000)
    parser.add_argument("--sources-dir", type=str, default=None,
                        help="Override sources directory")
    parser.add_argument("--only-files", nargs="+",
                        help="Only process these specific JSON files")
    parser.add_argument("--sync-commit", type=str, default=None,
                        help="Record this commit hash after import")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    project_root = Path(__file__).parent.parent
    data_dir = project_root / "data"
    sources_dir = Path(args.sources_dir) if args.sources_dir else data_dir / "sources"

    db_path = data_dir / "known_good_registry.db"
    if not db_path.exists():
        logger.error("known_good_registry.db not found.")
        logger.error("Run: python scripts/init_registry_db.py")
        sys.exit(1)

    if args.only_files:
        # --only-files still works with on-disk paths (backward compat)
        sources = []
        for f in args.only_files:
            p = Path(f)
            if p.exists():
                hive_type = _hive_from_filename(p.name)
                os_folder = p.parent.parent.parent.name
                sources.append(RegistryJsonSource(
                    path=p, zip_entry="", os_folder=os_folder, hive_type=hive_type
                ))
        if not sources:
            logger.error("None of the specified --only-files exist")
            sys.exit(1)
        logger.info(f"Processing {len(sources)} specified JSON files")
    else:
        sources = find_registry_json_files(sources_dir, args.hive)
        if not sources:
            logger.error("No registry JSON files found (checked for *_ROOT.json and RegistryHivesJSON.zip)")
            sys.exit(1)

    logger.info(f"Found {len(sources)} registry JSON sources")

    if args.os_filter:
        sources = [s for s in sources if args.os_filter.lower() in s.os_folder.lower()]
        logger.info(f"Filtered to {len(sources)} sources")

    if args.limit > 0:
        sources = sources[:args.limit]

    conn = None if args.dry_run else sqlite3.connect(db_path)

    total_stats = {'inserted': 0, 'updated': 0, 'errors': 0, 'files': 0}

    try:
        for i, source in enumerate(sources):
            os_info = parse_os_from_source(source)
            hive = os_info['hive_type']

            if source.zip_entry:
                label = f"{source.path.name}:{source.zip_entry}"
            else:
                label = str(source.path)
            logger.info(f"[{i+1}/{len(sources)}] {os_info['short_name']} - {hive} ({label})")

            try:
                data = load_registry_json(source)
            except Exception as e:
                logger.error(f"Failed to load {label}: {e}")
                total_stats['errors'] += 1
                continue

            records = flatten_registry_keys(data)
            logger.info(f"  Extracted {len(records):,} registry values")

            if args.dry_run:
                total_stats['inserted'] += len(records)
            else:
                get_or_create_os_id(conn, os_info)
                stats = import_registry_data(
                    conn, records, hive, os_info['short_name'], args.batch_size
                )
                logger.info(f"  Inserted: {stats['inserted']:,}, Updated: {stats['updated']:,}")
                for key in stats:
                    total_stats[key] += stats[key]

            total_stats['files'] += 1

    finally:
        if conn:
            # Record sync commit if provided
            if args.sync_commit:
                conn.execute(
                    "UPDATE sources SET last_sync_commit = ?, last_sync_time = datetime('now') WHERE name = ?",
                    (args.sync_commit, 'vanilla_windows_registry')
                )
                if conn.execute("SELECT changes()").fetchone()[0] == 0:
                    conn.execute(
                        "INSERT INTO sources (name, source_type, url, last_sync_commit, last_sync_time) "
                        "VALUES (?, 'git', 'https://github.com/AndrewRathbun/VanillaWindowsRegistryHives', ?, datetime('now'))",
                        ('vanilla_windows_registry', args.sync_commit)
                    )
                conn.commit()
            conn.close()

    print("\n" + "=" * 60)
    print("FULL REGISTRY IMPORT SUMMARY")
    print("=" * 60)
    print(f"Files processed:  {total_stats['files']}")
    print(f"Records inserted: {total_stats['inserted']:,}")
    print(f"Records updated:  {total_stats['updated']:,}")
    print(f"Errors:           {total_stats['errors']}")

    if not args.dry_run:
        size_mb = db_path.stat().st_size / (1024 * 1024)
        print(f"\nDatabase size: {size_mb:.1f} MB")


if __name__ == "__main__":
    main()
