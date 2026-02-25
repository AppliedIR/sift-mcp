#!/usr/bin/env python3
"""
Import Registry Extractions into known_good.db

Extracts services, scheduled tasks, and autoruns from VanillaWindowsRegistryHives
JSON exports and imports them into known_good.db with deduplication.

Data Source:
    VanillaWindowsRegistryHives (github.com/AndrewRathbun/VanillaWindowsRegistryHives)
    - 242 JSON files (SYSTEM_ROOT.json, SOFTWARE_ROOT.json, NTUSER_ROOT.json per OS)
    - KAPE/Registry Explorer export format

Extraction Targets:
    Services:   SYSTEM\\ControlSet001\\Services\\*
    Tasks:      SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*
    Autoruns:   SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*
                NTUSER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*

Prerequisites:
    1. Run init_databases.py first
    2. Clone VanillaWindowsRegistryHives:
       cd data/sources
       git clone https://github.com/AndrewRathbun/VanillaWindowsRegistryHives.git

Usage:
    python scripts/import_registry_extractions.py [options]

Options:
    --limit N       Only process first N JSON files (for testing)
    --os-filter X   Only process files matching pattern
    --dry-run       Parse but don't write to database
    --verbose       Show detailed progress
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from windows_triage.db import KnownGoodDB

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def is_release_number(s: str) -> bool:
    """Check if string looks like a Windows release number (1507, 1903, 20H2, 21H2, etc.)"""
    return bool(re.match(r"^(\d{4}|\d{2}H\d)$", s))


def parse_os_from_json_path(json_path: Path) -> dict[str, str]:
    """
    Parse OS information from JSON file path.

    Example path structures:
        W11_21H2_Pro_20230321_22000.1696/SYSTEM_ROOT.json  -> release_edition
        W10_Pro_1507_20150729_10240/SYSTEM_ROOT.json      -> edition_release (old)
        W2016_1607_Standard_20161108/SYSTEM_ROOT.json     -> Server 2016
        WindowsServer2022_21H2_Standard_20230321/SYSTEM_ROOT.json
    """
    parts = json_path.parts
    hive_type = json_path.stem.replace("_ROOT", "")  # SYSTEM, SOFTWARE, NTUSER

    result = {
        "short_name": "Unknown",
        "os_family": "Windows",
        "os_edition": None,
        "os_release": None,
        "hive_type": hive_type,
    }

    # Search through path parts for OS version folder
    for part in parts:
        # Try WindowsServer pattern first (most specific)
        # WindowsServer2022_21H2_Standard_20230321_20348.1607
        match = re.match(r"^WindowsServer(\d+)_([^_]+)_([^_]+)_(\d+)", part)
        if match:
            server_ver, release, edition = match.groups()[:3]
            result["short_name"] = part
            result["os_family"] = f"Windows Server {server_ver}"
            result["os_release"] = release
            result["os_edition"] = edition
            break

        # Try W2016 pattern (Server 2016) before W10/W11
        # W2016_1607_Standard_20161108_14393.447
        match = re.match(r"^W(\d{4})_([^_]+)_([^_]+)_(\d+)", part)
        if match:
            server_year, release, edition = match.groups()[:3]
            result["short_name"] = part
            result["os_family"] = f"Windows Server {server_year}"
            result["os_release"] = release
            result["os_edition"] = edition
            break

        # Try WS (abbreviated server) pattern
        # WS2022_21H2_Standard_...
        match = re.match(r"^WS(\d+)_([^_]+)_([^_]+)", part)
        if match:
            server_ver, release, edition = match.groups()
            result["short_name"] = part
            result["os_family"] = f"Windows Server {server_ver}"
            result["os_release"] = release
            result["os_edition"] = edition
            break

        # Try W10/W11 pattern: W10_1903_Pro_... or W10_Pro_1507_...
        # Use [^_]+ to stop at underscores
        match = re.match(r"^W(\d+)_([^_]+)_([^_]+)_(\d+)", part)
        if match:
            win_ver, field2, field3 = match.groups()[:3]
            result["short_name"] = part
            result["os_family"] = f"Windows {win_ver}"
            # Determine which field is release vs edition
            if is_release_number(field2):
                result["os_release"] = field2
                result["os_edition"] = field3
            else:
                result["os_edition"] = field2
                result["os_release"] = field3
            break

    return result


def find_registry_json_files(
    sources_dir: Path, custom_registry_dir: Path = None
) -> dict[str, list[Path]]:
    """
    Find all registry JSON files organized by type.

    Looks for extracted JSONs in:
      - mout/KapeResearch/*_ROOT.json (KAPE export structure)
      - *_ROOT.json directly (if reorganized)

    Args:
        sources_dir: Path to data/sources directory
        custom_registry_dir: Optional custom directory with extracted JSONs

    Returns:
        Dict with keys: system, software, ntuser
    """
    if custom_registry_dir and custom_registry_dir.exists():
        registry_dir = custom_registry_dir
        logger.info(f"Using custom registry directory: {registry_dir}")
    else:
        registry_dir = sources_dir / "VanillaWindowsRegistryHives"
        if not registry_dir.exists():
            logger.error(f"VanillaWindowsRegistryHives not found at {registry_dir}")
            return {"system": [], "software": [], "ntuser": []}

    files = {"system": [], "software": [], "ntuser": []}

    # Look for extracted JSONs (inside mout/KapeResearch/ from ZIP extraction)
    for json_path in registry_dir.rglob("*_ROOT.json"):
        name_lower = json_path.name.lower()
        if "system" in name_lower:
            files["system"].append(json_path)
        elif "software" in name_lower:
            files["software"].append(json_path)
        elif "ntuser" in name_lower:
            files["ntuser"].append(json_path)

    for key, paths in files.items():
        logger.info(f"Found {len(paths)} {key.upper()} JSON files")

    # Check if ZIPs need extraction
    if not any(files.values()):
        zip_count = len(list(registry_dir.rglob("RegistryHivesJSON.zip")))
        if zip_count > 0:
            logger.error(
                f"Found {zip_count} RegistryHivesJSON.zip files but no extracted JSONs!"
            )
            logger.error("Run: python scripts/extract_registry_zips.py")
            sys.exit(1)

    return files


def navigate_to_key(
    root: dict, key_path: str, _normalized_target: str = None
) -> dict | None:
    """
    Navigate to a registry key in the JSON structure.

    The JSON structure is nested arrays:
    {
        "KeyPath": "ROOT",  # or "CMI-CreateHive{GUID}" for some hives
        "SubKeys": [
            {"KeyPath": "ROOT\\ControlSet001", "SubKeys": [...], "Values": [...]},
            ...
        ]
    }

    Args:
        root: Root JSON object
        key_path: Path like "ROOT\\ControlSet001\\Services"
        _normalized_target: Internal - normalized path for recursion

    Returns:
        The key dict at that path, or None
    """
    if not root:
        return None

    current_path = root.get("KeyPath", "").upper()

    # On first call, normalize the target path using actual root
    if _normalized_target is None:
        # Replace 'ROOT' prefix with actual root from hive
        if key_path.upper().startswith("ROOT"):
            _normalized_target = current_path + key_path[4:].upper()
        else:
            _normalized_target = key_path.upper()

    # Check if we're already at the target
    if current_path == _normalized_target:
        return root

    # If target is a child of current, navigate down
    if not _normalized_target.startswith(current_path):
        return None

    # Search in SubKeys array
    subkeys = root.get("SubKeys", [])
    if not isinstance(subkeys, list):
        return None

    for subkey in subkeys:
        if not isinstance(subkey, dict):
            continue

        subkey_path = subkey.get("KeyPath", "").upper()

        # Exact match
        if subkey_path == _normalized_target:
            return subkey

        # Check if target is under this subkey
        if _normalized_target.startswith(subkey_path + "\\"):
            # Pass normalized target to avoid re-normalization
            result = navigate_to_key(subkey, key_path, _normalized_target)
            if result:
                return result

    return None


def extract_services(system_json: dict, os_info: dict, db: KnownGoodDB) -> int:
    """
    Extract services from SYSTEM hive JSON.

    Path: ROOT\\ControlSet001\\Services\\*
    """
    count = 0

    # Try to find Services key
    services_key = navigate_to_key(system_json, "ROOT\\ControlSet001\\Services")
    if not services_key:
        logger.debug("Services key not found in SYSTEM hive")
        return 0

    # SubKeys is an array of service entries
    subkeys = services_key.get("SubKeys", [])
    if not isinstance(subkeys, list):
        return 0

    for service_data in subkeys:
        if not isinstance(service_data, dict):
            continue

        try:
            # Service name is from KeyName
            service_name = service_data.get("KeyName", "")
            if not service_name:
                continue

            # Extract service properties from Values array
            values = service_data.get("Values", [])
            if not isinstance(values, list):
                values = []

            display_name = None
            image_path = None
            start_type = None
            service_type = None
            object_name = None
            description = None

            for value_entry in values:
                if not isinstance(value_entry, dict):
                    continue

                value_name = value_entry.get("ValueName", "")
                value_data = value_entry.get("ValueData", "")
                val_lower = value_name.lower()

                if val_lower == "displayname":
                    display_name = str(value_data)
                elif val_lower == "imagepath":
                    image_path = str(value_data)
                elif val_lower == "start":
                    try:
                        start_type = int(value_data)
                    except (ValueError, TypeError):
                        pass
                elif val_lower == "type":
                    try:
                        service_type = int(value_data)
                    except (ValueError, TypeError):
                        pass
                elif val_lower == "objectname":
                    object_name = str(value_data)
                elif val_lower == "description":
                    description = str(value_data)

            db.upsert_service(
                service_name=service_name,
                os_short_name=os_info["short_name"],
                display_name=display_name,
                binary_path=image_path,
                start_type=start_type,
                service_type=service_type,
                object_name=object_name,
                description=description,
            )
            count += 1

        except Exception as e:
            logger.debug(f"Error extracting service {service_name}: {e}")

    return count


def extract_tasks(software_json: dict, os_info: dict, db: KnownGoodDB) -> int:
    """
    Extract scheduled tasks from SOFTWARE hive JSON.

    Path: ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*
    """
    count = 0

    tasks_key = navigate_to_key(
        software_json,
        "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
    )
    if not tasks_key:
        logger.debug("TaskCache\\Tasks key not found in SOFTWARE hive")
        return 0

    subkeys = tasks_key.get("SubKeys", [])
    if not isinstance(subkeys, list):
        return 0

    for task_data in subkeys:
        if not isinstance(task_data, dict):
            continue

        try:
            task_guid = task_data.get("KeyName", "")
            values = task_data.get("Values", [])
            if not isinstance(values, list):
                values = []

            task_path = None
            uri = None
            author = None

            for value_entry in values:
                if not isinstance(value_entry, dict):
                    continue

                value_name = value_entry.get("ValueName", "")
                value_data = value_entry.get("ValueData", "")
                val_lower = value_name.lower()

                if val_lower == "path":
                    task_path = str(value_data)
                elif val_lower == "uri":
                    uri = str(value_data)
                elif val_lower == "author":
                    author = str(value_data)

            if task_path or uri:
                db.upsert_task(
                    task_path=task_path or uri or task_guid,
                    os_short_name=os_info["short_name"],
                    task_name=task_path.split("\\")[-1] if task_path else task_guid,
                    uri=uri,
                    author=author,
                )
                count += 1

        except Exception as e:
            logger.debug(f"Error extracting task {task_guid}: {e}")

    return count


def extract_autoruns(json_data: dict, os_info: dict, db: KnownGoodDB, hive: str) -> int:
    """
    Extract autorun entries from registry JSON.

    Extracts from multiple persistence locations including:
    - Run/RunOnce keys
    - Winlogon Shell/Userinit
    - AppInit_DLLs
    - Boot Execute
    - Image File Execution Options
    - Explorer Shell Extensions
    """
    count = 0

    hive_prefix = "HKLM" if hive in ["SYSTEM", "SOFTWARE"] else "HKU"

    # Standard Run key paths
    run_paths = [
        ("ROOT\\Microsoft\\Windows\\CurrentVersion\\Run", "Run"),
        ("ROOT\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce"),
        ("ROOT\\Microsoft\\Windows\\CurrentVersion\\RunServices", "RunServices"),
        (
            "ROOT\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
            "RunServicesOnce",
        ),
        ("ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Run"),
        ("ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce"),
    ]

    # Additional persistence locations (HIGH priority)
    if hive == "SOFTWARE":
        # Winlogon persistence
        run_paths.extend(
            [
                ("ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Winlogon"),
            ]
        )
        # AppInit_DLLs (legacy but still abused)
        run_paths.extend(
            [
                ("ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "AppInit"),
            ]
        )
        # Image File Execution Options (debugger persistence)
        run_paths.extend(
            [
                (
                    "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                    "IFEO",
                ),
            ]
        )
        # Explorer extensions
        run_paths.extend(
            [
                (
                    "ROOT\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
                    "BHO",
                ),
                (
                    "ROOT\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
                    "ShellExecuteHooks",
                ),
                (
                    "ROOT\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
                    "ShellServiceObjectDelayLoad",
                ),
            ]
        )
        # Print Monitors
        run_paths.extend(
            [
                ("ROOT\\CurrentControlSet\\Control\\Print\\Monitors", "PrintMonitor"),
            ]
        )

    if hive == "SYSTEM":
        # Boot Execute
        run_paths.extend(
            [
                ("ROOT\\ControlSet001\\Control\\Session Manager", "BootExecute"),
            ]
        )
        # LSA packages (credential providers)
        run_paths.extend(
            [
                ("ROOT\\ControlSet001\\Control\\Lsa", "LSA"),
            ]
        )
        # Print Monitors (also in SYSTEM)
        run_paths.extend(
            [
                ("ROOT\\ControlSet001\\Control\\Print\\Monitors", "PrintMonitor"),
            ]
        )

    if hive == "NTUSER":
        # User shell folders
        run_paths.extend(
            [
                ("ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Run"),
                (
                    "ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "RunOnce",
                ),
                (
                    "ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                    "ShellFolders",
                ),
                (
                    "ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                    "UserShellFolders",
                ),
            ]
        )

    for run_path, autorun_type in run_paths:
        run_key = navigate_to_key(json_data, run_path)
        if not run_key:
            continue

        # Handle special cases that have subkeys instead of values
        if autorun_type in ["IFEO", "BHO", "PrintMonitor"]:
            # These have subkeys, each subkey is an entry
            subkeys = run_key.get("SubKeys", [])
            if isinstance(subkeys, list):
                for subkey in subkeys:
                    if not isinstance(subkey, dict):
                        continue
                    key_name = subkey.get("KeyName", "")
                    if key_name:
                        db.upsert_autorun(
                            hive=hive_prefix,
                            key_path=run_path.replace("ROOT\\", "") + "\\" + key_name,
                            os_short_name=os_info["short_name"],
                            value_name=None,
                            value_data_pattern=key_name,
                            autorun_type=autorun_type,
                        )
                        count += 1
            continue

        # Extract values
        values = run_key.get("Values", [])
        if not isinstance(values, list):
            continue

        for value_entry in values:
            if not isinstance(value_entry, dict):
                continue

            try:
                value_name = value_entry.get("ValueName", "")
                value_data = value_entry.get("ValueData", "")

                # Filter to relevant values for some types
                if autorun_type == "Winlogon":
                    # Only specific Winlogon values are persistence-relevant
                    if value_name.lower() not in [
                        "shell",
                        "userinit",
                        "taskman",
                        "system",
                        "vmapplet",
                    ]:
                        continue
                elif autorun_type == "AppInit":
                    if value_name.lower() not in ["appinit_dlls", "loadappinit_dlls"]:
                        continue
                elif autorun_type == "BootExecute":
                    if value_name.lower() != "bootexecute":
                        continue
                elif autorun_type == "LSA":
                    if value_name.lower() not in [
                        "authentication packages",
                        "notification packages",
                        "security packages",
                    ]:
                        continue

                db.upsert_autorun(
                    hive=hive_prefix,
                    key_path=run_path.replace("ROOT\\", ""),
                    os_short_name=os_info["short_name"],
                    value_name=value_name,
                    value_data_pattern=str(value_data),
                    autorun_type=autorun_type,
                )
                count += 1

            except Exception as e:
                logger.debug(f"Error extracting autorun {value_name}: {e}")

    return count


def process_json_file(
    json_path: Path, db: KnownGoodDB, os_info: dict
) -> dict[str, int]:
    """Process a single registry JSON file."""
    stats = {"services": 0, "tasks": 0, "autoruns": 0, "errors": 0}

    try:
        with open(json_path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON {json_path}: {e}")
        stats["errors"] = 1
        return stats
    except Exception as e:
        logger.error(f"Failed to read {json_path}: {e}")
        stats["errors"] = 1
        return stats

    hive_type = os_info["hive_type"].upper()

    if hive_type == "SYSTEM":
        stats["services"] = extract_services(data, os_info, db)
    elif hive_type == "SOFTWARE":
        stats["tasks"] = extract_tasks(data, os_info, db)
        stats["autoruns"] = extract_autoruns(data, os_info, db, "SOFTWARE")
    elif hive_type == "NTUSER":
        stats["autoruns"] = extract_autoruns(data, os_info, db, "NTUSER")

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Import registry extractions into known_good.db"
    )
    parser.add_argument("--limit", type=int, default=0, help="Limit files processed")
    parser.add_argument("--os-filter", type=str, help="Filter by OS pattern")
    parser.add_argument(
        "--dry-run", action="store_true", help="Don't write to database"
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--registry-dir", type=str, help="Custom directory with extracted JSON files"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    project_root = Path(__file__).parent.parent
    data_dir = project_root / "data"
    sources_dir = data_dir / "sources"

    # Check database
    db_path = data_dir / "known_good.db"
    if not db_path.exists():
        logger.error("known_good.db not found. Run: python scripts/init_databases.py")
        sys.exit(1)

    # Find JSON files
    custom_registry_dir = Path(args.registry_dir) if args.registry_dir else None
    json_files = find_registry_json_files(sources_dir, custom_registry_dir)
    all_files = json_files["system"] + json_files["software"] + json_files["ntuser"]

    if not all_files:
        logger.error("No registry JSON files found.")
        logger.error(
            "Clone: git clone https://github.com/AndrewRathbun/VanillaWindowsRegistryHives.git"
        )
        logger.error("Or extract RegistryHivesJSON.zip files and use --registry-dir")
        sys.exit(1)

    # Apply filters
    if args.os_filter:
        all_files = [f for f in all_files if args.os_filter.lower() in str(f).lower()]
        logger.info(f"Filtered to {len(all_files)} files")

    if args.limit > 0:
        all_files = all_files[: args.limit]
        logger.info(f"Limited to {len(all_files)} files")

    # Process files
    db = None if args.dry_run else KnownGoodDB(db_path)
    if db:
        db.connect()

    total_stats = {"services": 0, "tasks": 0, "autoruns": 0, "errors": 0, "files": 0}

    try:
        for i, json_path in enumerate(all_files):
            os_info = parse_os_from_json_path(json_path)

            logger.info(
                f"[{i + 1}/{len(all_files)}] {os_info['short_name']} - {os_info['hive_type']}"
            )

            if args.dry_run:
                logger.info("  (dry run - skipping)")
            else:
                stats = process_json_file(json_path, db, os_info)
                for key in stats:
                    total_stats[key] += stats[key]
                logger.info(
                    f"  Services: {stats['services']}, Tasks: {stats['tasks']}, Autoruns: {stats['autoruns']}"
                )

            total_stats["files"] += 1

    finally:
        if db:
            db.close()

    # Summary
    print("\n" + "=" * 60)
    print("REGISTRY EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"Files processed:  {total_stats['files']}")
    print(f"Services:         {total_stats['services']}")
    print(f"Tasks:            {total_stats['tasks']}")
    print(f"Autoruns:         {total_stats['autoruns']}")
    print(f"Errors:           {total_stats['errors']}")

    if not args.dry_run:
        db = KnownGoodDB(db_path)
        db.connect()
        final_stats = db.get_stats()
        db.close()
        print("\nFinal database stats:")
        print(f"  Services: {final_stats['services']}")
        print(f"  Tasks:    {final_stats['tasks']}")
        print(f"  Autoruns: {final_stats['autoruns']}")


if __name__ == "__main__":
    main()
