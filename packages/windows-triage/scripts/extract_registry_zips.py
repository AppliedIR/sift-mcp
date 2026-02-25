#!/usr/bin/env python3
"""
Extract RegistryHivesJSON.zip files from VanillaWindowsRegistryHives

This script extracts the JSON registry exports from their ZIP archives,
preparing them for import by import_registry_extractions.py.

The VanillaWindowsRegistryHives repository contains:
  - RegistryHives.zip (raw hive files - not needed)
  - RegistryHivesJSON.zip (KAPE/Registry Explorer exports - we need these)

After extraction, each OS version folder will contain:
  mout/KapeResearch/
    SYSTEM_ROOT.json
    SOFTWARE_ROOT.json
    NTUSER_ROOT.json
    SAM_ROOT.json
    SECURITY_ROOT.json
    DEFAULT.json
    etc.

Usage:
    python scripts/extract_registry_zips.py [options]

Options:
    --limit N         Only extract first N ZIPs (for testing)
    --os-filter X     Only extract files matching pattern
    --output-dir DIR  Extract to specific directory (default: in-place)
    --dry-run         List what would be extracted without extracting
"""

import argparse
import logging
import subprocess
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def find_registry_zips(sources_dir: Path, os_filter: str = None) -> list[Path]:
    """Find all RegistryHivesJSON.zip files."""
    registry_dir = sources_dir / "VanillaWindowsRegistryHives"

    if not registry_dir.exists():
        logger.error(f"VanillaWindowsRegistryHives not found at {registry_dir}")
        logger.error("Clone it first:")
        logger.error("  cd data/sources")
        logger.error(
            "  git clone https://github.com/AndrewRathbun/VanillaWindowsRegistryHives.git"
        )
        return []

    zips = list(registry_dir.rglob("RegistryHivesJSON.zip"))

    if os_filter:
        zips = [z for z in zips if os_filter.lower() in str(z).lower()]

    return sorted(zips)


def extract_zip(zip_path: Path, output_dir: Path = None) -> dict[str, int]:
    """
    Extract a single RegistryHivesJSON.zip file.

    Args:
        zip_path: Path to the ZIP file
        output_dir: Where to extract (default: same directory as ZIP)

    Returns:
        Stats dict with files extracted count
    """
    stats = {"extracted": 0, "skipped": 0, "errors": 0}

    if output_dir is None:
        output_dir = zip_path.parent

    # Check if already extracted (look for SYSTEM_ROOT.json)
    expected_json = output_dir / "mout" / "KapeResearch" / "SYSTEM_ROOT.json"
    if expected_json.exists():
        stats["skipped"] = 1
        return stats

    try:
        # Use unzip command (handles Windows backslash paths in ZIP)
        result = subprocess.run(
            ["unzip", "-o", "-q", str(zip_path), "-d", str(output_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Check if extraction succeeded (return code 0 or 1 with just warnings)
        # Return code 1 can mean "warnings but success" for unzip
        json_files = list((output_dir / "mout" / "KapeResearch").glob("*.json"))
        if json_files:
            stats["extracted"] = len(json_files)
        elif result.returncode != 0 and "warning" not in result.stderr.lower():
            logger.warning(f"unzip error for {zip_path.name}: {result.stderr}")
            stats["errors"] = 1

    except subprocess.TimeoutExpired:
        logger.error(f"Timeout extracting {zip_path}")
        stats["errors"] = 1
    except Exception as e:
        logger.error(f"Error extracting {zip_path}: {e}")
        stats["errors"] = 1

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Extract RegistryHivesJSON.zip files for import"
    )
    parser.add_argument("--limit", type=int, default=0, help="Limit ZIPs to extract")
    parser.add_argument(
        "--os-filter", type=str, help="Filter by OS pattern (e.g., 'W10')"
    )
    parser.add_argument("--output-dir", type=str, help="Extract to specific directory")
    parser.add_argument(
        "--dry-run", action="store_true", help="List ZIPs without extracting"
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    project_root = Path(__file__).parent.parent
    sources_dir = project_root / "data" / "sources"

    # Find ZIPs
    zips = find_registry_zips(sources_dir, args.os_filter)

    if not zips:
        logger.error("No RegistryHivesJSON.zip files found")
        sys.exit(1)

    logger.info(f"Found {len(zips)} RegistryHivesJSON.zip files")

    if args.limit > 0:
        zips = zips[: args.limit]
        logger.info(f"Limited to {len(zips)} files")

    if args.dry_run:
        print("\nZIP files that would be extracted:")
        for z in zips:
            # Get relative path from sources dir
            rel_path = z.relative_to(sources_dir / "VanillaWindowsRegistryHives")
            print(f"  {rel_path}")
        print(f"\nTotal: {len(zips)} files")
        return

    # Extract ZIPs
    total_stats = {"extracted": 0, "skipped": 0, "errors": 0, "total": 0}

    for i, zip_path in enumerate(zips):
        output_dir = Path(args.output_dir) if args.output_dir else None
        rel_path = zip_path.relative_to(sources_dir / "VanillaWindowsRegistryHives")

        logger.info(f"[{i + 1}/{len(zips)}] {rel_path}")

        stats = extract_zip(zip_path, output_dir)

        for key in ["extracted", "skipped", "errors"]:
            total_stats[key] += stats[key]
        total_stats["total"] += 1

        if stats["skipped"]:
            logger.debug("  Already extracted, skipping")
        elif stats["extracted"]:
            logger.debug(f"  Extracted {stats['extracted']} JSON files")
        elif stats["errors"]:
            logger.warning("  Failed to extract")

    # Summary
    print("\n" + "=" * 60)
    print("EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"Total ZIP files:  {total_stats['total']}")
    print(f"Newly extracted:  {total_stats['extracted']} JSON files")
    print(f"Already existed:  {total_stats['skipped']}")
    print(f"Errors:           {total_stats['errors']}")

    # Verify extraction worked
    if total_stats["extracted"] > 0 or total_stats["skipped"] > 0:
        json_count = len(
            list((sources_dir / "VanillaWindowsRegistryHives").rglob("*_ROOT.json"))
        )
        print(f"\nTotal *_ROOT.json files now available: {json_count}")


if __name__ == "__main__":
    main()
