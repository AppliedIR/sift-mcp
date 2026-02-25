#!/usr/bin/env python3
"""
Import All Data Sources (v2 Orchestrator)

This script runs all import scripts in the correct order to fully populate
the forensic triage databases.

Databases Populated:
    known_good.db  - File baselines, services, tasks, autoruns
    context.db     - LOLBins, drivers, DLLs, process rules

Data Sources:
    VanillaWindowsReference    -> known_good.db (files, hashes)
    VanillaWindowsRegistryHives -> known_good.db (services, tasks, autoruns)
    LOLBAS                     -> context.db (LOLBins)
    LOLDrivers                 -> context.db (vulnerable drivers)
    HijackLibs                 -> context.db (DLL hijacking)

Prerequisites:
    1. Run init_databases.py first
    2. Clone data sources:
       cd data/sources
       git clone https://github.com/AndrewRathbun/VanillaWindowsReference.git
       git clone https://github.com/AndrewRathbun/VanillaWindowsRegistryHives.git
       git clone https://github.com/LOLBAS-Project/LOLBAS.git
       git clone https://github.com/magicsword-io/LOLDrivers.git
       git clone https://github.com/wietze/HijackLibs.git

Usage:
    python scripts/import_all.py [options]

Options:
    --skip-files      Skip VanillaWindowsReference file import
    --skip-registry   Skip VanillaWindowsRegistryHives extraction
    --skip-context    Skip context.db imports (LOLBins, etc.)
    --files-limit N   Limit number of file CSVs to process
    --verbose         Show detailed output
"""

import argparse
import subprocess
import sys
from pathlib import Path


def run_script(script_name: str, args: list = None, description: str = None):
    """Run a Python script and report results."""
    scripts_dir = Path(__file__).parent
    script_path = scripts_dir / script_name

    if not script_path.exists():
        print(f"ERROR: Script not found: {script_path}")
        return False

    cmd = [sys.executable, str(script_path)]
    if args:
        cmd.extend(args)

    print(f"\n{'=' * 60}")
    print(f"Running: {description or script_name}")
    print(f"{'=' * 60}")

    result = subprocess.run(cmd)
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description="Import all data sources into forensic triage databases"
    )
    parser.add_argument(
        "--skip-files",
        action="store_true",
        help="Skip VanillaWindowsReference file import",
    )
    parser.add_argument(
        "--skip-registry",
        action="store_true",
        help="Skip registry extractions (services/tasks/autoruns)",
    )
    parser.add_argument(
        "--skip-context", action="store_true", help="Skip context.db imports"
    )
    parser.add_argument(
        "--files-limit",
        type=int,
        default=0,
        help="Limit number of file CSVs to process",
    )
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    data_dir = project_root / "data"
    sources_dir = data_dir / "sources"

    # Check databases exist
    if not (data_dir / "known_good.db").exists():
        print("ERROR: known_good.db not found.")
        print("Run: python scripts/init_databases.py")
        sys.exit(1)

    if not (data_dir / "context.db").exists():
        print("ERROR: context.db not found.")
        print("Run: python scripts/init_databases.py")
        sys.exit(1)

    results = {}

    # Import context.db first (fastest)
    if not args.skip_context:
        extra_args = ["--verbose"] if args.verbose else []
        success = run_script(
            "import_context.py",
            extra_args,
            "Importing context.db (LOLBins, drivers, DLLs, process rules)",
        )
        results["context"] = success

    # Import VanillaWindowsReference files
    if not args.skip_files:
        extra_args = []
        if args.files_limit > 0:
            extra_args.extend(["--limit", str(args.files_limit)])
        if args.verbose:
            extra_args.append("--verbose")

        success = run_script(
            "import_files.py",
            extra_args,
            "Importing VanillaWindowsReference files (this may take a while)",
        )
        results["files"] = success

    # Import registry extractions
    if not args.skip_registry:
        # Auto-extract ZIPs if needed
        skip_registry = False
        registry_dir = sources_dir / "VanillaWindowsRegistryHives"
        if registry_dir.exists():
            zips = list(registry_dir.rglob("RegistryHivesJSON.zip"))
            jsons = list(registry_dir.rglob("*_ROOT.json"))
            if zips and not jsons:
                if not run_script(
                    "extract_registry_zips.py", [], "Extracting registry ZIPs"
                ):
                    print(
                        "WARNING: Registry ZIP extraction failed, skipping registry import"
                    )
                    results["registry"] = False
                    skip_registry = True

        if not skip_registry:
            extra_args = ["--verbose"] if args.verbose else []
            success = run_script(
                "import_registry_extractions.py",
                extra_args,
                "Extracting services/tasks/autoruns from VanillaWindowsRegistryHives",
            )
            results["registry"] = success

    # Summary
    print("\n" + "=" * 60)
    print("IMPORT ALL - SUMMARY")
    print("=" * 60)

    all_success = True
    for name, success in results.items():
        status = "SUCCESS" if success else "FAILED"
        print(f"  {name}: {status}")
        if not success:
            all_success = False

    # Show database sizes
    print("\nDatabase sizes:")
    for db_name in ["known_good.db", "context.db"]:
        db_path = data_dir / db_name
        if db_path.exists():
            size_mb = db_path.stat().st_size / (1024 * 1024)
            print(f"  {db_name}: {size_mb:.1f} MB")

    # Show optional registry note
    registry_db = data_dir / "known_good_registry.db"
    if not registry_db.exists():
        print("\nOptional: Full registry baseline not installed.")
        print("  To enable deep registry validation, run:")
        print("    python scripts/init_registry_db.py")
        print("    python scripts/import_registry_full.py")

    if all_success:
        print("\nAll imports completed successfully!")
    else:
        print("\nSome imports failed. Check output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
