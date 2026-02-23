#!/usr/bin/env python3
"""
Incremental Database Update Script

Self-contained script that updates baseline databases from upstream git sources.
Does NOT require source repos to be pre-cloned — clones what it needs into a
temp directory, imports only changed files, updates sync tracking, then cleans up.

Databases updated:
    known_good.db          - File baselines (VanillaWindowsReference)
    context.db             - LOLBins, drivers, hijackable DLLs
    known_good_registry.db - Full registry baseline (if it exists)

Design:
    1. Read last_sync_commit from each DB's sources table
    2. Query GitHub API for latest commit on each repo
    3. If changed: shallow clone, identify changed files, run selective import
    4. Update last_sync_commit in DB
    5. Clean up clones

Usage:
    python scripts/update_sources.py                # Update all databases
    python scripts/update_sources.py --check-only   # Just check for updates
    python scripts/update_sources.py --source files # Update specific source
    python scripts/update_sources.py --force        # Reimport everything
"""

import argparse
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================
# Source Definitions
# ============================================================

SOURCES = {
    'files': {
        'name': 'VanillaWindowsReference',
        'db': 'known_good.db',
        'db_source_key': 'vanilla_windows_reference',
        'repo': 'AndrewRathbun/VanillaWindowsReference',
        'url': 'https://github.com/AndrewRathbun/VanillaWindowsReference.git',
        'import_script': 'import_files.py',
        'file_glob': '*.csv',
        'description': 'Windows file baselines (~2.6M paths)',
    },
    'registry': {
        'name': 'VanillaWindowsRegistryHives',
        'db': 'known_good_registry.db',
        'db_source_key': 'vanilla_windows_registry',
        'repo': 'AndrewRathbun/VanillaWindowsRegistryHives',
        'url': 'https://github.com/AndrewRathbun/VanillaWindowsRegistryHives.git',
        'import_script': 'import_registry_full.py',
        'file_glob': '*_ROOT.json',
        'description': 'Full registry baseline (optional, 12GB)',
    },
    'registry_extractions': {
        'name': 'VanillaWindowsRegistryHives (extractions)',
        'db': 'known_good.db',
        'db_source_key': 'vanilla_windows_registry',
        'repo': 'AndrewRathbun/VanillaWindowsRegistryHives',
        'url': 'https://github.com/AndrewRathbun/VanillaWindowsRegistryHives.git',
        'import_script': 'import_registry_extractions.py',
        'file_glob': '*_ROOT.json',
        'description': 'Services, tasks, autoruns extracted from registry',
    },
    'lolbas': {
        'name': 'LOLBAS',
        'db': 'context.db',
        'db_source_key': 'lolbas',
        'repo': 'LOLBAS-Project/LOLBAS',
        'url': 'https://github.com/LOLBAS-Project/LOLBAS.git',
        'description': 'Living Off The Land Binaries',
    },
    'loldrivers': {
        'name': 'LOLDrivers',
        'db': 'context.db',
        'db_source_key': 'loldrivers_vulnerable',
        'repo': 'magicsword-io/LOLDrivers',
        'url': 'https://github.com/magicsword-io/LOLDrivers.git',
        'description': 'Vulnerable and malicious drivers',
    },
    'hijacklibs': {
        'name': 'HijackLibs',
        'db': 'context.db',
        'db_source_key': 'hijacklibs',
        'repo': 'wietze/HijackLibs',
        'url': 'https://github.com/wietze/HijackLibs.git',
        'description': 'DLL hijacking vulnerabilities',
    },
}


# ============================================================
# GitHub API Helpers
# ============================================================

def github_api_get(endpoint: str) -> Optional[dict]:
    """Make authenticated GitHub API request."""
    url = f"https://api.github.com/{endpoint}"
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        logger.debug(f"GitHub API error for {endpoint}: {e.code}")
        return None
    except Exception as e:
        logger.debug(f"GitHub API request failed: {e}")
        return None


def get_latest_commit(repo: str, branch: str = "main") -> Optional[str]:
    """Get latest commit SHA from GitHub API."""
    data = github_api_get(f"repos/{repo}/commits/{branch}")
    if data and 'sha' in data:
        return data['sha'][:40]
    # Try 'master' as fallback
    if branch == "main":
        data = github_api_get(f"repos/{repo}/commits/master")
        if data and 'sha' in data:
            return data['sha'][:40]
    return None


def get_changed_files(repo: str, base_commit: str, head_commit: str) -> List[str]:
    """Get list of changed files between two commits via GitHub API."""
    data = github_api_get(f"repos/{repo}/compare/{base_commit}...{head_commit}")
    if not data or 'files' not in data:
        return []
    return [f['filename'] for f in data['files']]


# ============================================================
# Database Helpers
# ============================================================

def get_last_sync(db_path: Path, source_key: str) -> Optional[str]:
    """Read last_sync_commit from a database's sources table."""
    if not db_path.exists():
        return None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.execute(
            "SELECT last_sync_commit FROM sources WHERE name = ?",
            (source_key,)
        )
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        return None


def set_last_sync(db_path: Path, source_key: str, commit: str, url: str = ""):
    """Write last_sync_commit to a database's sources table."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """UPDATE sources SET last_sync_commit = ?, last_sync_time = datetime('now')
           WHERE name = ?""",
        (commit, source_key)
    )
    # If no row was updated, insert one
    if conn.execute("SELECT changes()").fetchone()[0] == 0:
        conn.execute(
            """INSERT INTO sources (name, source_type, url, last_sync_commit, last_sync_time)
               VALUES (?, 'git', ?, ?, datetime('now'))""",
            (source_key, url, commit)
        )
    conn.commit()
    conn.close()


# ============================================================
# Clone & Import Helpers
# ============================================================

def extract_registry_zips(clone_dir: Path) -> int:
    """Extract RegistryHivesJSON.zip files in-place within a cloned repo."""
    extracted = 0
    for zip_path in clone_dir.rglob("RegistryHivesJSON.zip"):
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(zip_path.parent)
            extracted += 1
        except Exception as e:
            logger.warning(f"  Failed to extract {zip_path.name}: {e}")
    return extracted


def shallow_clone(url: str, dest: Path, depth: int = 1) -> bool:
    """Shallow clone a git repo."""
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", str(depth), url, str(dest)],
            capture_output=True, text=True, timeout=600
        )
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Clone failed: {e}")
        return False


def run_import(script_name: str, args: List[str], dry_run: bool = False) -> bool:
    """Run an import script with arguments."""
    scripts_dir = Path(__file__).parent
    script_path = scripts_dir / script_name

    if not script_path.exists():
        logger.error(f"Import script not found: {script_path}")
        return False

    cmd = [sys.executable, str(script_path)] + args

    if dry_run:
        logger.info(f"  Would run: {' '.join(cmd)}")
        return True

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=7200
        )
        if result.returncode != 0:
            logger.error(f"Import failed: {result.stderr[-500:]}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logger.error("Import timed out")
        return False
    except Exception as e:
        logger.error(f"Import error: {e}")
        return False


# ============================================================
# Source Update Functions
# ============================================================

def check_source(source_key: str, data_dir: Path) -> Dict:
    """Check if a source needs updating."""
    source = SOURCES[source_key]
    db_path = data_dir / source['db']

    status = {
        'key': source_key,
        'name': source['name'],
        'db': source['db'],
        'db_exists': db_path.exists(),
        'last_sync': None,
        'latest_commit': None,
        'needs_update': False,
        'changed_files': [],
        'skipped': False,
    }

    if not db_path.exists():
        status['skipped'] = True
        status['skip_reason'] = f"{source['db']} not found"
        return status

    status['last_sync'] = get_last_sync(db_path, source['db_source_key'])

    # Query GitHub for latest commit
    status['latest_commit'] = get_latest_commit(source['repo'])

    if not status['latest_commit']:
        logger.warning(f"  Could not fetch latest commit for {source['repo']}")
        status['skipped'] = True
        status['skip_reason'] = "GitHub API unavailable"
        return status

    if status['last_sync'] and status['last_sync'] == status['latest_commit']:
        status['needs_update'] = False
    else:
        status['needs_update'] = True
        # Get changed files if we have a previous sync point
        if status['last_sync']:
            status['changed_files'] = get_changed_files(
                source['repo'], status['last_sync'], status['latest_commit']
            )

    return status


def update_files(data_dir: Path, status: Dict, force: bool, dry_run: bool) -> bool:
    """Update known_good.db file baselines from VanillaWindowsReference."""
    source = SOURCES['files']
    db_path = data_dir / source['db']

    # Determine if we can do an incremental update
    changed_csvs = [f for f in status.get('changed_files', []) if f.endswith('.csv')]

    if not force and changed_csvs and status.get('last_sync'):
        # Incremental: clone and import only changed CSVs
        logger.info(f"  Incremental update: {len(changed_csvs)} changed CSVs")

        with tempfile.TemporaryDirectory() as tmp:
            clone_dir = Path(tmp) / "VanillaWindowsReference"
            logger.info("  Cloning repository (shallow)...")
            if not shallow_clone(source['url'], clone_dir):
                return False

            # Build full paths for changed CSVs
            csv_paths = []
            for csv_rel in changed_csvs:
                csv_path = clone_dir / csv_rel
                if csv_path.exists() and csv_path.stat().st_size > 1000:
                    csv_paths.append(str(csv_path))

            if not csv_paths:
                logger.info("  No actionable CSV changes")
                set_last_sync(db_path, source['db_source_key'], status['latest_commit'], source['url'])
                return True

            logger.info(f"  Importing {len(csv_paths)} changed CSVs...")
            import_args = ["--only-files"] + csv_paths
            import_args += ["--sync-commit", status['latest_commit']]
            return run_import(source['import_script'], import_args, dry_run)
    else:
        # Full import: clone everything
        logger.info("  Full import (no previous sync or --force)")

        with tempfile.TemporaryDirectory() as tmp:
            clone_dir = Path(tmp) / "VanillaWindowsReference"
            logger.info("  Cloning repository (shallow)...")
            if not shallow_clone(source['url'], clone_dir):
                return False

            # import_files.py expects sources_dir containing VanillaWindowsReference/
            import_args = ["--sources-dir", tmp]
            import_args += ["--sync-commit", status['latest_commit']]
            return run_import(source['import_script'], import_args, dry_run)


def update_registry(data_dir: Path, status: Dict, force: bool, dry_run: bool) -> bool:
    """Update known_good_registry.db from VanillaWindowsRegistryHives."""
    source = SOURCES['registry']
    db_path = data_dir / source['db']

    # Registry hive JSONs are inside zip files — always need extraction after clone
    changed_jsons = [f for f in status.get('changed_files', [])
                     if f.endswith('_ROOT.json') or f.endswith('.zip')]

    if not force and changed_jsons and status.get('last_sync'):
        logger.info(f"  Incremental update: {len(changed_jsons)} changed files")

    # Registry always needs full clone + extraction (zips contain the JSONs)
    logger.info("  Full clone + extraction required (JSONs are inside zips)")

    with tempfile.TemporaryDirectory() as tmp:
        clone_dir = Path(tmp) / "VanillaWindowsRegistryHives"
        logger.info("  Cloning repository (shallow)...")
        if not shallow_clone(source['url'], clone_dir):
            return False

        logger.info("  Extracting registry JSON from zip archives...")
        extracted = extract_registry_zips(clone_dir)
        logger.info(f"  Extracted {extracted} zip archives")

        import_args = ["--sources-dir", tmp]
        import_args += ["--sync-commit", status['latest_commit']]
        return run_import(source['import_script'], import_args, dry_run)


def update_registry_extractions(data_dir: Path, status: Dict, force: bool, dry_run: bool) -> bool:
    """Update services/tasks/autoruns in known_good.db from registry hives."""
    source = SOURCES['registry_extractions']
    db_path = data_dir / source['db']

    # Registry extractions always re-import fully — the extraction logic is complex
    # and the dataset is relatively small (thousands not millions)
    logger.info("  Full re-import of services/tasks/autoruns")

    with tempfile.TemporaryDirectory() as tmp:
        clone_dir = Path(tmp) / "VanillaWindowsRegistryHives"
        logger.info("  Cloning repository (shallow)...")
        if not shallow_clone(source['url'], clone_dir):
            return False

        logger.info("  Extracting registry JSON from zip archives...")
        extracted = extract_registry_zips(clone_dir)
        logger.info(f"  Extracted {extracted} zip archives")

        # import_registry_extractions.py accepts --registry-dir
        import_args = ["--registry-dir", str(clone_dir)]
        success = run_import(source['import_script'], import_args, dry_run)
        if success and not dry_run:
            set_last_sync(db_path, source['db_source_key'], status['latest_commit'], source['url'])
        return success


def _update_registry_with_clone(data_dir: Path, status: Dict,
                                shared_dir: str, force: bool, dry_run: bool) -> bool:
    """Update known_good_registry.db using an already-cloned and extracted registry repo."""
    source = SOURCES['registry']
    db_path = data_dir / source['db']

    import_args = ["--sources-dir", shared_dir]
    import_args += ["--sync-commit", status['latest_commit']]
    return run_import(source['import_script'], import_args, dry_run)


def _update_registry_extractions_with_clone(data_dir: Path, status: Dict,
                                            shared_dir: str, force: bool, dry_run: bool) -> bool:
    """Update services/tasks/autoruns in known_good.db using an already-cloned registry repo."""
    source = SOURCES['registry_extractions']
    db_path = data_dir / source['db']
    clone_dir = Path(shared_dir) / "VanillaWindowsRegistryHives"

    import_args = ["--registry-dir", str(clone_dir)]
    success = run_import(source['import_script'], import_args, dry_run)
    if success and not dry_run:
        set_last_sync(db_path, source['db_source_key'], status['latest_commit'], source['url'])
    return success


def update_context_source(source_key: str, data_dir: Path, status: Dict,
                          force: bool, dry_run: bool) -> bool:
    """Update a single context.db source (LOLBAS, LOLDrivers, or HijackLibs)."""
    source = SOURCES[source_key]
    db_path = data_dir / source['db']

    # Context sources are small — always do full re-import
    logger.info(f"  Full re-import of {source['name']}")

    with tempfile.TemporaryDirectory() as tmp:
        clone_dir = Path(tmp) / source['name']
        logger.info("  Cloning repository (shallow)...")
        if not shallow_clone(source['url'], clone_dir):
            return False

        # Call the appropriate importer directly via Python
        if dry_run:
            logger.info(f"  Would import from {clone_dir}")
            return True

        try:
            if source_key == 'lolbas':
                from windows_triage.importers import import_lolbas
                stats = import_lolbas(db_path=db_path, lolbas_dir=clone_dir)
                logger.info(f"  Imported {stats['lolbins_imported']} LOLBins")

            elif source_key == 'loldrivers':
                from windows_triage.importers import import_loldrivers
                stats = import_loldrivers(
                    db_path=db_path, loldrivers_dir=clone_dir,
                    include_malicious=True
                )
                logger.info(f"  Imported {stats['vulnerable_imported']} vulnerable, "
                            f"{stats['malicious_imported']} malicious drivers")

            elif source_key == 'hijacklibs':
                from windows_triage.importers import import_hijacklibs
                stats = import_hijacklibs(db_path=db_path, hijacklibs_dir=clone_dir)
                logger.info(f"  Imported {stats['entries_imported']} hijackable DLL entries")

            set_last_sync(db_path, source['db_source_key'], status['latest_commit'], source['url'])
            return True

        except Exception as e:
            logger.error(f"  Import failed: {e}")
            return False


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Incremental database update from upstream sources"
    )
    parser.add_argument("--source", type=str,
                        help=f"Only update specific source ({', '.join(SOURCES.keys())})")
    parser.add_argument("--force", action="store_true",
                        help="Ignore sync tracking, reimport everything")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without doing it")
    parser.add_argument("--check-only", action="store_true",
                        help="Just check for updates, don't apply")
    parser.add_argument("--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--list-sources", action="store_true",
                        help="List available sources")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list_sources:
        print("\nAvailable sources:")
        print("=" * 70)
        for key, source in SOURCES.items():
            print(f"  {key:25} {source['description']}")
        return

    project_root = Path(__file__).parent.parent
    data_dir = project_root / "data"

    # Determine which sources to check
    if args.source:
        if args.source not in SOURCES:
            logger.error(f"Unknown source: {args.source}")
            logger.error(f"Available: {', '.join(SOURCES.keys())}")
            sys.exit(1)
        sources_to_check = [args.source]
    else:
        sources_to_check = list(SOURCES.keys())

    # ── Check Status ──────────────────────────────────────────

    print("\n" + "=" * 70)
    print("DATABASE UPDATE STATUS")
    print("=" * 70)

    # Deduplicate GitHub API calls for sources sharing the same repo
    _repo_commit_cache = {}

    statuses = {}
    for source_key in sources_to_check:
        repo = SOURCES[source_key]['repo']
        if repo in _repo_commit_cache:
            # Reuse cached commit for same repo
            status = check_source(source_key, data_dir)
            status['latest_commit'] = _repo_commit_cache[repo]
            if status.get('last_sync') and status['last_sync'] == status['latest_commit']:
                status['needs_update'] = False
            elif not status.get('skipped'):
                status['needs_update'] = True
        else:
            status = check_source(source_key, data_dir)
            if status.get('latest_commit'):
                _repo_commit_cache[repo] = status['latest_commit']

        statuses[source_key] = status

        if status.get('skipped'):
            icon = "⊘"
            label = status.get('skip_reason', 'skipped')
        elif status['needs_update']:
            icon = "●"
            changed = len(status.get('changed_files', []))
            label = f"UPDATE AVAILABLE ({changed} files changed)" if changed else "UPDATE AVAILABLE"
        else:
            icon = "✓"
            label = "up to date"

        sync_info = f" [{status['last_sync'][:8]}]" if status.get('last_sync') else ""
        print(f"  {icon} {status['name']:40} {label}{sync_info}")

    if args.check_only:
        needs = sum(1 for s in statuses.values() if s['needs_update'])
        skipped = sum(1 for s in statuses.values() if s['skipped'])
        print(f"\n{needs} source(s) need updating, {skipped} skipped")
        return

    # ── Run Updates ───────────────────────────────────────────

    needs_update = {k: v for k, v in statuses.items()
                    if v['needs_update'] or args.force}

    if not needs_update:
        print("\nAll databases are up to date.")
        return

    print("\n" + "=" * 70)
    print("RUNNING UPDATES")
    print("=" * 70)

    results = {}

    # Share clone directory for registry sources that use the same repo
    _shared_registry_dir = None

    for source_key, status in needs_update.items():
        if status.get('skipped'):
            continue

        print(f"\n── {SOURCES[source_key]['name']} ──")

        try:
            if source_key == 'files':
                success = update_files(data_dir, status, args.force, args.dry_run)
            elif source_key in ('registry', 'registry_extractions'):
                # Share clone between registry and registry_extractions
                if _shared_registry_dir is None:
                    _shared_registry_dir = tempfile.mkdtemp()
                    clone_dir = Path(_shared_registry_dir) / "VanillaWindowsRegistryHives"
                    logger.info("  Cloning VanillaWindowsRegistryHives (shared)...")
                    if not shallow_clone(SOURCES['registry']['url'], clone_dir):
                        logger.error("  Clone failed")
                        results[source_key] = False
                        continue
                    logger.info("  Extracting registry JSON from zip archives...")
                    extracted = extract_registry_zips(clone_dir)
                    logger.info(f"  Extracted {extracted} zip archives")

                if source_key == 'registry':
                    success = _update_registry_with_clone(
                        data_dir, status, _shared_registry_dir, args.force, args.dry_run)
                else:
                    success = _update_registry_extractions_with_clone(
                        data_dir, status, _shared_registry_dir, args.force, args.dry_run)
            elif source_key in ('lolbas', 'loldrivers', 'hijacklibs'):
                success = update_context_source(source_key, data_dir, status, args.force, args.dry_run)
            else:
                logger.warning(f"  No update handler for {source_key}")
                success = False

            results[source_key] = success

        except Exception as e:
            logger.error(f"  Error updating {source_key}: {e}")
            results[source_key] = False

    # Clean up shared clone
    if _shared_registry_dir:
        shutil.rmtree(_shared_registry_dir, ignore_errors=True)

    # ── Summary ───────────────────────────────────────────────

    print("\n" + "=" * 70)
    print("UPDATE SUMMARY")
    print("=" * 70)

    succeeded = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)

    for source_key, success in results.items():
        icon = "✓" if success else "✗"
        print(f"  {icon} {SOURCES[source_key]['name']}")

    print(f"\n  {succeeded} succeeded, {failed} failed")

    if args.dry_run:
        print("  (dry run — no changes made)")

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
