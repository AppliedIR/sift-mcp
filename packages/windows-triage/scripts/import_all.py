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
    With --fetch, none: it clones every source itself.
    Without it, run init_databases.py first, with the sources already cloned
    under data/sources/.

Usage:
    python scripts/import_all.py [options]

Options:
    --fetch           Clone each source and build its DBs in a temp dir; the
                      clones, their licences and the DBs replace those in data/
                      only when every step passes
    --skip-files      Skip VanillaWindowsReference file import
    --skip-registry   Skip VanillaWindowsRegistryHives extraction
    --skip-context    Skip context.db imports (LOLBins, etc.)
    --files-limit N   Limit number of file CSVs to process
    --verbose         Show detailed output
"""

import argparse
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extract_registry_zips
import update_sources
from windows_triage import release_manifest
from windows_triage.db.schemas import (
    CONTEXT_INITIAL_DATA,
    CONTEXT_SCHEMA,
    KNOWN_GOOD_SCHEMA,
    REGISTRY_FULL_SCHEMA,
)

# --fetch: the SOURCES keys each --skip-* option leaves out; any other key is fetched
FETCH_SKIPS = {
    "skip_files": {"files"},
    "skip_registry": {"registry", "registry_extractions"},
    "skip_context": {"lolbas", "loldrivers", "hijacklibs"},
}
CONTEXT_KEYS = ("lolbas", "loldrivers", "hijacklibs")
IMPORTERS = {  # SOURCES key: the script that imports its clone, in run order
    "files": "import_files.py",
    "registry_extractions": "import_registry_extractions.py",
    "registry": "import_registry_full.py",
}
# Each DB as init_databases.py and init_registry_db.py create it
DB_SCHEMAS = {
    "known_good.db": KNOWN_GOOD_SCHEMA,
    "context.db": CONTEXT_SCHEMA + CONTEXT_INITIAL_DATA,
    "known_good_registry.db": REGISTRY_FULL_SCHEMA,
}
LICENCE_NAME = re.compile(r"(LICEN[CS]E|NOTICE|COPYING)", re.I)


class FetchError(Exception):
    """A --fetch step failed; each arg is one line saying what failed."""


class KeptError(FetchError):
    """The install into data/ failed and could not be undone; work/ is kept."""


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
    print(f"{'=' * 60}", flush=True)

    result = subprocess.run(cmd)
    return result.returncode == 0


def _clone(url: str, dest: Path, timeout: int, log: Path) -> str:
    """Clone url into dest within timeout seconds; returns the clone's head."""
    print(f"Cloning {url}", flush=True)
    with open(log, "w") as out:
        try:
            proc = subprocess.Popen(
                ["git", "clone", "--depth", "1", url, str(dest)],
                stdout=out,
                stderr=subprocess.STDOUT,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            )
        except OSError as e:
            raise FetchError(f"{dest.name}: git could not run: {e}") from None
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise FetchError(
                f"{dest.name}: the clone of {url} took over {timeout} s"
            ) from None
    if rc != 0:
        tail = log.read_text(errors="replace").strip().splitlines()[-3:]
        raise FetchError(f"{dest.name}: the clone of {url} failed (exit {rc})", *tail)
    head = update_sources.clone_head(dest)
    if head is None:
        raise FetchError(f"{dest.name}: the clone of {url} has no HEAD commit")
    return head


def _copy_licences(clone: Path, dest: Path) -> None:
    """Copy the licence files at the clone's root; none, or one over the
    size cap, is an error."""
    found = [
        p
        for p in sorted(clone.iterdir())
        if LICENCE_NAME.match(p.name) and not p.is_symlink() and p.is_file()
    ]
    cap = release_manifest.LICENCE_FILE_MAX
    oversized = [
        f"{clone.name}: licence file {p.name} is {p.stat().st_size} bytes,"
        f" over the {cap}-byte cap"
        for p in found
        if p.stat().st_size > cap
    ]
    if oversized:
        raise FetchError(*oversized)
    if not found:
        raise FetchError(f"{clone.name}: no licence file at the clone's root")
    dest.mkdir(parents=True)
    for p in found:
        shutil.copyfile(p, dest / p.name)


def _extract_zips(src: Path) -> None:
    """Extract the registry clone's JSON zips, as the import scripts read them."""
    registry = src / "VanillaWindowsRegistryHives"
    zips = sorted(registry.rglob("RegistryHivesJSON.zip")) if registry.is_dir() else []
    if not zips or any(registry.rglob("*_ROOT.json")):
        return
    bad = [z for z in zips if extract_registry_zips.extract_zip(z)["errors"]]
    if bad:
        raise FetchError(
            *(f"{z.relative_to(src)}: could not be extracted" for z in bad)
        )


def _prepare_db(name: str, existing: Path, path: Path, complete: bool) -> None:
    """A DB every source of which is fetched starts empty; any other starts as
    a copy of the installed one, so the sources not fetched keep their rows."""
    if not complete and existing.exists():
        source, copy = sqlite3.connect(existing), sqlite3.connect(path)
        try:
            source.backup(copy)
        finally:
            copy.close()
            source.close()
        return
    conn = sqlite3.connect(path)
    try:
        conn.executescript(DB_SCHEMAS[name])
    finally:
        conn.close()


def _plan(selected: set, heads: dict, args, work: Path) -> list:
    """Each import to run: (script, its args, description)."""
    sources = update_sources.SOURCES
    clone_dir = update_sources.clone_dir
    common = ["--sources-dir", str(work / "src")]
    if args.verbose:
        common.append("--verbose")
    plan = []
    context = [clone_dir(sources[k]) for k in CONTEXT_KEYS if k in selected]
    if context:
        commits = [a for d in context for a in ("--sync-commit", f"{d}={heads[d]}")]
        script_args = ["--db", str(work / "db" / "context.db"), *commits, *common]
        plan.append(("import_context.py", script_args, "Importing context.db"))
    for key, script in IMPORTERS.items():
        if key not in selected:
            continue
        entry = sources[key]
        script_args = ["--db", str(work / "db" / entry["db"])]
        script_args += ["--sync-commit", heads[clone_dir(entry)], *common]
        if key == "files" and args.files_limit > 0:
            script_args += ["--limit", str(args.files_limit)]
        plan.append((script, script_args, f"Importing {entry['name']} ({key})"))
    return plan


def _install(work: Path, data_dir: Path, dirs, dbs) -> None:
    """Move each clone, its licences and each built DB into data/, each old one
    into work/. A failed move undoes every move made; a failed undo raises
    KeptError, with the old files left in work/."""
    places = (
        (data_dir / "sources", work / "src", work / "old"),
        (
            data_dir / release_manifest.LICENCE_DIR,
            work / "licenses",
            work / "old-licenses",
        ),
    )
    done = []  # (from, to) for each move made, in order; from None: a dir made

    def move(src: Path, dst: Path) -> None:
        os.replace(src, dst)
        done.append((src, dst))

    try:
        for base, new, old in places:
            if not base.is_dir():
                base.mkdir()
                done.append((None, base))
            old.mkdir()
            for d in dirs:
                if (base / d).exists() or (base / d).is_symlink():
                    move(base / d, old / d)
                move(new / d, base / d)
        for name in dbs:
            for side in (data_dir / f"{name}-wal", data_dir / f"{name}-shm"):
                if side.exists():  # an old DB's journal must not meet the new DB
                    move(side, work / "old" / side.name)
            if (data_dir / name).exists():
                move(data_dir / name, work / "old" / name)
            move(work / "db" / name, data_dir / name)
    except OSError as e:
        failed = f"installing into data/ failed: {e}"
        try:
            for src, dst in reversed(done):
                if src is None:
                    dst.rmdir()
                else:
                    os.replace(dst, src)
        except OSError as undo:
            raise KeptError(
                failed,
                f"undoing it failed too: {undo}",
                f"The files it replaced are kept in {work}",
                "data/ may be partly changed",
            ) from e
        raise FetchError(failed) from e


def fetch(args, data_dir: Path) -> None:
    """Clone, import and floor-check in a temp dir under data/sources, then
    install; raises FetchError, with data/ unchanged, when any step fails, or
    KeptError, with work/ kept, when a failed install could not be undone."""
    sources = update_sources.SOURCES
    skipped = set()
    for option, keys in FETCH_SKIPS.items():
        if getattr(args, option):
            skipped |= keys
    selected = {k for k in sources if k not in skipped}
    dirs: dict[str, tuple[str, int]] = {}  # clone dir: (url, clone timeout)
    for key in sources:
        if key in selected:
            entry = sources[key]
            clone = update_sources.clone_dir(entry)
            url, timeout = dirs.get(clone, (entry["url"], 0))
            dirs[clone] = (url, max(timeout, entry["clone_timeout"]))
    imported = [k for k in selected if k in IMPORTERS or k in CONTEXT_KEYS]
    dbs = sorted({sources[k]["db"] for k in imported})
    complete = {
        db
        for db in dbs
        if all(k in selected for k in sources if sources[k]["db"] == db)
    }

    (data_dir / "sources").mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".fetch-", dir=data_dir / "sources"))
    kept = False
    try:
        for sub in ("src", "licenses", "db"):
            (work / sub).mkdir()
        heads = {}
        for d, (url, timeout) in dirs.items():
            heads[d] = _clone(url, work / "src" / d, timeout, work / f"{d}.log")
            _copy_licences(work / "src" / d, work / "licenses" / d)
        _extract_zips(work / "src")
        for name in dbs:
            _prepare_db(name, data_dir / name, work / "db" / name, name in complete)
        for script, script_args, description in _plan(selected, heads, args, work):
            if not run_script(script, script_args, description):
                raise FetchError(f"{script} failed: see its output above")
        errors = []
        for name in dbs:
            tables = None  # every source of the DB fetched: every table floored
            if name not in complete:
                fed = release_manifest.FED_BY[name]
                tables = [t for k in sorted(selected) if k in fed for t in fed[k]]
            errors += release_manifest.check_floors(name, work / "db" / name, tables)
        if errors:
            raise FetchError(*errors)
        try:
            _install(work, data_dir, dirs, dbs)
        except KeptError:
            kept = True
            raise
    finally:
        if not kept:
            shutil.rmtree(work, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(
        description="Import all data sources into forensic triage databases"
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Clone and build every source in a temp dir; install only if all pass",
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

    if args.fetch:
        try:
            fetch(args, data_dir)
        except FetchError as e:
            for line in e.args:
                print(f"ERROR: {line}")
            if not isinstance(e, KeptError):
                print("Nothing in data/ was changed.")
            sys.exit(1)
        _summary({"fetch": True}, data_dir)
        return

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

    _summary(results, data_dir)


def _summary(results: dict, data_dir: Path) -> None:
    """Print each step's result and the DB sizes; exit 1 when a step failed."""
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
    for db_name in release_manifest.DATABASES:
        db_path = data_dir / db_name
        if db_path.exists():
            size_mb = db_path.stat().st_size / (1024 * 1024)
            print(f"  {db_name}: {size_mb:.1f} MB")

    # Show optional registry note
    registry_db = data_dir / "known_good_registry.db"
    if not registry_db.exists():
        print("\nOptional: Full registry baseline not installed.")
        print("  To build it with the other DBs from their sources, run:")
        print("    python scripts/import_all.py --fetch")

    if all_success:
        print("\nAll imports completed successfully!")
    else:
        print("\nSome imports failed. Check output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
