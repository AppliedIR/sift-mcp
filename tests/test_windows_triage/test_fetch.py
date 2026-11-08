"""``import_all.py --fetch``: one clone per URL from ``update_sources.SOURCES``.

Every upstream is a local fixture bare repo reached through ``git url.insteadOf`` in
an isolated HOME. The run uses a PATH-shim ``git`` that logs each call and runs the
real git, or, for the one URL a case names, writes a partial file into the clone's
destination and sleeps (a hanging clone). Each run is ``main()`` of a copy of the
scripts dir with its data dir beside it, started by a wrapper process that merges
the case's entries into ``SOURCES`` first (the timeout cases patch a source's
``clone_timeout`` to 2 s there, so they are unit-level, in the run's own process).
The fixture DBs hold a few rows, so a sitecustomize on PYTHONPATH sets the
manifest's expected counts to 0 in every Python the run starts: each floor is 0.
"""

from __future__ import annotations

import collections
import hashlib
import importlib.util
import itertools
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from .test_build_release_checks import SHIM
from .test_context_import_failures import GOOD
from .test_context_imports_keep_rows import HIJACKLIBS
from .test_sync_commits import HIVE, OS_A
from .test_update_check import SCHEMAS, _git, _remote

SCRIPTS = Path(__file__).resolve().parents[2] / "packages/windows-triage/scripts"
_loads = itertools.count()
WRAPPER = textwrap.dedent(
    """
    import importlib.util
    import json
    import os
    import sys
    from pathlib import Path

    script = Path(sys.argv[1])
    sys.path.insert(0, str(script.parent))
    import update_sources

    with open(os.environ["FETCH_TEST_SOURCES"]) as f:
        for key, fields in json.load(f).items():
            update_sources.SOURCES.setdefault(key, {}).update(fields)
    spec = importlib.util.spec_from_file_location("import_all", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sys.argv = [str(script), *sys.argv[2:]]
    mod.main()
    """
)
GIT_SHIM = textwrap.dedent(
    """\
    #!/bin/bash
    printf '%s\\n' "$*" >> "$GIT_SHIM_LOG"
    if [[ -n "$GIT_SHIM_HANG" && " $* " == *" clone "* && "$*" == *"$GIT_SHIM_HANG"* ]]
    then
        dest="${@: -1}"
        mkdir -p "$dest"
        echo partial > "$dest/partial"
        touch "$GIT_SHIM_MARK"
        exec sleep 60
    fi
    exec "$GIT_SHIM_REAL" "$@"
    """
)
CSV_PATH = f"Windows10/1507/{OS_A}/FileHashes.csv"
CSV = "FullName,Name,DirectoryName,Length,MD5,SHA1,SHA256\n" + "".join(
    f"C:\\Windows\\System32\\fixture{i:02}.dll,fixture{i:02}.dll,"
    f"C:\\Windows\\System32,{1000 + i},{i:032x},{i:040x},{i:064x}\n"
    for i in range(20)
)
DATA_FILES = {"sources", "licenses", *SCHEMAS}
NO_LICENCE = {
    "nolicence": {
        "name": "NoLicence",
        "db": "context.db",
        "db_source_key": "nolicence",
        "repo": "fixture-owner/NoLicence",
        "url": "https://github.com/fixture-owner/NoLicence.git",
        "clone_timeout": 600,
        "description": "A fixture source with no licence file",
    }
}


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(f"us_{next(_loads)}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SOURCES = _load(SCRIPTS / "update_sources.py").SOURCES


def _dir(entry: dict) -> str:
    """The clone dir an entry's URL goes to: its repo's name."""
    return entry["repo"].split("/")[1]


DIRS = sorted({_dir(e) for e in SOURCES.values()})
URLS = sorted({e["url"] for e in SOURCES.values()})
REGISTRY_URL = SOURCES["registry"]["url"]


def _files(name: str) -> dict[str, str]:
    """The fixture files of each upstream, a licence at the root of each."""
    licence = {"LICENSE": f"Fixture licence for {name}\n"}
    if name == "VanillaWindowsReference":
        return {**licence, CSV_PATH: CSV}
    if name == "VanillaWindowsRegistryHives":
        path = f"{OS_A}/mout/KapeResearch/SYSTEM_ROOT.json"
        return {**licence, path: json.dumps(HIVE)}
    if name in ("LOLBAS", "LOLDrivers"):
        folder, file_name, text, _ = GOOD[name.lower()]
        return {**licence, f"{folder}/{file_name}": text}
    if name == "HijackLibs":
        return {**licence, **{f"yml/{k}": v for k, v in HIJACKLIBS.items()}}
    return {"README": f"{name}\n"}


@pytest.fixture
def home(tmp_path, monkeypatch):
    """An isolated HOME whose .gitconfig holds the case's insteadOf lines."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    return home


def _upstreams(tmp: Path, home: Path, unreachable: str = "", extra=()) -> dict:
    """A fixture remote per URL (``unreachable`` points at a path that does not
    exist), plus one per entry in ``extra``; returns each clone dir's head."""
    heads = {}
    entries = [*{_dir(e): e for e in SOURCES.values()}.values(), *extra]
    for entry in entries:
        name = _dir(entry)
        if name == unreachable:
            with open(home / ".gitconfig", "a", encoding="utf-8") as f:
                f.write(
                    f'[url "{tmp / "nowhere" / name}"]\n'
                    f"\tinsteadOf = https://github.com/{entry['repo']}\n"
                )
            continue
        heads[name] = _remote(tmp, home, entry["repo"], "main", _files(name))
    return heads


def _advance(tmp: Path, name: str) -> str:
    """A second commit on a fixture remote; returns its head."""
    work = tmp / "work" / name
    (work / "SECOND").write_text("second commit\n", encoding="utf-8")
    _git("add", "-A", cwd=work)
    _git("-c", "user.name=f", "-c", "user.email=f@f", "commit", "-qm", "2", cwd=work)
    _git("push", "-q", str(tmp / "remotes" / f"{name}.git"), "HEAD:main", cwd=work)
    return _git("rev-parse", "HEAD", cwd=work)


def _tree(tmp: Path) -> Path:
    root = tmp / "tree"
    shutil.copytree(SCRIPTS, root / "scripts")
    (root / "data" / "sources").mkdir(parents=True)
    return root


def _old_clone(root: Path, name: str) -> Path:
    """data/sources/<name> as a clone of the fixture's head now, with a file the
    fixture never had."""
    url = next(e["url"] for e in SOURCES.values() if _dir(e) == name)
    dest = root / "data" / "sources" / name
    _git("clone", "-q", url, str(dest))
    (dest / "stale-file").write_text("from the old dir\n", encoding="utf-8")
    return dest


def _plant_dbs(root: Path) -> dict[str, str]:
    """Every DB, empty, in data/; returns each one's sha256."""
    for db, schema in SCHEMAS.items():
        conn = sqlite3.connect(root / "data" / db)
        conn.executescript(schema)
        conn.close()
    return _db_shas(root)


def _db_shas(root: Path) -> dict[str, str]:
    data = root / "data"
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(data.glob("*.db"))
    }


def _zero_counts() -> dict[str, dict[str, int]]:
    counts = {}
    for db, schema in SCHEMAS.items():
        conn = sqlite3.connect(":memory:")
        conn.executescript(schema)
        query = "SELECT name FROM sqlite_master WHERE type='table'"
        names = [r[0] for r in conn.execute(query)]
        conn.close()
        counts[db] = {
            n: 0 for n in names if n != "sources" and not n.startswith("sqlite_")
        }
    return counts


def _env(tmp: Path, sources: dict, hang: str) -> dict[str, str]:
    shim = tmp / "pyshim"
    if not shim.exists():
        shim.mkdir()
        (shim / "sitecustomize.py").write_text(SHIM)
        (tmp / "counts.json").write_text(json.dumps(_zero_counts()))
        (tmp / "wrapper.py").write_text(WRAPPER)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "git").write_text(GIT_SHIM)
        (bin_dir / "git").chmod(0o755)
    (tmp / "sources.json").write_text(json.dumps(sources))
    path = os.pathsep.join(
        [str(tmp / "bin"), str(Path(sys.executable).parent), os.environ["PATH"]]
    )
    return {
        **os.environ,
        "PATH": path,
        "PYTHONPATH": str(shim),
        "TRIAGE_TEST_COUNTS": str(tmp / "counts.json"),
        "FETCH_TEST_SOURCES": str(tmp / "sources.json"),
        "GIT_SHIM_LOG": str(tmp / "git.log"),
        "GIT_SHIM_REAL": shutil.which("git"),
        "GIT_SHIM_HANG": hang,
        "GIT_SHIM_MARK": str(tmp / "hang.mark"),
    }


def _command(tmp: Path, root: Path, args) -> list[str]:
    script = root / "scripts" / "import_all.py"
    return [sys.executable, str(tmp / "wrapper.py"), str(script), "--fetch", *args]


def _fetch(tmp: Path, root: Path, *args: str, sources=None, hang: str = ""):
    env = _env(tmp, sources or {}, hang)
    return subprocess.run(
        _command(tmp, root, args),
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


def _out(run) -> str:
    return run.stdout + run.stderr


def _tail(run) -> str:
    return f"rc {run.returncode}: {run.stdout[-2000:]} {run.stderr[-2000:]}"


def _clones(tmp: Path) -> collections.Counter:
    """The URLs the shim saw cloned, each with its count."""
    log = tmp / "git.log"
    lines = log.read_text().splitlines() if log.exists() else []
    urls = collections.Counter()
    for line in lines:
        words = line.split()
        if "clone" in words:
            urls.update(w for w in words if w.startswith("https://"))
    return urls


def _head(path: Path) -> str | None:
    """The clone's head, or None when there is no clone there."""
    if not path.is_dir():
        return None
    run = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return run.stdout.strip() if run.returncode == 0 else None


def _left_over(root: Path) -> list[str]:
    """Entries in data/ and data/sources/ that are not a DB, a clone or licences."""
    data = root / "data"
    extra = [
        p.name
        for p in data.iterdir()
        if p.name.removesuffix("-wal").removesuffix("-shm") not in DATA_FILES
    ]
    sources = data / "sources"
    extra += [f"sources/{p.name}" for p in sources.iterdir() if p.name not in DIRS]
    return sorted(extra)


def _errors_naming(run, name: str) -> list[str]:
    return [
        line
        for line in _out(run).splitlines()
        if line.startswith("ERROR:") and name in line
    ]


# --- one clone per URL, each clone at the fixture's head ---------------------


def test_the_stated_clone_timeouts():
    timeouts = {key: entry.get("clone_timeout") for key, entry in SOURCES.items()}
    want = {key: 600 for key in SOURCES}
    want.update(registry=7200, registry_extractions=7200)
    assert timeouts == want


def test_a_fetch_clones_each_url_once(tmp_path, home):
    _upstreams(tmp_path, home)
    run = _fetch(tmp_path, _tree(tmp_path))
    assert run.returncode == 0, _tail(run)
    assert _clones(tmp_path) == {url: 1 for url in URLS}


def test_each_clone_dir_is_at_the_fixture_head(tmp_path, home):
    heads = _upstreams(tmp_path, home)
    root = _tree(tmp_path)
    run = _fetch(tmp_path, root)
    assert run.returncode == 0, _tail(run)
    sources = root / "data" / "sources"
    assert {name: _head(sources / name) for name in DIRS} == heads


def test_an_existing_dir_is_replaced_by_a_good_clone(tmp_path, home):
    _upstreams(tmp_path, home)
    root = _tree(tmp_path)
    old = _old_clone(root, "LOLBAS")
    new = _advance(tmp_path, "LOLBAS")
    run = _fetch(tmp_path, root)
    assert run.returncode == 0, _tail(run)
    assert (_head(old), (old / "stale-file").exists()) == (new, False)


@pytest.mark.parametrize("existing", [True, False], ids=["old-dir", "no-dir"])
def test_a_clone_killed_by_its_timeout_leaves_no_partial_dir(tmp_path, home, existing):
    heads = _upstreams(tmp_path, home)
    root = _tree(tmp_path)
    if existing:
        _old_clone(root, "LOLDrivers")
    timeout = {"loldrivers": {"clone_timeout": 2}}
    run = _fetch(tmp_path, root, sources=timeout, hang="LOLDrivers")
    assert run.returncode == 1, _tail(run)
    dest = root / "data" / "sources" / "LOLDrivers"
    state = (_head(dest), (dest / "stale-file").exists(), (dest / "partial").exists())
    if existing:
        assert state == (heads["LOLDrivers"], True, False)
    else:
        assert not dest.exists(), f"{dest}: {state}"
    assert _left_over(root) == []


# --- a new temp path per run, gone at the end --------------------------------


def test_a_fetch_leaves_no_temp_path(tmp_path, home):
    _upstreams(tmp_path, home)
    root = _tree(tmp_path)
    run = _fetch(tmp_path, root)
    assert run.returncode == 0, _tail(run)
    assert _left_over(root) == []


def test_a_run_killed_mid_clone_then_run_again_exits_0(tmp_path, home):
    _upstreams(tmp_path, home)
    root = _tree(tmp_path)
    out = tmp_path / "first.out"
    with open(out, "w") as f:
        first = subprocess.Popen(
            _command(tmp_path, root, ()),
            cwd=root,
            env=_env(tmp_path, {}, "LOLDrivers"),
            stdout=f,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    mark = tmp_path / "hang.mark"
    deadline = time.monotonic() + 300
    while not mark.exists() and first.poll() is None and time.monotonic() < deadline:
        time.sleep(0.1)
    if first.poll() is None:
        os.killpg(first.pid, signal.SIGKILL)
    first.wait(timeout=60)
    assert mark.exists(), f"rc {first.returncode}: {out.read_text()[-2000:]}"
    run = _fetch(tmp_path, root)
    assert run.returncode == 0, _tail(run)


def test_a_second_fetch_over_the_dbs_the_first_wrote_exits_0(tmp_path, home):
    _upstreams(tmp_path, home)
    root = _tree(tmp_path)
    first = _fetch(tmp_path, root)
    assert first.returncode == 0, _tail(first)
    run = _fetch(tmp_path, root)
    assert run.returncode == 0, _tail(run)


# --- --skip-registry makes no registry clone ---------------------------------


def test_skip_registry_makes_no_registry_clone(tmp_path, home):
    _upstreams(tmp_path, home)
    run = _fetch(tmp_path, _tree(tmp_path), "--skip-registry")
    assert run.returncode == 0, _tail(run)
    assert _clones(tmp_path)[REGISTRY_URL] == 0


# --- a source that can't be fetched fails the run ----------------------------


@pytest.mark.parametrize("case", ["unreachable", "timeout"])
def test_a_source_that_cant_be_fetched_fails_naming_it(tmp_path, home, case):
    if case == "unreachable":
        _upstreams(tmp_path, home, unreachable="LOLDrivers")
        patch, hang = {}, ""
    else:
        _upstreams(tmp_path, home)
        patch, hang = {"loldrivers": {"clone_timeout": 2}}, "LOLDrivers"
    root = _tree(tmp_path)
    before = _plant_dbs(root)
    run = _fetch(tmp_path, root, sources=patch, hang=hang)
    assert run.returncode == 1, _tail(run)
    assert _errors_naming(run, "LOLDrivers"), _tail(run)
    assert "Skipping" not in _out(run), _tail(run)
    assert _db_shas(root) == before


# --- each source's recorded commit is its clone's head -----------------------


def _recorded(root: Path) -> dict[str, str | None]:
    """Each SOURCES entry's row in its own DB: its last_sync_commit (entries with
    no row are left out)."""
    rows = {}
    for key, entry in SOURCES.items():
        conn = sqlite3.connect(root / "data" / entry["db"])
        try:
            row = conn.execute(
                "SELECT last_sync_commit FROM sources WHERE name = ?",
                (entry["db_source_key"],),
            ).fetchone()
        finally:
            conn.close()
        if row is not None:
            rows[key] = row[0]
    return rows


def test_each_source_records_its_clone_head(tmp_path, home):
    _upstreams(tmp_path, home)
    root = _tree(tmp_path)
    run = _fetch(tmp_path, root)
    assert run.returncode == 0, _tail(run)
    rows = _recorded(root)
    assert len(rows) == len(SOURCES) == 6, f"rows checked: {sorted(rows)}"
    sources = root / "data" / "sources"
    remote = {}
    for key, entry in SOURCES.items():
        listed = _git("ls-remote", entry["url"], "HEAD").split()[0]
        remote[key] = (listed, _head(sources / _dir(entry)))
    assert {key: (commit, commit) for key, commit in rows.items()} == remote


# --- after a fetch nothing needs an update -----------------------------------


def test_after_a_fetch_no_source_needs_an_update(tmp_path, home):
    _upstreams(tmp_path, home)
    root = _tree(tmp_path)
    run = _fetch(tmp_path, root)
    assert run.returncode == 0, _tail(run)
    us = _load(root / "scripts" / "update_sources.py")
    us.github_api_get = lambda endpoint: None
    status = {key: us.check_source(key, root / "data") for key in us.SOURCES}
    seen = {key: (s["needs_update"], s["skipped"]) for key, s in status.items()}
    assert seen == {key: (False, False) for key in SOURCES}


# --- each clone's licence, and none is an error ------------------------------


def test_a_fetch_copies_each_clone_root_licence(tmp_path, home):
    _upstreams(tmp_path, home)
    root = _tree(tmp_path)
    run = _fetch(tmp_path, root)
    assert run.returncode == 0, _tail(run)
    licences = root / "data" / "licenses"
    copied = {
        p.relative_to(licences).as_posix(): p.read_text()
        for p in sorted(licences.rglob("*"))
        if p.is_file()
    }
    want = {f"{name}/LICENSE": _files(name)["LICENSE"] for name in DIRS}
    assert copied == want


def test_a_source_with_no_licence_fails_naming_it(tmp_path, home):
    _upstreams(tmp_path, home, extra=NO_LICENCE.values())
    root = _tree(tmp_path)
    run = _fetch(tmp_path, root, sources=NO_LICENCE)
    assert run.returncode == 1, _tail(run)
    assert _errors_naming(run, "NoLicence"), _tail(run)
