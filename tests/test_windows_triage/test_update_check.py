"""The triage update check: its lookup, and what it reports for what it couldn't do.

The lookup is tested at its own interface (owner/repo) on fixture bare repos, reached
through ``git url.insteadOf`` in an isolated HOME; ``github_api_get`` is stubbed in
every case, so no case asks the GitHub API. The run cases go through ``main()`` of a
copy of the scripts dir, with its data dir beside it, and patch the lookup function
the update check calls (``get_latest_commit``), keyed per repo.
"""

from __future__ import annotations

import importlib.util
import itertools
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from windows_triage.db.schemas import (
    CONTEXT_SCHEMA,
    KNOWN_GOOD_SCHEMA,
    REGISTRY_FULL_SCHEMA,
)

from .test_context_import_failures import GOOD

SCRIPTS = Path(__file__).resolve().parents[2] / "packages/windows-triage/scripts"
OLD = "1" * 40  # the commit every installed row holds
SCHEMAS = {
    "known_good.db": KNOWN_GOOD_SCHEMA,
    "known_good_registry.db": REGISTRY_FULL_SCHEMA,
    "context.db": CONTEXT_SCHEMA,
}
ALL_UP_TO_DATE = "All databases are up to date."
_loads = itertools.count()


@pytest.fixture(autouse=True)
def git_home(tmp_path, monkeypatch):
    """An isolated HOME whose .gitconfig holds the case's insteadOf lines."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    return home


def _git(*args: str, cwd: Path | None = None) -> str:
    run = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=60
    )
    assert run.returncode == 0, f"git {args}: {run.stderr}"
    return run.stdout.strip()


def _point(home: Path, owner_repo: str, target: Path) -> None:
    with open(home / ".gitconfig", "a", encoding="utf-8") as f:
        f.write(f'[url "{target}"]\n\tinsteadOf = https://github.com/{owner_repo}\n')


def _remote(tmp: Path, home: Path, owner_repo: str, branch: str, files: dict) -> str:
    """A bare repo on ``branch`` holding ``files``, pointed at by owner_repo's URL
    with and without ".git"; returns its head."""
    name = owner_repo.split("/")[1]
    work = tmp / "work" / name
    work.mkdir(parents=True)
    _git("init", "-q", "-b", branch, str(work))
    for rel, text in files.items():
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text(text, encoding="utf-8")
    _git("add", "-A", cwd=work)
    _git("-c", "user.name=f", "-c", "user.email=f@f", "commit", "-qm", "f", cwd=work)
    remotes = tmp / "remotes"
    remotes.mkdir(exist_ok=True)
    _git("clone", "-q", "--bare", str(work), str(remotes / f"{name}.git"))
    (remotes / name).symlink_to(remotes / f"{name}.git")
    _point(home, owner_repo, remotes / name)
    return _git("rev-parse", "HEAD", cwd=work)


def _update_sources(tmp: Path, api=lambda endpoint: None):
    """update_sources from a copy of the scripts dir; returns the module."""
    root = tmp / "tree"
    if not root.exists():
        shutil.copytree(SCRIPTS, root / "scripts")
        (root / "data").mkdir()
    path = root / "scripts" / "update_sources.py"
    spec = importlib.util.spec_from_file_location(f"us_{next(_loads)}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.github_api_get = api
    return mod


def _install(us, dbs) -> None:
    """The named DBs, every git source row at OLD."""
    data = Path(us.__file__).parent.parent / "data"
    for db in dbs:
        conn = sqlite3.connect(data / db)
        conn.executescript(SCHEMAS[db])
        conn.execute(
            "UPDATE sources SET last_sync_commit = ? WHERE source_type = 'git'", (OLD,)
        )
        conn.commit()
        conn.close()


def _name_of(rest: str, names: list[str]) -> str:
    """The source a status line names (longest name first: one is another's prefix)."""
    return next(n for n in names if rest == n or rest.startswith(n + " "))


def _main(us, monkeypatch, capsys, *args: str):
    """main() as a run would; returns the exit code, each source's status label,
    the closing line, and all the run printed."""
    monkeypatch.setattr(sys, "argv", ["update_sources.py", *args])
    try:
        us.main()
        rc = 0
    except SystemExit as e:
        rc = 0 if e.code is None else e.code
    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    start = lines.index("DATABASE UPDATE STATUS") + 2
    names = sorted((s["name"] for s in us.SOURCES.values()), key=len, reverse=True)
    labels = {}
    for line in itertools.takewhile(str.strip, lines[start:]):
        rest = line.strip()[2:]
        name = _name_of(rest, names)
        labels[name] = rest[len(name) :].strip()
    closing = [line.strip() for line in lines if line.strip()][-1]
    return rc, labels, closing, captured.out + captured.err


def _heads(us, heads: dict[str, str | None]) -> None:
    us.get_latest_commit = lambda repo, *a, **k: heads[repo]


# --- the lookup, at its own interface ----------------------------------------

REPO = "fixture-owner/fixture-repo"


def test_the_lookup_returns_the_head_of_a_trunk_default_branch(tmp_path, git_home):
    head = _remote(tmp_path, git_home, REPO, "trunk", {"README": "x\n"})

    def api(endpoint):  # the GitHub API as it would answer for this repo
        return {"sha": head} if endpoint == f"repos/{REPO}/commits/trunk" else None

    us = _update_sources(tmp_path, api)
    found = us.get_latest_commit(REPO)
    assert found == head, f"lookup gave {found}"


@pytest.mark.parametrize("branch", ["main", "master"])
def test_the_lookup_returns_the_head_of_a_main_or_master_default(
    tmp_path, git_home, branch
):
    head = _remote(tmp_path, git_home, REPO, branch, {"README": "x\n"})
    us = _update_sources(tmp_path)
    found = us.get_latest_commit(REPO)
    assert found == head, f"lookup gave {found}"


# --- (e) every lookup returns None, every DB installed ----------------------


def _all_unchecked(tmp_path, monkeypatch, capsys):
    us = _update_sources(tmp_path)
    _install(us, SCHEMAS)
    _heads(us, {s["repo"]: None for s in us.SOURCES.values()})
    return _main(us, monkeypatch, capsys)


def test_a_source_that_could_not_be_checked_never_reads_up_to_date(
    tmp_path, monkeypatch, capsys
):
    _, labels, _, _ = _all_unchecked(tmp_path, monkeypatch, capsys)
    dated = [name for name, label in labels.items() if "up to date" in label]
    assert len(labels) == 6 and not dated, f"labels {labels}"


def test_a_source_that_could_not_be_checked_reads_could_not_check(
    tmp_path, monkeypatch, capsys
):
    _, labels, _, _ = _all_unchecked(tmp_path, monkeypatch, capsys)
    assert all("could not check" in label for label in labels.values()), labels


def test_a_run_with_sources_not_checked_does_not_end_all_up_to_date(
    tmp_path, monkeypatch, capsys
):
    _, _, closing, _ = _all_unchecked(tmp_path, monkeypatch, capsys)
    assert closing != ALL_UP_TO_DATE


def test_a_run_with_sources_not_checked_counts_them_in_its_closing_line(
    tmp_path, monkeypatch, capsys
):
    _, _, closing, _ = _all_unchecked(tmp_path, monkeypatch, capsys)
    assert "0 DB(s) not installed" in closing, closing
    assert "6 source(s) could not be checked" in closing, closing


def test_a_lookup_that_cannot_reach_the_remote_reads_could_not_check(
    tmp_path, git_home, monkeypatch, capsys
):
    us = _update_sources(tmp_path)
    _install(us, ["context.db"])
    _point(git_home, us.SOURCES["lolbas"]["repo"], tmp_path / "no-such-repo")
    _, labels, _, text = _main(us, monkeypatch, capsys, "--source", "lolbas")
    assert "could not check" in labels["LOLBAS"], f"labels {labels}"
    assert "Traceback" not in text


# --- (d) known_good.db not installed: one DB, two sources --------------------


def _one_db_absent(tmp_path, monkeypatch, capsys):
    us = _update_sources(tmp_path)
    _install(us, ["known_good_registry.db", "context.db"])
    _heads(us, {s["repo"]: OLD for s in us.SOURCES.values()})
    return _main(us, monkeypatch, capsys)


ON_KNOWN_GOOD = (  # the two sources whose DB is known_good.db
    "VanillaWindowsReference",
    "VanillaWindowsRegistryHives (extractions)",
)


def test_a_db_not_installed_never_reads_up_to_date(tmp_path, monkeypatch, capsys):
    _, labels, _, _ = _one_db_absent(tmp_path, monkeypatch, capsys)
    assert not [n for n in ON_KNOWN_GOOD if "up to date" in labels[n]], labels


def test_a_db_not_installed_reads_not_installed(tmp_path, monkeypatch, capsys):
    _, labels, _, _ = _one_db_absent(tmp_path, monkeypatch, capsys)
    assert all("not installed" in labels[n] for n in ON_KNOWN_GOOD), f"{labels}"


def test_an_installed_db_at_the_head_reads_up_to_date(tmp_path, monkeypatch, capsys):
    _, labels, _, _ = _one_db_absent(tmp_path, monkeypatch, capsys)
    assert labels["LOLBAS"].startswith("up to date"), labels


def test_a_run_with_a_db_not_installed_does_not_end_all_up_to_date(
    tmp_path, monkeypatch, capsys
):
    _, _, closing, _ = _one_db_absent(tmp_path, monkeypatch, capsys)
    assert closing != ALL_UP_TO_DATE


def test_a_db_shared_by_two_sources_counts_once_as_not_installed(
    tmp_path, monkeypatch, capsys
):
    _, _, closing, _ = _one_db_absent(tmp_path, monkeypatch, capsys)
    assert "1 DB(s) not installed" in closing, closing
    assert "0 source(s) could not be checked" in closing, closing


# --- a mixed run: one update, one source not checked, one DB not installed ---


def _mixed(tmp_path, git_home, monkeypatch, capsys):
    us = _update_sources(tmp_path)
    _install(us, ["known_good.db", "context.db"])  # known_good_registry.db absent
    folder, file_name, yml, _ = GOOD["lolbas"]  # one LOLBin
    lolbas = us.SOURCES["lolbas"]["repo"]
    head = _remote(tmp_path, git_home, lolbas, "main", {f"{folder}/{file_name}": yml})
    heads = {s["repo"]: OLD for s in us.SOURCES.values()}
    heads.update({lolbas: head, us.SOURCES["hijacklibs"]["repo"]: None})
    _heads(us, heads)
    rc, labels, closing, text = _main(us, monkeypatch, capsys)
    conn = sqlite3.connect(Path(us.__file__).parent.parent / "data" / "context.db")
    row = conn.execute(
        "SELECT last_sync_commit FROM sources WHERE name = 'lolbas'"
    ).fetchone()
    conn.close()
    return rc, closing, head, row[0], text


def test_a_mixed_run_updates_the_one_source_and_exits_0(
    tmp_path, git_home, monkeypatch, capsys
):
    rc, closing, head, commit, text = _mixed(tmp_path, git_home, monkeypatch, capsys)
    assert (rc, commit) == (0, head) and "1 succeeded, 0 failed" in closing, text


def test_a_mixed_run_counts_the_db_not_installed(
    tmp_path, git_home, monkeypatch, capsys
):
    _, closing, _, _, _ = _mixed(tmp_path, git_home, monkeypatch, capsys)
    assert "1 DB(s) not installed" in closing, closing


def test_a_mixed_run_counts_the_source_not_checked(
    tmp_path, git_home, monkeypatch, capsys
):
    _, closing, _, _, _ = _mixed(tmp_path, git_home, monkeypatch, capsys)
    assert "1 source(s) could not be checked" in closing, closing
