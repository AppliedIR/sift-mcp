"""Tests work on a private copy of the RAG index (rag_private_index).

The root conftest copies the shared data dir before any test module is
imported, points RAG_INDEX_DIR at the copy and fails the session if a shared
data dir changed. The last two tests run a pytest session with that conftest:
one whose test writes the shared dir must fail, one whose test writes the copy
must pass.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import rag_private_index as rpi

TESTS = Path(__file__).resolve().parent


def _shared(root: Path) -> Path:
    (root / "chroma").mkdir(parents=True)
    (root / "chroma" / "chroma.sqlite3").write_bytes(b"index")
    (root / "metadata.json").write_text("{}", encoding="utf-8")
    (root / "meta-link").symlink_to("metadata.json")
    return root


@pytest.fixture
def no_package_dir(monkeypatch):
    """Only the dir RAG_INDEX_DIR names is shared."""
    monkeypatch.setattr(rpi, "package_data_dir", lambda: None)


def test_isolate_copies_the_shared_dir_and_points_the_env_at_the_copy(
    tmp_path, monkeypatch, no_package_dir
):
    shared = _shared(tmp_path / "shared")
    monkeypatch.setenv(rpi.ENV, str(shared))
    guard = rpi.isolate(tmp_path / "private")
    copy = tmp_path / "private" / "rag-index"
    assert os.environ[rpi.ENV] == str(copy)
    assert [root for root, _ in guard] == [shared.resolve()]
    assert rpi.manifest(copy) == rpi.manifest(shared)
    assert (copy / "meta-link").is_symlink()
    assert rpi.changed(guard) == []


def _edit(shared: Path) -> str:
    (shared / "chroma" / "chroma.sqlite3").write_bytes(b"index+")
    return "chroma/chroma.sqlite3"


def _add(shared: Path) -> str:
    (shared / "chroma" / "new.bin").write_bytes(b"")
    return "chroma/new.bin"


def _remove(shared: Path) -> str:
    (shared / "metadata.json").unlink()
    return "metadata.json"


def _relink(shared: Path) -> str:
    (shared / "meta-link").unlink()
    (shared / "meta-link").symlink_to("chroma")
    return "meta-link"


@pytest.mark.parametrize("change", [_edit, _add, _remove, _relink])
def test_changed_names_each_changed_shared_file(
    tmp_path, monkeypatch, no_package_dir, change
):
    shared = _shared(tmp_path / "shared")
    monkeypatch.setenv(rpi.ENV, str(shared))
    guard = rpi.isolate(tmp_path / "private")
    rel = change(shared)
    assert rpi.changed(guard) == [str(shared.resolve() / rel)]


def test_a_test_that_writes_the_copy_changes_nothing_shared(
    tmp_path, monkeypatch, no_package_dir
):
    shared = _shared(tmp_path / "shared")
    monkeypatch.setenv(rpi.ENV, str(shared))
    guard = rpi.isolate(tmp_path / "private")
    _edit(Path(os.environ[rpi.ENV]))
    _add(Path(os.environ[rpi.ENV]))
    assert rpi.changed(guard) == []


def test_a_read_only_shared_dir_gives_a_writable_copy(
    tmp_path, monkeypatch, no_package_dir
):
    shared = _shared(tmp_path / "shared")
    for path in [*sorted(shared.rglob("*"), reverse=True), shared]:
        if not path.is_symlink():
            path.chmod(0o555 if path.is_dir() else 0o444)
    modes = {p: p.lstat().st_mode for p in [shared, *shared.rglob("*")]}
    monkeypatch.setenv(rpi.ENV, str(shared))
    guard = rpi.isolate(tmp_path / "private")
    copy = Path(os.environ[rpi.ENV])
    _edit(copy)
    _add(copy)
    (copy / "metadata.json").write_text('{"x": 1}', encoding="utf-8")
    assert (copy / "meta-link").is_symlink()
    assert {p: p.lstat().st_mode for p in modes} == modes
    assert rpi.changed(guard) == []


def test_a_shared_dir_made_during_the_session_counts_as_changed(
    tmp_path, monkeypatch, no_package_dir
):
    shared = tmp_path / "shared"
    monkeypatch.setenv(rpi.ENV, str(shared))
    guard = rpi.isolate(tmp_path / "private")
    assert not (tmp_path / "private" / "rag-index").exists()
    (shared / "chroma").mkdir(parents=True)
    (shared / "chroma" / "chroma.sqlite3").write_bytes(b"")
    assert rpi.changed(guard) == [str(shared.resolve() / "chroma/chroma.sqlite3")]


def test_the_package_data_dir_is_guarded_too(tmp_path, monkeypatch):
    shared = _shared(tmp_path / "shared")
    package = _shared(tmp_path / "pkg" / "data")
    monkeypatch.setenv(rpi.ENV, str(shared))
    monkeypatch.setattr(rpi, "package_data_dir", lambda: package.resolve())
    guard = rpi.isolate(tmp_path / "private")
    assert [root for root, _ in guard] == [shared.resolve(), package.resolve()]
    _remove(package)
    assert rpi.changed(guard) == [str(package.resolve() / "metadata.json")]


def test_with_no_rag_index_dir_the_package_data_dir_is_copied(tmp_path, monkeypatch):
    package = _shared(tmp_path / "pkg" / "data")
    monkeypatch.delenv(rpi.ENV, raising=False)
    monkeypatch.setattr(rpi, "package_data_dir", lambda: package.resolve())
    guard = rpi.isolate(tmp_path / "private")
    assert [root for root, _ in guard] == [package.resolve()]
    copy = Path(os.environ[rpi.ENV])
    assert rpi.manifest(copy) == rpi.manifest(package)


def test_package_data_dir_is_the_one_rag_mcp_uses():
    utils = pytest.importorskip("rag_mcp.utils")
    assert rpi.package_data_dir() == utils.PACKAGE_DATA_DIR.resolve()


@pytest.mark.skipif(
    importlib.util.find_spec("rag_mcp") is None, reason="forensic-rag not installed"
)
def test_this_session_reads_a_copy_under_its_own_home():
    index_dir = Path(os.environ[rpi.ENV])
    assert index_dir.name == "rag-index"
    assert index_dir.parent == Path(os.environ["HOME"])


PLANT = """
import os
from pathlib import Path


def test_it_writes_the_index():
    target = Path(os.environ[os.environ["PLANT_TARGET"]])
    with open(target / "chroma" / "chroma.sqlite3", "ab") as fh:
        fh.write(b"written by a test")
"""


def _session(tmp_path: Path, target: str) -> tuple[subprocess.CompletedProcess, Path]:
    """A pytest session under this suite's root conftest, with a planted test
    that writes the dir the env var `target` names."""
    shared = _shared(tmp_path / "shared")
    run = tmp_path / "run"
    run.mkdir()
    (run / "test_plant.py").write_text(textwrap.dedent(PLANT), encoding="utf-8")
    (run / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    env = {
        **os.environ,
        rpi.ENV: str(shared),
        "PLANT_SHARED": str(shared),
        "PLANT_TARGET": target,
        "PYTHONPATH": str(TESTS),
    }
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-p",
        "conftest",
        "-q",
        str(run / "test_plant.py"),
    ]
    proc = subprocess.run(
        cmd,
        cwd=run,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    return proc, shared


def test_a_session_whose_test_writes_the_shared_index_fails(tmp_path):
    proc, shared = _session(tmp_path, "PLANT_SHARED")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out[-3000:]
    assert "the shared RAG index changed during the tests" in out, out[-3000:]
    assert str(shared.resolve() / "chroma" / "chroma.sqlite3") in out, out[-3000:]


def test_a_session_whose_test_writes_its_copy_passes(tmp_path):
    proc, shared = _session(tmp_path, rpi.ENV)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out[-3000:]
    assert (shared / "chroma" / "chroma.sqlite3").read_bytes() == b"index"
