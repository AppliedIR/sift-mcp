"""The RAG downloader's side of the update's data offer.

``--check`` reports the installed and newest index, a failed check exits with one
line, an index no metadata names is "unknown", a named release installs and one
without this version's assets is refused before any download, the download is
checked for free space first (after a killed run's stage is removed), and every
failed install, a Ctrl-C in the swap included, leaves the installed index
as it was with no stage left behind, and a real Chroma index (when chromadb is
installed) is swapped in and refreshed in place. Synthetic bundles: the GitHub API is
served from a local listing through ``urlopen``; the asset download, the index
check, the examiner store and the drift check are stubbed. The module is loaded
from its file, because CI doesn't install forensic-rag.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import types
import urllib.error
from pathlib import Path

import pytest

zstd = pytest.importorskip("zstandard")

MODULE = (
    Path(__file__).resolve().parents[1]
    / "packages/forensic-rag/src/rag_mcp/scripts/download_index.py"
)
PKG = "_rag_data_offer_under_test"
TAG = "rag-index-v2099.01.01"
PRIOR_TAG = "rag-index-v2098.01.01"
BARE_TAG = "rag-index-v2099.02.01"  # a release without this version's asset names
STAGE = ".rag-new-*"
# The free space wanted: the download and its unpacked index, 2.25 times the
# download (a reasoned ratio, not a measured one).
NEED_FACTOR = 3.25
OFFLINE = urllib.error.URLError("[Errno -3] Temporary failure in name resolution")


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _bundle(rel: Path, index: bytes, sums: str = "good") -> None:
    """The release's assets: a bundle whose index is ``index``, and its checksums
    file per ``sums``: "good", "bad" (a wrong digest) or "unlisted" (it names
    another file only)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in (
            ("metadata.json", b"{}"),
            ("chroma/chroma.sqlite3", index),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    bundle = rel / "rag-index.tar.zst"
    bundle.write_bytes(zstd.ZstdCompressor().compress(buf.getvalue()))
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    line = {
        "good": f"{digest} rag-index.tar.zst\n",
        "bad": f"{'0' * 64} rag-index.tar.zst\n",
        "unlisted": f"{digest} another.tar.zst\n",
    }[sums]
    (rel / "rag-checksums.sha256").write_text(line)


def _record(rel: Path, tag: str, names=None) -> dict:
    names = [n.name for n in sorted(rel.iterdir())] if names is None else names
    return {
        "tag_name": tag,
        "prerelease": False,
        "assets": [
            {"name": n, "url": str(rel / n), "size": (rel / n).stat().st_size}
            for n in names
        ],
    }


def _load(monkeypatch):
    """download_index.py under a stand-in package: the real constants.py, and
    stand-ins for the refresh and for utils.resolve_data_dir (the --dest path)."""
    refresh = types.ModuleType(f"{PKG}.refresh")
    refresh.refresh = lambda **kw: types.SimpleNamespace(status="success", errors=[])
    utils = types.ModuleType(f"{PKG}.utils")
    utils.resolve_data_dir = lambda d: Path(d)
    spec = importlib.util.spec_from_file_location(
        f"{PKG}.constants", MODULE.parents[1] / "constants.py"
    )
    constants = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(constants)
    pkg = types.ModuleType(PKG)
    pkg.constants = constants
    for name, mod in (
        (PKG, pkg),
        (f"{PKG}.constants", constants),
        (f"{PKG}.refresh", refresh),
        (f"{PKG}.utils", utils),
    ):
        monkeypatch.setitem(sys.modules, name, mod)
    spec = importlib.util.spec_from_file_location(f"{PKG}.scripts.dl", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def rag(tmp_path, monkeypatch):
    """The module, serving TAG (newest) and BARE_TAG from local files. ``seen``
    holds the assets downloaded, the examiner-store syncs and the sleeps;
    ``serve(index=, sums=)`` rebuilds TAG's assets."""
    mod = _load(monkeypatch)
    seen = types.SimpleNamespace(downloaded=[], synced=[], sleeps=[], fail=set())
    releases: dict[str, dict] = {}

    def serve(index: bytes = b"the new index", sums: str = "good") -> dict:
        rel = tmp_path / "release"
        rel.mkdir(exist_ok=True)
        _bundle(rel, index, sums)
        bare = tmp_path / "bare"
        bare.mkdir(exist_ok=True)
        (bare / "rag-index.tar.gz").write_bytes(b"a renamed format")
        releases[TAG] = _record(rel, TAG)
        releases[BARE_TAG] = _record(bare, BARE_TAG)
        return releases[TAG]

    def urlopen(req, timeout=None):
        url = getattr(req, "full_url", req)
        api = f"https://api.github.com/repos/{mod.REPO}/releases"
        if url == f"{api}?per_page=100":
            body = [releases[BARE_TAG], releases[TAG]]  # newest first
        elif url.startswith(f"{api}/tags/") and url[len(api) + 6 :] in releases:
            body = releases[url[len(api) + 6 :]]
        else:
            raise AssertionError(f"unexpected URL {url}")
        return _Response(json.dumps(body).encode())

    def download_asset(url, dest):
        seen.downloaded.append(Path(url).name)
        if Path(url).name in seen.fail:
            raise OSError("connection reset")
        Path(dest).write_bytes(Path(url).read_bytes())

    def sync(dest):
        seen.synced.append(dest)
        return 0

    monkeypatch.setattr(mod, "_github_headers", dict)
    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(mod, "_download_asset", download_asset)
    monkeypatch.setattr(mod, "_verify_index", lambda data_dir: True)
    monkeypatch.setattr(mod, "_sync_examiner_store", sync)
    monkeypatch.setattr(mod, "_bundled_drift", lambda dest: False)
    monkeypatch.setattr(mod.time, "sleep", seen.sleeps.append)
    monkeypatch.setenv("ANONYMIZED_TELEMETRY", "False")
    serve()
    return types.SimpleNamespace(mod=mod, seen=seen, serve=serve, releases=releases)


def _prior(dest: Path) -> dict[str, bytes]:
    """A prior install in ``dest``; returns its files."""
    (dest / "chroma").mkdir(parents=True)
    (dest / "chroma/chroma.sqlite3").write_bytes(b"the old index")
    (dest / "metadata.json").write_text(json.dumps({"bundle_tag": PRIOR_TAG}))
    return _tree(dest)


def _tree(dest: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(dest)): p.read_bytes()
        for p in sorted(dest.rglob("*"))
        if p.is_file()
    }


def _stages(dest: Path) -> list[Path]:
    return sorted(dest.glob(STAGE))


def _check(mod):
    check = getattr(mod, "check", None)
    assert check is not None, "no --check: the module has no check()"
    return check


def _main(mod, monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["download_index", *args])
    with pytest.raises(SystemExit) as stop:
        mod.main()
    return stop.value.code


def _download_bytes(release: dict) -> int:
    return sum(a["size"] for a in release["assets"])


# --- D-2 (RAG leg): the installed and newest index ----------------------------------


def test_d2_check_reports_the_installed_and_the_newest_index(rag, tmp_path):
    dest = tmp_path / "dest"
    _prior(dest)
    assert _check(rag.mod)(dest) == {
        "installed": PRIOR_TAG,
        "absent": False,
        "newest": TAG,
        "download_bytes": _download_bytes(rag.releases[TAG]),
    }


def test_d2_check_prints_one_json_line(rag, tmp_path, monkeypatch, capsys):
    dest = tmp_path / "dest"
    _prior(dest)
    code = _main(rag.mod, monkeypatch, "--check", "--dest", str(dest))
    out = capsys.readouterr().out
    assert code == 0, out
    assert out.count("\n") == 1
    assert json.loads(out) == _check(rag.mod)(dest)


# --- Y5 (RAG leg): an index no metadata names is "unknown" --------------------------


@pytest.mark.parametrize("metadata", [None, "{}", '{"bundle_tag": ""}', "not json"])
def test_y5_an_index_no_metadata_names_is_unknown(rag, tmp_path, metadata):
    dest = tmp_path / "dest"
    (dest / "chroma").mkdir(parents=True)
    if metadata is not None:
        (dest / "metadata.json").write_text(metadata)
    got = _check(rag.mod)(dest)
    assert (got["installed"], got["absent"], got["newest"]) == ("unknown", False, TAG)


def test_y5_no_index_is_absent(rag, tmp_path):
    got = _check(rag.mod)(tmp_path / "dest")
    assert (got["installed"], got["absent"]) == ("unknown", True)


# --- D-3 (RAG leg): a failed check is one line and a non-zero exit ------------------


def test_d3_a_failed_check_exits_with_one_line_naming_the_cause(
    rag, tmp_path, monkeypatch, capsys
):
    def offline(req, timeout=None):
        raise OFFLINE

    monkeypatch.setattr(rag.mod.urllib.request, "urlopen", offline)
    dest = tmp_path / "dest"
    before = _prior(dest)
    code = _main(rag.mod, monkeypatch, "--check", "--dest", str(dest))
    assert code == f"Could not check for a newer RAG index: {OFFLINE}"
    assert capsys.readouterr().out == ""
    assert _tree(dest) == before


# --- D-8 (RAG leg): a named release ---------------------------------------------------


def test_d8_a_named_release_installs_with_its_tag(rag, tmp_path):
    dest = tmp_path / "dest"
    _prior(dest)
    assert rag.mod.download_index(dest, TAG) is True
    assert (dest / "chroma/chroma.sqlite3").read_bytes() == b"the new index"
    assert json.loads((dest / "metadata.json").read_text())["bundle_tag"] == TAG
    assert _stages(dest) == []


def test_d8_a_release_without_this_versions_assets_is_refused_before_any_download(
    rag, tmp_path, capsys
):
    dest = tmp_path / "dest"
    before = _prior(dest)
    assert rag.mod.download_index(dest, BARE_TAG) is False
    out = capsys.readouterr().out
    assert "No usable rag-index-* release. Nothing was downloaded or changed." in out
    assert rag.seen.downloaded == []
    assert rag.seen.synced == []
    assert _tree(dest) == before


def test_d8_the_newest_skips_a_release_without_this_versions_assets(rag, tmp_path):
    dest = tmp_path / "dest"
    _prior(dest)
    assert rag.mod.download_index(dest) is True
    assert json.loads((dest / "metadata.json").read_text())["bundle_tag"] == TAG


# --- Y3 (RAG leg): free space is checked before anything is fetched or synced -------


def _free(monkeypatch, mod, free: int) -> None:
    usage = types.SimpleNamespace(total=free, used=0, free=free)
    monkeypatch.setattr(mod.shutil, "disk_usage", lambda path: usage)


def test_y3_one_byte_short_is_refused_before_any_download(
    rag, tmp_path, monkeypatch, capsys
):
    need = int(_download_bytes(rag.releases[TAG]) * NEED_FACTOR)
    dest = tmp_path / "dest"
    before = _prior(dest)
    _free(monkeypatch, rag.mod, need - 1)
    assert rag.mod.download_index(dest) is False
    want = f"Not enough free space ({need:,} bytes). Nothing was changed."
    assert want in capsys.readouterr().out
    assert rag.seen.downloaded == []
    assert rag.seen.synced == []
    assert _tree(dest) == before


def test_y3_free_space_equal_to_the_need_installs(rag, tmp_path, monkeypatch):
    need = int(_download_bytes(rag.releases[TAG]) * NEED_FACTOR)
    dest = tmp_path / "dest"
    _prior(dest)
    _free(monkeypatch, rag.mod, need)
    assert rag.mod.download_index(dest) is True


# --- D-6 (RAG leg): a failed install leaves the installed index and no stage --------


def _refused(rag, dest: Path, before: dict, capsys) -> str:
    assert rag.mod.download_index(dest) is False
    assert _tree(dest) == before, "a failed install changed the installed index"
    assert _stages(dest) == []
    return capsys.readouterr().out


def test_d6_a_download_that_keeps_failing(rag, tmp_path, capsys):
    rag.seen.fail.add("rag-index.tar.zst")
    dest = tmp_path / "dest"
    out = _refused(rag, dest, _prior(dest), capsys)
    assert "All download attempts failed." in out


def test_d6_a_checksum_mismatch(rag, tmp_path, capsys):
    rag.serve(sums="bad")
    dest = tmp_path / "dest"
    out = _refused(rag, dest, _prior(dest), capsys)
    assert "Checksum verification failed after all attempts." in out


def test_d6_checksums_that_do_not_list_the_index(rag, tmp_path, capsys):
    rag.serve(sums="unlisted")
    dest = tmp_path / "dest"
    out = _refused(rag, dest, _prior(dest), capsys)
    assert "rag-checksums.sha256 does not list the index. Nothing was changed." in out


def test_d6_an_index_that_fails_its_check(rag, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rag.mod, "_verify_index", lambda data_dir: False)
    dest = tmp_path / "dest"
    out = _refused(rag, dest, _prior(dest), capsys)
    assert "Index verification failed." in out


def _fail_into(monkeypatch, mod, target: Path) -> None:
    """Every rename onto ``target`` fails."""
    real = os.replace

    def replace(src, dst):
        if Path(dst) == target:
            raise OSError(f"cannot move onto {target}")
        return real(src, dst)

    monkeypatch.setattr(mod.os, "replace", replace)


def test_d6_a_failed_swap_is_undone(rag, tmp_path, monkeypatch, capsys):
    dest = tmp_path / "dest"
    before = _prior(dest)
    real = os.replace

    def replace(src, dst):  # the new index onto dest fails; the undo works
        from_stage = Path(src).parent.name.startswith(".rag-new-")
        if Path(dst) == dest / "chroma" and from_stage:
            raise OSError("disk full")
        return real(src, dst)

    monkeypatch.setattr(rag.mod.os, "replace", replace)
    out = _refused(rag, dest, before, capsys)
    assert "The installed index was not changed." in out


def test_d6_a_failed_undo_keeps_the_old_files_and_names_them(
    rag, tmp_path, monkeypatch, capsys
):
    dest = tmp_path / "dest"
    before = _prior(dest)
    _fail_into(monkeypatch, rag.mod, dest / "chroma")
    assert rag.mod.download_index(dest) is False
    out = capsys.readouterr().out
    [stage] = _stages(dest)
    assert f"The files it replaced are in {stage / 'old'}." in out
    assert (stage / "old/chroma/chroma.sqlite3").read_bytes() == (
        before["chroma/chroma.sqlite3"]
    )


def test_d6_the_next_run_removes_a_left_stage_and_keeps_one_with_old_files(
    rag, tmp_path
):
    dest = tmp_path / "dest"
    _prior(dest)
    left = dest / ".rag-new-left"
    (left / "chroma").mkdir(parents=True)
    (left / "chroma/chroma.sqlite3").write_bytes(b"a killed run's index")
    kept = dest / ".rag-new-kept"
    (kept / "old/chroma").mkdir(parents=True)
    (kept / "old/chroma/chroma.sqlite3").write_bytes(b"a failed undo's index")
    assert rag.mod.download_index(dest) is True
    assert _stages(dest) == [kept]
    assert (kept / "old/chroma/chroma.sqlite3").read_bytes() == b"a failed undo's index"
    assert (dest / "chroma/chroma.sqlite3").read_bytes() == b"the new index"


# --- D-6 (RAG leg): a Ctrl-C in the swap leaves the installed index ------------------


def _interrupt_swap(monkeypatch, mod, dest: Path, on: set[int]) -> list[tuple]:
    """The moves into or out of ``dest`` numbered in ``on`` (from 1) raise
    KeyboardInterrupt; moves inside the stage aren't counted."""
    calls: list[tuple] = []
    real = os.replace

    def replace(src, dst):
        if dest in (Path(src).parent, Path(dst).parent):
            calls.append((src, dst))
            if len(calls) in on:
                raise KeyboardInterrupt
        return real(src, dst)

    monkeypatch.setattr(mod.os, "replace", replace)
    return calls


def _run(fn, *args):
    """fn's result, or "interrupted" when the KeyboardInterrupt got out (one that
    leaves a test stops the whole pytest run)."""
    try:
        return fn(*args)
    except KeyboardInterrupt:
        return "interrupted"


def test_d6_a_ctrl_c_in_the_swap_puts_the_installed_index_back(
    rag, tmp_path, monkeypatch, capsys
):
    dest = tmp_path / "dest"
    before = _prior(dest)
    calls = _interrupt_swap(monkeypatch, rag.mod, dest, {2})
    got = _run(rag.mod.download_index, dest)
    assert len(calls) >= 2, "the install did not reach a second move"
    assert _tree(dest) == before, "a Ctrl-C in the swap lost the installed index"
    assert _stages(dest) == []
    assert got is False
    assert "The installed index was not changed." in capsys.readouterr().out


def test_d6_a_ctrl_c_in_the_undo_keeps_the_stage_with_the_old_index(
    rag, tmp_path, monkeypatch
):
    dest = tmp_path / "dest"
    before = _prior(dest)
    _interrupt_swap(monkeypatch, rag.mod, dest, {2, 3})
    _run(rag.mod.download_index, dest)
    stages = _stages(dest)
    assert len(stages) == 1, "the stage holding the old index was removed"
    assert (stages[0] / "old/chroma/chroma.sqlite3").read_bytes() == (
        before["chroma/chroma.sqlite3"]
    )


# --- Y3 (RAG leg): a killed run's stage is removed before the free-space check -------


def test_y3_a_left_stage_is_removed_before_free_space_is_checked(
    rag, tmp_path, monkeypatch
):
    """The left stage's bytes count against free space only while it is there."""
    need = int(_download_bytes(rag.releases[TAG]) * NEED_FACTOR)
    dest = tmp_path / "dest"
    _prior(dest)
    left = dest / ".rag-new-left"
    (left / "chroma").mkdir(parents=True)
    (left / "chroma/chroma.sqlite3").write_bytes(b"a killed run's index")

    def usage(path):
        free = need - 1 if left.exists() else need
        return types.SimpleNamespace(total=free, used=0, free=free)

    monkeypatch.setattr(rag.mod.shutil, "disk_usage", usage)
    assert rag.mod.download_index(dest) is True
    assert not left.exists()
    assert (dest / "chroma/chroma.sqlite3").read_bytes() == b"the new index"


# --- D-6 (RAG leg): a real Chroma index is swapped in and refreshed in place ---------


def _chroma(chromadb, path: Path, ids: list[str]) -> None:
    """A Chroma store at ``path`` whose ir_knowledge collection holds ``ids``,
    with explicit embeddings (no model is loaded)."""
    collection = chromadb.PersistentClient(path=str(path)).get_or_create_collection(
        "ir_knowledge"
    )
    collection.add(
        ids=ids,
        embeddings=[[float(n), 1.0, 0.0] for n in range(len(ids))],
        documents=ids,
    )


def _close(chromadb) -> None:
    """Drop this process's Chroma clients, so their files are closed."""
    chromadb.api.client.SharedSystemClient.clear_system_cache()


def _pack(rel: Path, build: Path) -> None:
    """``build``'s chroma/ and metadata.json as the release's bundle and checksums."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(build / "chroma", arcname="chroma")
        tar.add(build / "metadata.json", arcname="metadata.json")
    bundle = rel / "rag-index.tar.zst"
    bundle.write_bytes(zstd.ZstdCompressor().compress(buf.getvalue()))
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    (rel / "rag-checksums.sha256").write_text(f"{digest} rag-index.tar.zst\n")


# A fresh process's view of an installed index: its record ids, sorted
READ = (
    "import json, sys, chromadb; "
    "c = chromadb.PersistentClient(path=sys.argv[1]).get_collection('ir_knowledge'); "
    "print(json.dumps(sorted(c.get()['ids'])))"
)


def test_d6_a_real_chroma_index_is_swapped_in_and_refreshed_in_place(
    rag, tmp_path, monkeypatch
):
    """The check opens the new index where it was unpacked and the refresh writes
    into the installed index, so a fresh process opening it reads the bundle's
    records and the refresh's, and none of the prior index's."""
    chromadb = pytest.importorskip("chromadb")
    dest = tmp_path / "dest"
    build = tmp_path / "build"
    try:
        _chroma(chromadb, dest / "chroma", ["old-1", "old-2"])
        (dest / "metadata.json").write_text(json.dumps({"bundle_tag": PRIOR_TAG}))
        _chroma(chromadb, build / "chroma", ["new-1", "new-2", "new-3"])
        (build / "metadata.json").write_text("{}")
        _close(chromadb)
        _pack(tmp_path / "release", build)
        rag.releases[TAG] = _record(tmp_path / "release", TAG)
        checked = []

        def verify(data_dir):
            collection = chromadb.PersistentClient(
                path=str(Path(data_dir) / "chroma")
            ).get_collection("ir_knowledge")
            checked.append(collection.count())
            hits = collection.query(query_embeddings=[[0.0, 1.0, 0.0]], n_results=1)
            return collection.count() == 3 and bool(hits["ids"][0])

        def refresh(skip_online, data_dir):
            chromadb.PersistentClient(
                path=str(Path(data_dir) / "chroma")
            ).get_collection("ir_knowledge").add(
                ids=["refreshed"], embeddings=[[9.0, 1.0, 0.0]], documents=["refreshed"]
            )
            return types.SimpleNamespace(status="success", errors=[])

        monkeypatch.setattr(rag.mod, "_verify_index", verify)
        monkeypatch.setattr(rag.mod, "_bundled_drift", lambda dest: True)
        monkeypatch.setattr(sys.modules[f"{PKG}.refresh"], "refresh", refresh)
        assert rag.mod.download_index(dest, TAG) is True
    finally:
        _close(chromadb)
    assert checked == [3], "the new index was not checked before the install"
    read = subprocess.run(
        [sys.executable, "-I", "-c", READ, str(dest / "chroma")],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert read.returncode == 0, read.stderr
    assert json.loads(read.stdout.splitlines()[-1]) == [
        "new-1",
        "new-2",
        "new-3",
        "refreshed",
    ], "the installed index is not the bundle's records plus the refresh's"
    assert _stages(dest) == []
