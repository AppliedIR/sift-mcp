"""What the RAG release bundle packs, and what an install takes from it.

build_release --skip-build packs a prepared data dir: a missing member fails
the pack naming it, the packed metadata.json never carries refreshed_at (the
data dir's own file is left as it was), and a member added to the one member
list is both packed and installed. The record-count floor is set to 0 on
this path, so a fixture needs no record_count.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

build_release = pytest.importorskip("rag_mcp.scripts.build_release")
zstandard = pytest.importorskip("zstandard")

PROBE = Path(__file__).with_name("_rag_paths_probe.py")
MODEL = "BAAI/bge-base-en-v1.5"


def _data_dir(root: Path, metadata: dict | None = None) -> Path:
    """A data dir holding every member a bundle packs."""
    d = root / "data"
    (d / "chroma").mkdir(parents=True)
    (d / "chroma" / "chroma.sqlite3").write_bytes(b"fixture")
    lic = d / "sources" / "licenses" / "fixture_a"
    lic.mkdir(parents=True)
    (lic / "LICENSE").write_text("Fixture licence\n", encoding="utf-8")
    (d / "sources" / "fixture_a.jsonl").write_text(
        json.dumps({"text": "a", "metadata": {"source": "fixture_a"}}) + "\n",
        encoding="utf-8",
    )
    body = {"model": MODEL} if metadata is None else metadata
    (d / "metadata.json").write_text(json.dumps(body, indent=2), encoding="utf-8")
    (d / "user_state.json").write_text(
        json.dumps({"version": 1, "files": {}}), encoding="utf-8"
    )
    (d / "sources_state.json").write_text(
        json.dumps({"version": 1, "sources": {}}), encoding="utf-8"
    )
    return d


def _bundle_members(path: Path) -> dict[str, bytes | None]:
    members: dict[str, bytes | None] = {}
    with open(path, "rb") as fh:
        with zstandard.ZstdDecompressor().stream_reader(fh) as reader:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                for m in tar:
                    f = tar.extractfile(m) if m.isreg() else None
                    members[m.name] = f.read() if f else None
    return members


def _pack(monkeypatch, capsys, data_dir: Path, out_dir: Path) -> tuple[int, str]:
    monkeypatch.setenv("RAG_INDEX_DIR", str(data_dir))
    monkeypatch.setattr(build_release, "MIN_RECORD_COUNT", 0)
    monkeypatch.setattr(
        sys,
        "argv",
        ["build_release", "--skip-build", "--output-dir", str(out_dir)],
    )
    try:
        build_release.main()
        rc = 0
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else 1
    captured = capsys.readouterr()
    return rc, captured.out + captured.err


# A member named by itself in the output: "sources" is not "sources_state.json"
# or "sources/licenses"
NAMED = {
    "sources": r"(?<![\w.-])sources(?![\w/.-])",
    "user_state.json": r"(?<![\w.-])user_state\.json(?![\w/.-])",
    "sources/licenses": r"(?<![\w.-])sources/licenses(?![\w/.-])",
}


@pytest.mark.parametrize("member", list(NAMED))
def test_skip_build_without_a_member_fails_naming_it(
    tmp_path, monkeypatch, capsys, member
):
    d = _data_dir(tmp_path)
    gone = d / member
    if gone.is_dir():
        shutil.rmtree(gone)
    else:
        gone.unlink()
    rc, output = _pack(monkeypatch, capsys, d, tmp_path / "release")
    assert rc != 0, f"the pack without {member} exited 0: {output[-400:]}"
    assert re.search(NAMED[member], output), f"{member} not named: {output[-400:]}"
    assert "Build failed" not in output


def test_skip_build_without_metadata_fails(tmp_path, monkeypatch, capsys):
    d = _data_dir(tmp_path)
    (d / "metadata.json").unlink()
    rc, output = _pack(monkeypatch, capsys, d, tmp_path / "release")
    assert rc == 1
    assert "No metadata.json found" in output


def test_the_packed_metadata_has_no_refreshed_at(tmp_path, monkeypatch, capsys):
    d = _data_dir(tmp_path, {"model": MODEL, "refreshed_at": "2026-01-02T03:04:05Z"})
    rc, output = _pack(monkeypatch, capsys, d, tmp_path / "release")
    assert rc == 0, output[-400:]
    assert "Build failed" not in output
    members = _bundle_members(tmp_path / "release" / "rag-index.tar.zst")
    packed = json.loads(members["metadata.json"] or b"{}")
    assert "refreshed_at" not in packed, f"packed metadata.json: {packed}"


def test_the_pack_leaves_the_data_dir_metadata_as_it_was(tmp_path, monkeypatch, capsys):
    d = _data_dir(tmp_path, {"model": MODEL, "refreshed_at": "2026-01-02T03:04:05Z"})
    before = (d / "metadata.json").read_bytes()
    rc, output = _pack(monkeypatch, capsys, d, tmp_path / "release")
    assert rc == 0, output[-400:]
    assert "Build failed" not in output
    assert (d / "metadata.json").read_bytes() == before


def test_metadata_without_refreshed_at_packs_as_it_is(tmp_path, monkeypatch, capsys):
    d = _data_dir(tmp_path, {"model": MODEL, "bundle_tag": "rag-index-v2026.01.02"})
    rc, output = _pack(monkeypatch, capsys, d, tmp_path / "release")
    assert rc == 0, output[-400:]
    assert "Build failed" not in output
    members = _bundle_members(tmp_path / "release" / "rag-index.tar.zst")
    packed = json.loads(members["metadata.json"] or b"{}")
    assert packed == json.loads((d / "metadata.json").read_text(encoding="utf-8"))


# A member added to the one member list: a file and a directory
ADDED = ("sources_state.json", "extra")


def _hand_bundle(path: Path, src: Path) -> None:
    tar_path = path.with_suffix(".tar")
    with tarfile.open(tar_path, "w") as tar:
        for name in ("chroma", "sources", "metadata.json", "user_state.json", *ADDED):
            tar.add(src / name, arcname=name)
    with open(tar_path, "rb") as fin, open(path, "wb") as fout:
        zstandard.ZstdCompressor(level=1).copy_stream(fin, fout)
    tar_path.unlink()


@pytest.fixture(scope="module")
def added_member_run(tmp_path_factory):
    root = tmp_path_factory.mktemp("rag-members")
    d = _data_dir(root)
    (d / "extra").mkdir()
    (d / "extra" / "fixture.json").write_text('{"extra": true}', encoding="utf-8")
    bundle = root / "hand" / "rag-index.tar.zst"
    bundle.parent.mkdir()
    _hand_bundle(bundle, d)
    dest = root / "installed"
    dest.mkdir()
    out_dir = root / "release"
    spec = {
        "add": list(ADDED),
        "data_dir": str(d),
        "out_dir": str(out_dir),
        "bundle": str(bundle),
        "dest": str(dest),
    }
    spec_path = root / "members-spec.json"
    out_path = root / "members-out.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("RAG_")}
    proc = subprocess.run(
        [sys.executable, str(PROBE), "members", str(spec_path), str(out_path)],
        env=env,
        cwd=str(root),
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0 or not out_path.exists():
        tail = (proc.stdout + proc.stderr)[-2000:]
        raise RuntimeError(f"probe members rc {proc.returncode}: {tail}")
    result = json.loads(out_path.read_text(encoding="utf-8"))
    result["bundle"] = out_dir / "rag-index.tar.zst"
    result["dest"] = dest
    return result


def test_an_added_member_is_packed(added_member_run):
    pack = added_member_run["pack"]
    assert pack["error"] is None and pack["rc"] == 0, pack
    names = set(_bundle_members(added_member_run["bundle"]))
    missing = [
        n for n in ("sources_state.json", "extra/fixture.json") if n not in names
    ]
    assert not missing, f"the bundle lacks {missing}"


def test_an_added_member_is_installed(added_member_run):
    inst = added_member_run["install"]
    assert inst["error"] is None, inst
    dest = added_member_run["dest"]
    missing = [
        n
        for n in ("sources_state.json", "extra/fixture.json")
        if not (dest / n).is_file()
    ]
    skipped = added_member_run["skipped"]
    assert not missing, f"the install lacks {missing}; skipped {skipped}"
