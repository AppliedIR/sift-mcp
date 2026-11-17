"""The triage downloader's side of the update's data offer.

``--check`` reports the installed and newest release, a failed check exits with one
line, an installed release no reader can name is "unknown", a release other than
RELEASE_TAG is refused under its floors, and a download that would not fit is
refused before any data asset is fetched. A present DB is never absent, and a
Ctrl-C in the swap puts the installed DBs back. Each case serves a local fixture
release through the module's seams; the asset list carries each file's size as the
GitHub API does, and metadata.json (the unpacked sizes) is read through ``urlopen``.
"""

from __future__ import annotations

import io
import json
import os
import sys
import types
import urllib.error
import urllib.parse
from pathlib import Path

import pytest
from windows_triage import release_manifest
from windows_triage.scripts import download_databases as dd

from .test_download_tag import (
    _files,
    _fixture_dbs,
    _plant_prior,
    _release_dir,
    _set_counts,
    _stages,
)

TAG = release_manifest.RELEASE_TAG
OTHER_TAG = "triage-db-v2099.01.01"
OFFLINE = urllib.error.URLError("[Errno -3] Temporary failure in name resolution")


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _url(p: Path) -> str:
    """metadata.json is read through urllib (which needs a URL); the data assets go
    through the download seam, which takes the path."""
    return p.as_uri() if p.name == "metadata.json" else str(p)


def _serve(monkeypatch, release: Path, tag_name: str = TAG) -> types.SimpleNamespace:
    """Serve ``release`` (adding its metadata.json of unpacked sizes) as the newest
    and the named release. Returns the data assets downloaded, the sleeps, and the
    release record."""
    dbs = [p for p in sorted(release.iterdir()) if p.suffix == ".zst"]
    meta = {"databases": {p.stem: {"size_bytes": 10 * p.stat().st_size} for p in dbs}}
    (release / "metadata.json").write_text(json.dumps(meta))
    record = {
        "tag_name": tag_name,
        "prerelease": False,
        "assets": [
            {"name": p.name, "url": _url(p), "size": p.stat().st_size}
            for p in sorted(release.iterdir())
        ],
    }
    seen = types.SimpleNamespace(downloaded=[], sleeps=[], release=record, meta=meta)

    def download_asset(url, dest):
        seen.downloaded.append(Path(url).name)
        Path(dest).write_bytes(Path(url).read_bytes())

    def urlopen(req, timeout=None):
        url = urllib.parse.urlparse(getattr(req, "full_url", req))
        assert url.scheme == "file", url
        return _Response(Path(url.path).read_bytes())

    monkeypatch.setattr(dd, "_github_headers", dict)  # no `gh auth token` run
    monkeypatch.setattr(dd, "_fetch_release", lambda tag: record)
    monkeypatch.setattr(dd, "_newest_release", lambda: record, raising=False)
    monkeypatch.setattr(dd, "_download_asset", download_asset)
    monkeypatch.setattr(dd.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(dd.time, "sleep", seen.sleeps.append)
    return seen


def _check():
    check = getattr(dd, "check", None)
    assert check is not None, "no --check: the module has no check()"
    return check


def _installed(tmp_path, monkeypatch) -> tuple[Path, types.SimpleNamespace]:
    dbs = _fixture_dbs(tmp_path / "dbs")
    seen = _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    assert dd.download_databases(dest) is True
    return dest, seen


def _free(monkeypatch, free: int) -> None:
    usage = types.SimpleNamespace(total=free, used=0, free=free)
    monkeypatch.setattr(dd.shutil, "disk_usage", lambda path: usage)


# --- D-2 (sift leg): the newest installed is reported as current -------------------


def test_d2_check_reports_the_installed_release_as_the_newest(tmp_path, monkeypatch):
    dest, seen = _installed(tmp_path, monkeypatch)
    sizes = {a["name"]: a["size"] for a in seen.release["assets"]}
    want = sum(sizes[n] for n in (*dd.ASSETS, "metadata.json"))
    assert _check()(dest) == {
        "installed": TAG,
        "absent": False,
        "newest": TAG,
        "download_bytes": want,
    }


def test_d2_check_of_an_empty_dest_is_absent_and_unknown(tmp_path, monkeypatch):
    _serve(
        monkeypatch, _release_dir(tmp_path / "release", _fixture_dbs(tmp_path / "d"))
    )
    got = _check()(tmp_path / "dest")
    assert (got["installed"], got["absent"], got["newest"]) == ("unknown", True, TAG)


def test_d2_check_prints_one_json_line(tmp_path, monkeypatch, capsys):
    dest, _ = _installed(tmp_path, monkeypatch)
    capsys.readouterr()
    monkeypatch.setattr(
        sys, "argv", ["download_databases", "--check", "--dest", str(dest)]
    )
    with pytest.raises(SystemExit) as stop:
        dd.main()
    out = capsys.readouterr().out
    assert stop.value.code == 0, out
    assert out.count("\n") == 1
    assert json.loads(out) == _check()(dest)


# --- D-3 (sift leg): a failed check is one line and a non-zero exit ----------------


def test_d3_a_failed_check_exits_with_one_line_naming_the_cause(
    tmp_path, monkeypatch, capsys
):
    def offline():
        raise OFFLINE

    monkeypatch.setattr(dd, "_newest_release", offline, raising=False)
    argv = ["download_databases", "--check", "--dest", str(tmp_path / "dest")]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as stop:
        dd.main()
    assert stop.value.code == f"Could not check for newer triage databases: {OFFLINE}"
    assert capsys.readouterr().out == ""
    assert not (tmp_path / "dest").exists() or not any((tmp_path / "dest").iterdir())


# --- Y5 (sift leg): a DB changed since install is "unknown" --------------------------


def test_y5_a_db_changed_since_install_is_unknown(tmp_path, monkeypatch):
    dest, _ = _installed(tmp_path, monkeypatch)
    other = _fixture_dbs(tmp_path / "other", marker="local")
    (dest / "context.db").write_bytes(other["context.db"].read_bytes())
    got = _check()(dest)
    assert (got["installed"], got["absent"], got["newest"]) == ("unknown", False, TAG)


# --- D-11 (reduced): another release is refused under one floor ---------------------


def test_d11_another_release_under_a_floor_is_refused_and_changes_nothing(
    tmp_path, monkeypatch, capsys
):
    dbs = _fixture_dbs(tmp_path / "dbs")
    seen = _serve(monkeypatch, _release_dir(tmp_path / "release", dbs), OTHER_TAG)
    _set_counts(monkeypatch, dbs)
    counts = {**release_manifest.COUNTS}
    counts["context.db"] = {**counts["context.db"], "lolbins": 4}  # floor 2, holds 1
    monkeypatch.setattr(release_manifest, "COUNTS", counts)
    dest = tmp_path / "dest"
    before = _plant_prior(dest, tmp_path)
    assert dd.download_databases(dest, OTHER_TAG) is False
    out = capsys.readouterr().out
    assert "context.db: lolbins has 1 rows, under its floor of 2" in out
    assert "Database verification failed." in out
    assert _files(dest, before) == before
    assert _stages(dest) == []
    assert seen.downloaded  # refused at the verify, after the download


# --- Y3 (reduced): free space is checked before any data asset -----------------------


def _need(seen) -> int:
    sizes = {a["name"]: a["size"] for a in seen.release["assets"]}
    unpacked = sum(d["size_bytes"] for d in seen.meta["databases"].values())
    return sum(sizes[n] for n in dd.ASSETS) + unpacked


def test_y3_one_byte_short_is_refused_before_any_data_asset(
    tmp_path, monkeypatch, capsys
):
    dbs = _fixture_dbs(tmp_path / "dbs")
    seen = _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    before = _plant_prior(dest, tmp_path)
    _free(monkeypatch, _need(seen) - 1)
    assert dd.download_databases(dest) is False
    want = f"Not enough free space ({_need(seen):,} bytes). Nothing was changed."
    assert want in capsys.readouterr().out
    assert seen.downloaded == []
    assert _files(dest, before) == before
    assert _stages(dest) == []


def test_y3_free_space_equal_to_the_need_installs(tmp_path, monkeypatch):
    dbs = _fixture_dbs(tmp_path / "dbs")
    seen = _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    _plant_prior(dest, tmp_path)
    _free(monkeypatch, _need(seen))
    assert dd.download_databases(dest) is True
    assert dd.read_installed_tag(dest) == TAG


# --- D-2 (sift leg): a present DB is never "absent" ----------------------------------


def test_d2_a_changed_db_with_the_other_missing_is_not_absent(tmp_path, monkeypatch):
    """Absent would let VHIR_ASSUME_DEFAULTS download over the changed DB unasked."""
    dest, _ = _installed(tmp_path, monkeypatch)
    other = _fixture_dbs(tmp_path / "other", marker="local")
    (dest / "known_good.db").write_bytes(other["known_good.db"].read_bytes())
    (dest / "context.db").unlink()
    got = _check()(dest)
    assert (got["installed"], got["absent"], got["newest"]) == ("unknown", False, TAG)


def test_d2_an_unchanged_db_with_the_other_missing_is_not_absent(tmp_path, monkeypatch):
    dest, _ = _installed(tmp_path, monkeypatch)
    (dest / "context.db").unlink()
    got = _check()(dest)
    assert (got["installed"], got["absent"]) == ("unknown", False)


# --- D-6 (sift leg): a Ctrl-C in the swap leaves the installed DBs -------------------


def _interrupt_replace(monkeypatch, on: set[int]) -> list[int]:
    """The os.replace calls numbered in ``on`` (from 1) raise KeyboardInterrupt."""
    calls: list[int] = []
    real = os.replace

    def replace(src, dst, *args, **kwargs):
        calls.append(len(calls) + 1)
        if calls[-1] in on:
            raise KeyboardInterrupt
        return real(src, dst, *args, **kwargs)

    monkeypatch.setattr(dd.os, "replace", replace)
    return calls


def _run(fn, *args):
    """fn's result, or "interrupted" when the KeyboardInterrupt got out (one that
    leaves a test stops the whole pytest run)."""
    try:
        return fn(*args)
    except KeyboardInterrupt:
        return "interrupted"


def _prior_install(tmp_path, monkeypatch) -> tuple[Path, dict[str, bytes]]:
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    return dest, _plant_prior(dest, tmp_path)


def test_d6_a_ctrl_c_in_the_swap_puts_the_installed_dbs_back(
    tmp_path, monkeypatch, capsys
):
    dest, before = _prior_install(tmp_path, monkeypatch)
    calls = _interrupt_replace(monkeypatch, {3})
    got = _run(dd.download_databases, dest)
    assert len(calls) >= 3, "the install did not reach a third move"
    assert _files(dest, before) == before, "a Ctrl-C in the swap lost the prior DBs"
    assert _stages(dest) == []
    assert got is False
    assert "the installed databases were not changed" in capsys.readouterr().out


def test_d6_a_ctrl_c_in_the_undo_keeps_the_stage_with_the_old_files(
    tmp_path, monkeypatch
):
    dest, before = _prior_install(tmp_path, monkeypatch)
    _interrupt_replace(monkeypatch, {3, 4})
    _run(dd.download_databases, dest)
    stages = _stages(dest)
    assert len(stages) == 1, "the stage holding the old DBs was removed"
    old = stages[0] / "old"
    for name in ("known_good.db", "installed_release.json"):
        assert (old / name).read_bytes() == before[name], name
