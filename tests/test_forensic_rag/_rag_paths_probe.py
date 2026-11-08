"""Run RAG entry points in a fresh process and record the paths they touch.

Used by test_rag_data_dir.py and test_rag_bundle_members.py; not a test
module itself. A fresh process is needed because some modules read the data
dir at import time.

Usage: python _rag_paths_probe.py <mode> <spec.json> <out.json>

Modes:
  use      run the release build, a sync, refresh, status, the update check,
           the bundle install and the index load with RAG_INDEX_DIR set, and
           record, per step, the package data-dir files and the data-dir files
           it touched
  paths    run each entry point once and record the data dir it reports
  members  add members to the bundle member list before anything imports it,
           then pack a data dir with --skip-build and install a bundle
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
import traceback
from pathlib import Path

ONE_PATH = {
    "open",
    "os.mkdir",
    "os.remove",
    "os.rmdir",
    "os.listdir",
    "os.scandir",
    "os.chmod",
    "os.utime",
    "os.truncate",
    "shutil.rmtree",
    "sqlite3.connect",
}
TWO_PATHS = {
    "os.rename",
    "os.replace",
    "os.symlink",
    "os.link",
    "shutil.copyfile",
    "shutil.copytree",
    "shutil.move",
}
STOCK_MEMBERS = ("chroma", "sources", "metadata.json", "user_state.json")


class Recorder:
    """An audit hook that records (event, raw path, cwd) per named step."""

    def __init__(self) -> None:
        self.step: str | None = None
        self.events: dict[str, list[list[str]]] = {}
        self._busy = False

    def __call__(self, event: str, args: tuple) -> None:
        if self.step is None or self._busy:
            return
        if event in ONE_PATH:
            wanted = args[:1]
        elif event in TWO_PATHS:
            wanted = args[:2]
        else:
            return
        self._busy = True
        try:
            for arg in wanted:
                if arg is None or isinstance(arg, int):
                    continue
                try:
                    raw = os.fsdecode(arg)
                except TypeError:
                    continue
                self.events.setdefault(self.step, []).append([event, raw, os.getcwd()])
        except BaseException:
            pass
        finally:
            self._busy = False


def _roots(path: str) -> set[str]:
    return {os.path.abspath(path), os.path.realpath(path)}


def _under(path: str, roots: set[str]) -> bool:
    return any(path == r or path.startswith(r + os.sep) for r in roots)


def _call(fn, argv: list[str] | None = None) -> dict:
    """Run fn, returning its result or exit code and any error."""
    out: dict = {"rc": None, "error": None, "stdout": ""}
    saved = sys.argv
    buf = io.StringIO()
    try:
        if argv is not None:
            sys.argv = argv
        with contextlib.redirect_stdout(buf):
            result = fn()
        out["rc"] = result if isinstance(result, int) else 0
    except SystemExit as e:
        out["rc"] = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except BaseException:
        out["error"] = traceback.format_exc(limit=3).strip().splitlines()[-1]
    finally:
        sys.argv = saved
    out["stdout"] = buf.getvalue()
    return out


def _sha(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def mode_use(spec: dict) -> dict:
    data_dir = spec["data_dir"]
    from rag_mcp import refresh, sources, status
    from rag_mcp.index import RAGIndex
    from rag_mcp.scripts import build_release, download_index
    from rag_mcp.utils import PACKAGE_DATA_DIR

    sources.SOURCES.clear()
    for fx in spec["fixtures"]:
        sources.SOURCES[fx["name"]] = sources.SourceConfig(
            name=fx["name"],
            description=f"Fixture {fx['name']}",
            source_type="github_commits",
            repo=f"fixture/{fx['name']}",
            branch="main",
            parser=fx["parser"],
            paths=[],
        )
    version = spec["version"]
    sources.get_latest_commit = lambda repo, branch: version
    build_release.MIN_RECORD_COUNT = 1

    def load_index():
        RAGIndex().load()

    steps = [
        (
            "build_release",
            lambda: build_release.main(),
            ["build_release", "--output-dir", spec["out_dir"]],
        ),
        ("sync_source", lambda: sources.sync_source(spec["sync"], force=True), None),
        ("refresh", lambda: refresh.main(), ["refresh"]),
        ("status", lambda: status.main(), ["status", "--json"]),
        ("check_source_updates", lambda: sources.check_source_updates(), None),
        ("download_index", lambda: download_index.main(), ["download_index"]),
        ("RAGIndex", load_index, None),
    ]
    rec = Recorder()
    sys.addaudithook(rec)
    results: dict = {}
    state_sha = None
    for name, fn, argv in steps:
        rec.step = name
        results[name] = _call(fn, argv)
        rec.step = None
        if name == "build_release":
            state_sha = _sha(Path(data_dir) / "sources_state.json")

    pkg_roots = _roots(str(PACKAGE_DATA_DIR))
    d_roots = _roots(data_dir)
    exempt = {
        os.path.join(r, n)
        for r in pkg_roots
        for n in ("user_state.json", "tuning_config.json")
    }
    for name, _fn, _argv in steps:
        pkg: set[str] = set()
        under_d = 0
        for _event, raw, cwd in rec.events.get(name, []):
            path = os.path.normpath(os.path.join(cwd, raw))
            if _under(path, pkg_roots) and path not in exempt:
                pkg.add(path)
            if _under(path, d_roots):
                under_d += 1
        results[name]["package_paths"] = sorted(pkg)
        results[name]["under_data_dir"] = under_d
    return {"steps": results, "state_sha": state_sha}


def _first(events: list[list[str]], event: str, basename: str | None = None):
    for ev, raw, _cwd in events:
        if ev == event and (basename is None or os.path.basename(raw) == basename):
            return raw
    return None


def mode_paths(spec: dict) -> dict:
    os.chdir(spec["import_cwd"])
    from rag_mcp import build, refresh, status
    from rag_mcp.index import RAGIndex
    from rag_mcp.scripts import download_index

    index_dir: list[str] = []

    def make_index() -> None:
        index_dir.append(str(RAGIndex().index_dir))

    runs = {
        "build": (build.main, ["build", "--dry-run"]),
        "refresh": (refresh.main, ["refresh"]),
        "status": (status.main, ["status", "--verbose", "--no-check"]),
        "download": (download_index.main, ["download_index"]),
        "index": (make_index, None),
    }
    os.chdir(spec["run_cwd"])
    rec = Recorder()
    sys.addaudithook(rec)
    out: dict = {}
    for entry, explicit in spec["entries"]:
        key = f"{entry}|{explicit or ''}"
        fn, argv = runs[entry]
        if explicit is not None:
            flag = "--dest" if entry == "download" else "--data-dir"
            argv = [*argv, flag, explicit]
        index_dir.clear()
        rec.step = key
        result = _call(fn, argv)
        rec.step = None
        events = rec.events.get(key, [])
        if entry in ("build", "refresh"):
            raw = _first(events, "open", "metadata.json")
            result["reported"] = None if raw is None else os.path.dirname(raw)
        elif entry == "download":
            result["reported"] = _first(events, "os.mkdir")
        elif entry == "status":
            lines = result["stdout"].splitlines()
            data = [ln.split(":", 1)[1].strip() for ln in lines if "Data dir:" in ln]
            srcs = [ln.split(":", 1)[1].strip() for ln in lines if "Sources dir:" in ln]
            result["reported"] = data[0] if data else None
            result["sources_dir"] = srcs[0] if srcs else None
        else:
            result["reported"] = index_dir[0] if index_dir else None
        result.pop("stdout")
        out[key] = result
    return out


def mode_members(spec: dict) -> dict:
    from rag_mcp import constants

    current = tuple(getattr(constants, "BUNDLE_MEMBERS", STOCK_MEMBERS))
    added = tuple(m for m in spec["add"] if m not in current)
    constants.BUNDLE_MEMBERS = current + added

    from rag_mcp.scripts import build_release, download_index

    build_release.MIN_RECORD_COUNT = 0
    os.environ["RAG_INDEX_DIR"] = spec["data_dir"]
    pack = _call(
        build_release.main,
        ["build_release", "--skip-build", "--output-dir", spec["out_dir"]],
    )
    skipped: list[str] = []

    def install() -> None:
        bundle, dest = Path(spec["bundle"]), Path(spec["dest"])
        skipped.extend(download_index._extract_bundle(bundle, dest))

    inst = _call(install)
    return {"pack": pack, "install": inst, "skipped": skipped}


def main() -> int:
    mode, spec_path, out_path = sys.argv[1:4]
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    modes = {"use": mode_use, "paths": mode_paths, "members": mode_members}
    result = modes[mode](spec)
    Path(out_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
