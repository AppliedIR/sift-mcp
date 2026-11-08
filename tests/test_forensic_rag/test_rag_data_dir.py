"""One data dir for every RAG entry point.

With RAG_INDEX_DIR set, the release build, a source sync, refresh, status,
the update check, the bundle install and the index read and write their data
files under it and never under the package's own data dir. Whatever form the
data dir is given in (empty, relative, ~/, a symlink, as RAG_INDEX_DIR or as
--dest / --data-dir), every entry point reports the same resolved path.

Each case runs in a fresh process (_rag_paths_probe.py) with an audit hook
recording the paths touched. Sources are local bare repos reached through
git's insteadOf in an isolated HOME; nothing goes to the network.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

rag_utils = pytest.importorskip("rag_mcp.utils")
pytest.importorskip("chromadb")
zstandard = pytest.importorskip("zstandard")

PACKAGE_DATA_DIR = rag_utils.PACKAGE_DATA_DIR
PROBE = Path(__file__).with_name("_rag_paths_probe.py")
MODEL = "BAAI/bge-base-en-v1.5"
VERSION = "fixture00001"

FIXTURES = {
    "fixture_a": (
        "parse_velociraptor",
        {
            "content/exchange/artifacts/Fixture.Alpha.yaml": (
                "name: Fixture.Alpha\ndescription: A fixture artifact\n"
                "type: CLIENT\n"
            )
        },
    ),
    "fixture_b": (
        "parse_hijacklibs",
        {
            "yml/fixture_b.yml": (
                "Name: fixture_b.dll\nAuthor: Fixture\n"
                "Description: A fixture entry\n"
            )
        },
    ),
    "fixture_c": (
        "parse_kape",
        {
            "Targets/Fixture/Fixture.tkape": (
                "Description: Fixture target\nAuthor: Fixture\nVersion: 1.0\n"
                "Id: fixture-c\nTargets: []\n"
            )
        },
    ),
}
ENABLED = ("fixture_a", "fixture_b")
DISABLED = "fixture_c"

USE_STEPS = (
    "build_release",
    "sync_source",
    "refresh",
    "status",
    "check_source_updates",
    "download_index",
    "RAGIndex",
)


def _git(*args: str, cwd: Path | None = None, env: dict | None = None) -> None:
    subprocess.run(
        ["git", "-c", "init.defaultBranch=main", *args],
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
    )


def _isolated_env(home: Path, **extra: str) -> dict:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("RAG_", "GIT_")) and k != "GITHUB_TOKEN"
    }
    env.update(
        HOME=str(home),
        GIT_CONFIG_NOSYSTEM="1",
        GITHUB_TOKEN="fixture-token-not-used",
        HTTPS_PROXY="http://127.0.0.1:9",
        https_proxy="http://127.0.0.1:9",
        NO_PROXY="",
        no_proxy="",
        ANONYMIZED_TELEMETRY="False",
        HF_HUB_OFFLINE="1",
        TRANSFORMERS_OFFLINE="1",
    )
    env.update(extra)
    return env


def _bare_repos(root: Path, home: Path) -> None:
    """One local bare repo per fixture source, each with a root LICENSE, and
    an insteadOf in HOME's .gitconfig pointing its GitHub URL at it."""
    env = _isolated_env(home)
    config = []
    for name, (_parser, files) in FIXTURES.items():
        work = root / "work" / name
        for rel, text in {**files, "LICENSE": f"Fixture licence {name}\n"}.items():
            (work / rel).parent.mkdir(parents=True, exist_ok=True)
            (work / rel).write_text(text, encoding="utf-8")
        _git("init", "-q", str(work), env=env)
        _git("add", "-A", cwd=work, env=env)
        _git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
            cwd=work,
            env=env,
        )
        bare = root / "bare" / f"{name}.git"
        _git("clone", "-q", "--bare", str(work), str(bare), env=env)
        config.append(
            f'[url "file://{root / "bare" / name}"]\n'
            f"\tinsteadOf = https://github.com/fixture/{name}\n"
        )
    (home / ".gitconfig").write_text("".join(config), encoding="utf-8")


def _probe(mode: str, spec: dict, root: Path, env: dict) -> tuple[dict, str]:
    spec_path = root / f"{mode}-spec.json"
    out_path = root / f"{mode}-out.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(PROBE), mode, str(spec_path), str(out_path)],
        env=env,
        capture_output=True,
        text=True,
        timeout=1800,
        cwd=spec.get("import_cwd", str(root)),
    )
    if proc.returncode != 0 or not out_path.exists():
        tail = (proc.stdout + proc.stderr)[-2000:]
        raise RuntimeError(f"probe {mode} rc {proc.returncode}: {tail}")
    return json.loads(out_path.read_text(encoding="utf-8")), proc.stdout


def _model_cached() -> bool:
    try:
        from huggingface_hub import snapshot_download

        snapshot_download(MODEL, local_files_only=True)
    except Exception:
        return False
    return True


@pytest.fixture(scope="module")
def package_data_guard():
    """Leave the package data dir as it was: remove only what the run made."""
    existed = PACKAGE_DATA_DIR.exists()
    before = set()
    if existed:
        before = set(PACKAGE_DATA_DIR.rglob("*"))
    yield
    if not existed:
        shutil.rmtree(PACKAGE_DATA_DIR, ignore_errors=True)
        return
    made = [p for p in PACKAGE_DATA_DIR.rglob("*") if p not in before]
    for p in sorted(made, key=lambda q: len(q.parts), reverse=True):
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p, ignore_errors=True)
        else:
            p.unlink(missing_ok=True)


def _bundle_members(path: Path) -> dict[str, bytes | None]:
    members: dict[str, bytes | None] = {}
    with open(path, "rb") as fh:
        with zstandard.ZstdDecompressor().stream_reader(fh) as reader:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                for m in tar:
                    f = tar.extractfile(m) if m.isreg() else None
                    members[m.name] = f.read() if f else None
    return members


@pytest.fixture(scope="module")
def use_run(tmp_path_factory, package_data_guard):
    """The seven steps with RAG_INDEX_DIR set: two fixture sources enabled,
    one disabled in RAG_INDEX_DIR/sources_config.json with its JSONL already
    in RAG_INDEX_DIR/sources/. The package data dir gets a sources_config.json
    and a sources_state.json only if it has none, so a step that reads the
    package files is seen reading them."""
    if not _model_cached():
        pytest.skip(f"embedding model {MODEL} not in the local cache")
    root = tmp_path_factory.mktemp("rag-use")
    home = root / "home"
    home.mkdir()
    _bare_repos(root, home)
    data_dir = root / "data"
    (data_dir / "sources").mkdir(parents=True)
    (data_dir / "sources_config.json").write_text(
        json.dumps({"disabled_sources": [DISABLED]}), encoding="utf-8"
    )
    (data_dir / "sources" / f"{DISABLED}.jsonl").write_text(
        json.dumps({"text": "planted", "metadata": {"source": "kape"}}) + "\n",
        encoding="utf-8",
    )
    PACKAGE_DATA_DIR.mkdir(parents=True, exist_ok=True)
    plants = {
        "sources_config.json": {"disabled_sources": [DISABLED]},
        "sources_state.json": {"version": 1, "sources": {}},
    }
    for name, body in plants.items():
        if not (PACKAGE_DATA_DIR / name).exists():
            (PACKAGE_DATA_DIR / name).write_text(json.dumps(body), encoding="utf-8")
    knowledge = root / "knowledge"
    knowledge.mkdir()
    out_dir = root / "release"
    spec = {
        "data_dir": str(data_dir),
        "out_dir": str(out_dir),
        "fixtures": [{"name": n, "parser": p} for n, (p, _f) in FIXTURES.items()],
        "version": VERSION,
        "sync": ENABLED[0],
    }
    env = _isolated_env(
        home, RAG_INDEX_DIR=str(data_dir), RAG_KNOWLEDGE_DIR=str(knowledge)
    )
    result, _stdout = _probe("use", spec, root, env)
    result["data_dir"] = data_dir
    result["bundle"] = out_dir / "rag-index.tar.zst"
    return result


def test_the_release_build_packs_the_enabled_sources_only(use_run):
    step = use_run["steps"]["build_release"]
    assert step["error"] is None and step["rc"] == 0, step
    assert "Build failed" not in step["stdout"], step["stdout"][-500:]
    assert use_run["bundle"].is_file(), "no bundle written"
    members = _bundle_members(use_run["bundle"])
    packed = {
        n.split("/", 1)[1]
        for n in members
        if n.startswith("sources/") and n.count("/") == 1 and n.endswith(".jsonl")
    }
    want = {f"{n}.jsonl" for n in ENABLED}
    assert packed == want, f"bundle sources/ holds {sorted(packed)}"


def test_the_release_bundle_state_is_the_data_dir_state(use_run):
    step = use_run["steps"]["build_release"]
    assert step["error"] is None and step["rc"] == 0, step
    members = _bundle_members(use_run["bundle"])
    packed = members.get("sources_state.json")
    assert packed is not None, "no sources_state.json in the bundle"
    assert use_run["state_sha"] is not None, "no sources_state.json in the data dir"
    assert hashlib.sha256(packed).hexdigest() == use_run["state_sha"]


@pytest.mark.parametrize("step", USE_STEPS)
def test_each_step_touches_no_package_data_file(use_run, step):
    rec = use_run["steps"][step]
    assert rec["error"] is None, f"{step} raised {rec['error']}"
    paths = rec["package_paths"]
    assert not paths, f"{step} touched package data files: {' '.join(paths)}"


@pytest.mark.parametrize("step", USE_STEPS)
def test_each_step_uses_the_data_dir(use_run, step):
    rec = use_run["steps"][step]
    assert rec["error"] is None, f"{step} raised {rec['error']}"
    assert rec["under_data_dir"] > 0, f"{step} touched nothing under RAG_INDEX_DIR"


# The data dir as each entry point reports it
#   build, refresh: the dir of the first metadata.json they open
#   download: the first dir it creates
#   status: its "Data dir:" line (and "Sources dir:" is that dir's sources/)
#   index: RAGIndex().index_dir
ENV_CASES = ("empty", "rel-same-cwd", "rel-other-cwd", "home", "symlink")
ENTRIES = ("build", "refresh", "download", "status", "index")
EXPLICIT_CASES = ("rel", "home")
EXPLICIT_ENTRIES = ("build", "refresh", "download", "status")
ENV_VALUES = {
    "empty": "",
    "rel-same-cwd": "rel/x",
    "rel-other-cwd": "rel/x",
    "home": "~/x",
    "symlink": None,
}
EXPLICIT_VALUES = {"rel": "rel/x", "home": "~/x"}


def _expected(value: str, cwd: Path, home: Path) -> str:
    if value == "":
        return str(PACKAGE_DATA_DIR.resolve())
    if value.startswith("~/"):
        value = str(home / value[2:])
    return os.path.realpath(os.path.join(cwd, value))


@pytest.fixture(scope="module")
def paths_run(tmp_path_factory, package_data_guard):
    root = tmp_path_factory.mktemp("rag-paths")
    home = root / "home"
    a = root / "a"
    b = root / "b"
    knowledge = root / "knowledge"
    for d in (home, a, b, knowledge):
        d.mkdir()
    target = root / "target"
    link = root / "link"
    target.mkdir()
    link.symlink_to(target)
    # status prints its dirs only when an index dir is there
    for d in (a / "rel/x", b / "rel/x", home / "x", target, PACKAGE_DATA_DIR):
        (d / "chroma").mkdir(parents=True, exist_ok=True)
    results: dict = {}

    def run(label: str, env_value: str | None, run_cwd: Path, entries) -> None:
        extra = {"RAG_KNOWLEDGE_DIR": str(knowledge)}
        if env_value is not None:
            extra["RAG_INDEX_DIR"] = env_value
        spec = {"import_cwd": str(a), "run_cwd": str(run_cwd), "entries": entries}
        out, _stdout = _probe("paths", spec, root / label, _isolated_env(home, **extra))
        results[label] = (out, run_cwd)

    for case in ENV_CASES:
        (root / case).mkdir()
        value = str(link) if case == "symlink" else ENV_VALUES[case]
        run_cwd = b if case == "rel-other-cwd" else a
        run(case, value, run_cwd, [[e, None] for e in ENTRIES])
    (root / "explicit").mkdir()
    run(
        "explicit",
        None,
        a,
        [[e, EXPLICIT_VALUES[c]] for c in EXPLICIT_CASES for e in EXPLICIT_ENTRIES],
    )
    return results, home, link


def _check(rec: dict, want: str, entry: str) -> None:
    got = rec["reported"]
    assert got == want, f"{entry} reports {got!r}, want {want!r} ({rec['error']})"
    if entry == "status":
        srcs = rec["sources_dir"]
        assert srcs == os.path.join(want, "sources"), f"status sources dir {srcs!r}"


@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("case", ENV_CASES)
def test_rag_index_dir_resolves_alike_for_every_entry_point(paths_run, case, entry):
    results, home, link = paths_run
    out, run_cwd = results[case]
    value = str(link) if case == "symlink" else ENV_VALUES[case]
    _check(out[f"{entry}|"], _expected(value, run_cwd, home), entry)


@pytest.mark.parametrize("entry", EXPLICIT_ENTRIES)
@pytest.mark.parametrize("case", EXPLICIT_CASES)
def test_an_explicit_data_dir_resolves_alike(paths_run, case, entry):
    results, home, _link = paths_run
    out, run_cwd = results["explicit"]
    value = EXPLICIT_VALUES[case]
    _check(out[f"{entry}|{value}"], _expected(value, run_cwd, home), entry)
