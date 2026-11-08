"""What a RAG sync records as a source's version, and what the update check
says about it.

Every run goes through _rag_versions_probe.py in a fresh process on a scratch
copy of the package: the copy's own data dir (PROJECT_ROOT/"data") is where
the package reads its state and config whatever RAG_INDEX_DIR says, so a row
that needs both read sets RAG_INDEX_DIR to that same dir, and a row that
needs them apart points it elsewhere. The version lookups are stubbed at
their functions, URL fetches are answered from fixture files only, clones
reach a local fixture repo through insteadOf in an isolated HOME, and a git
shim first on PATH logs each git call.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

sources = pytest.importorskip("rag_mcp.sources")

GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="the fixture repos need git")

PROBE = Path(__file__).with_name("_rag_versions_probe.py")
ALL = list(sources.SOURCES)
EMBEDDED = sorted(n for n, s in sources.SOURCES.items() if s.source_type == "embedded")
ONLINE = sorted(n for n in ALL if n not in EMBEDDED)
MITRE = sources.SOURCES["mitre_attack"].repo
KEV_URL = sources.SOURCES["cisa_kev"].repo
SIGMA = sources.SOURCES["sigma"].repo
HIJACK = sources.SOURCES["hijacklibs"].repo
RAW = "https://raw.githubusercontent.com/"
STIX_PREFIX = f"{RAW}{MITRE}/"
HEX = "0123456789ab"
# A line about a failed version lookup, whatever its exact words
LOOKUP_FAILED = re.compile(r"lookup.*(fail|could not)|(fail|could not).*lookup", re.I)
RECORDS_LINE = re.compile(r"^  (\w+): (\d+) records$", re.M)

FX_REL = {
    "name": "fx_rel",
    "source_type": "github_releases",
    "repo": "fixture/fx",
    "branch": "dev",
    "parser": "parse_hijacklibs",
}
FX_COM = {**FX_REL, "name": "fx_com", "source_type": "github_commits"}

STIX = {
    "type": "bundle",
    "objects": [
        {
            "type": "attack-pattern",
            "name": "Fixture technique",
            "description": "A fixture technique.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T0001"}
            ],
            "x_mitre_platforms": ["Windows"],
            "kill_chain_phases": [{"phase_name": "execution"}],
        }
    ],
}
KEV = {
    "catalogVersion": "2026.11.01",
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-0001",
            "vendorProject": "Fixture",
            "product": "Fixture",
            "vulnerabilityName": "Fixture vulnerability",
            "shortDescription": "A fixture entry.",
        }
    ],
}
YML_MAIN = "Name: one.dll\nAuthor: Fixture\nDescription: Fixture entry one.\n"
YML_DEV = "Name: two.dll\nAuthor: Fixture\nDescription: Fixture entry two.\n"


@dataclass
class Rig:
    root: Path
    src: Path  # the scratch package's src dir, first on sys.path
    data: Path  # PROJECT_ROOT/"data" in the scratch copy
    home: Path
    shim: Path
    bare: Path  # fixture repo: HEAD main, a dev branch whose tip differs
    main_tip: str
    dev_tip: str
    empty: Path
    stix: Path
    kev: Path
    runs: int = 0


def _clean_env() -> dict:
    drop = ("RAG_", "GIT_")
    env = {k: v for k, v in os.environ.items() if not k.startswith(drop)}
    env.pop("PYTHONPATH", None)
    return env


def _git(home: Path, *args: str, cwd: Path | None = None) -> str:
    env = {**_clean_env(), "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"}
    proc = subprocess.run(
        [GIT, *args], cwd=cwd, env=env, capture_output=True, text=True, check=True
    )
    return proc.stdout.strip()


def _gitconfig(remote: Path, redirect_hijacklibs: bool) -> str:
    """Every github.com URL to a path that does not exist, except the fixture
    repo's (and hijacklibs', if asked): the longest insteadOf match wins."""
    lines = [
        "[user]",
        "\tname = Fixture",
        "\temail = fixture@example.invalid",
        "[init]",
        "\tdefaultBranch = main",
        "[commit]",
        "\tgpgsign = false",
        '[protocol "file"]',
        "\tallow = always",
        '[url "file:///nonexistent-fixture-remote/"]',
        "\tinsteadOf = https://github.com/",
        f'[url "file://{remote}"]',
        "\tinsteadOf = https://github.com/fixture/fx",
    ]
    if redirect_hijacklibs:
        lines.append(f"\tinsteadOf = https://github.com/{HIJACK}")
    return "\n".join(lines) + "\n"


SHIM_LINES = [
    "#!/bin/sh",
    'if [ -n "$PROBE_GIT_LOG" ]; then',
    '  printf "%s\\n" "$*" >> "$PROBE_GIT_LOG"',
    "fi",
]


def make_rig(root: Path, redirect_hijacklibs: bool = True) -> Rig:
    """A scratch package copy, a fixture repo, an isolated HOME and a git shim."""
    src = root / "pkg" / "src"
    shutil.copytree(
        Path(sources.__file__).parent,
        src / "rag_mcp",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    data = root / "pkg" / "data"
    data.mkdir()
    home = root / "home"
    home.mkdir()
    remote = root / "remotes" / "fx"
    bare = remote.with_name("fx.git")
    gitconfig = _gitconfig(remote, redirect_hijacklibs)
    (home / ".gitconfig").write_text(gitconfig, encoding="utf-8")
    work = root / "work"
    (work / "yml").mkdir(parents=True)
    _git(home, "init", "-q", "-b", "main", str(work))
    (work / "yml" / "one.yml").write_text(YML_MAIN, encoding="utf-8")
    _git(home, "add", "-A", cwd=work)
    _git(home, "commit", "-q", "-m", "main", cwd=work)
    _git(home, "checkout", "-q", "-b", "dev", cwd=work)
    (work / "yml" / "two.yml").write_text(YML_DEV, encoding="utf-8")
    _git(home, "add", "-A", cwd=work)
    _git(home, "commit", "-q", "-m", "dev", cwd=work)
    bare.parent.mkdir()
    _git(home, "clone", "-q", "--bare", str(work), str(bare))
    _git(home, "-C", str(bare), "symbolic-ref", "HEAD", "refs/heads/main")
    shim = root / "shim"
    shim.mkdir()
    script = "\n".join([*SHIM_LINES, f'exec "{GIT}" "$@"']) + "\n"
    (shim / "git").write_text(script, encoding="utf-8")
    (shim / "git").chmod(0o755)
    fixtures = root / "fixtures"
    fixtures.mkdir()
    stix = fixtures / "enterprise-attack.json"
    stix.write_text(json.dumps(STIX), encoding="utf-8")
    kev = fixtures / "kev.json"
    kev.write_text(json.dumps(KEV), encoding="utf-8")
    empty = root / "empty-knowledge"
    empty.mkdir()
    return Rig(
        root=root,
        src=src,
        data=data,
        home=home,
        shim=shim,
        bare=bare,
        main_tip=_git(home, "-C", str(bare), "rev-parse", "refs/heads/main"),
        dev_tip=_git(home, "-C", str(bare), "rev-parse", "refs/heads/dev"),
        empty=empty,
        stix=stix,
        kev=kev,
    )


def run_probe(
    rig: Rig,
    ops: list[dict],
    *,
    lookups: dict | None = None,
    responses: list | None = None,
    extra: list[dict] | None = None,
    replace: bool = False,
    index_dir: Path | None = None,
) -> dict:
    """Run ops in a fresh process on the scratch copy; RAG_INDEX_DIR is the
    copy's own data dir unless index_dir is given."""
    rig.runs += 1
    run = rig.root / "runs" / f"run{rig.runs}"
    cwd = run / "cwd"
    cwd.mkdir(parents=True)
    spec = {
        "pkg_src": str(rig.src),
        "ops": ops,
        "lookups": lookups or {},
        "responses": responses or [],
        "sources": extra or [],
        "replace_sources": replace,
    }
    spec_path, out_path, git_log = run / "spec.json", run / "out.json", run / "git.log"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    env = {
        **_clean_env(),
        "HOME": str(rig.home),
        "PATH": f"{rig.shim}{os.pathsep}{os.environ.get('PATH', '')}",
        "PYTHONPATH": str(rig.src),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HF_HUB_OFFLINE": "1",
        "PROBE_GIT_LOG": str(git_log),
        "RAG_INDEX_DIR": str(index_dir or rig.data),
    }
    proc = subprocess.run(
        [sys.executable, str(PROBE), str(spec_path), str(out_path)],
        env=env,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0 or not out_path.exists():
        tail = (proc.stdout + proc.stderr)[-2000:]
        raise RuntimeError(f"probe rc {proc.returncode}: {tail}")
    result = json.loads(out_path.read_text(encoding="utf-8"))
    logged = git_log.read_text(encoding="utf-8") if git_log.exists() else ""
    result["git"] = logged.splitlines()
    return result


def git_calls(result: dict, sub: str) -> list[str]:
    """The logged git calls whose subcommand is sub."""
    found = []
    for line in result["git"]:
        words = line.split()
        while words and words[0] in ("-C", "-c"):
            words = words[2:]
        if words and words[0] == sub:
            found.append(line)
    return found


def api_requests(op: dict) -> list[str]:
    return [u for u in op["requests"] if u.startswith("https://api.github.com/")]


def downloads(op: dict) -> list[str]:
    return [u for u in op["requests"] if u.startswith(RAW)]


def read_state(d: Path) -> dict:
    path = d / "sources_state.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def stored(d: Path, name: str):
    return read_state(d).get("sources", {}).get(name, {}).get("version")


def plant_state(dirs: list[Path], entries: dict) -> None:
    body = json.dumps({"version": 1, "sources": entries}, indent=2)
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        (d / "sources_state.json").write_text(body, encoding="utf-8")


def plant_config(d: Path, disabled: list[str]) -> None:
    d.mkdir(parents=True, exist_ok=True)
    body = json.dumps({"disabled_sources": disabled})
    (d / "sources_config.json").write_text(body, encoding="utf-8")


def only(*names: str) -> list[str]:
    """The disabled list that leaves only names enabled."""
    return [n for n in ALL if n not in names]


def entry(version: str) -> dict:
    return {
        "version": version,
        "last_sync": "2026-01-02T03:04:05+00:00",
        "records": 1,
        "cache_hash": "",
    }


PLANTED = b'{"text": "planted", "metadata": {"source": "planted"}}\n'


def plant_source(rig: Rig, name: str, version: str) -> tuple[bytes, bytes]:
    """A state entry and a cached JSONL for name, as a good earlier sync left."""
    plant_state([rig.data], {name: entry(version)})
    (rig.data / "sources").mkdir(exist_ok=True)
    (rig.data / "sources" / f"{name}.jsonl").write_bytes(PLANTED)
    return (rig.data / "sources_state.json").read_bytes(), PLANTED


def sync(name: str, force: bool = True) -> dict:
    return {"op": "sync", "name": name, "force": force}


def latest(name: str) -> dict:
    return {"op": "latest", "name": name}


def fallback_build(rig: Rig) -> dict:
    """python -m rag_mcp.build without --force-fetch: the installers' fallback."""
    argv = ["--no-bundled", "--knowledge-dir", str(rig.empty)]
    return {"op": "build", "argv": argv}


def release_build(rig: Rig) -> dict:
    """build() with the release build's arguments."""
    kwargs = {
        "force_fetch": True,
        "no_bundled": True,
        "knowledge_dir": str(rig.empty),
        "strict_sources": True,
    }
    return {"op": "build_fn", "kwargs": kwargs}


def built_records(stdout: str) -> dict[str, int]:
    return {n: int(c) for n, c in RECORDS_LINE.findall(stdout)}


def fixture_responses(rig: Rig) -> list:
    return [[STIX_PREFIX, str(rig.stix)], [KEV_URL, str(rig.kev)]]


@pytest.fixture
def rig(tmp_path):
    return make_rig(tmp_path / "rig")


# --- a cloned source records its clone's head --------------------------------


def test_cloned_release_source_stores_its_branch_head(rig):
    lookups = {
        "release": {"fixture/fx": "v9.9.9"},
        "commit": {"fixture/fx": {"tip": str(rig.bare)}},
    }
    ops = [sync("fx_rel"), latest("fx_rel")]
    out = run_probe(rig, ops, lookups=lookups, extra=[FX_REL])
    synced, looked_up = out["ops"]
    assert synced["value"]["status"] == "success", synced
    want = rig.dev_tip[:12]
    got = {"stored": stored(rig.data, "fx_rel"), "lookup": looked_up["value"]}
    assert got == {"stored": want, "lookup": want}


def test_commits_source_stores_its_branch_head(rig):
    lookups = {"commit": {"fixture/fx": {"tip": str(rig.bare)}}}
    ops = [sync("fx_com"), latest("fx_com")]
    out = run_probe(rig, ops, lookups=lookups, extra=[FX_COM])
    synced, looked_up = out["ops"]
    assert synced["value"]["status"] == "success", synced
    want = rig.dev_tip[:12]
    got = {"stored": stored(rig.data, "fx_com"), "lookup": looked_up["value"]}
    assert got == {"stored": want, "lookup": want}


def test_commits_source_stores_the_head_it_cloned(rig):
    # a commit lands on the branch between the clone and any later lookup
    lookups = {"commit": {"fixture/fx": {"advance": str(rig.bare)}}}
    out = run_probe(rig, [sync("fx_com")], lookups=lookups, extra=[FX_COM])
    assert out["ops"][0]["value"]["status"] == "success", out["ops"][0]
    assert len(git_calls(out, "clone")) == 1, out["git"]
    assert stored(rig.data, "fx_com") == rig.dev_tip[:12]


def test_hijacklibs_stores_its_branch_head(rig):
    lookups = {"commit": {HIJACK: {"tip": str(rig.bare)}}}
    ops = [sync("hijacklibs"), latest("hijacklibs")]
    out = run_probe(rig, ops, lookups=lookups)
    synced, looked_up = out["ops"]
    assert synced["value"]["status"] == "success", synced
    want = rig.main_tip[:12]
    got = {"stored": stored(rig.data, "hijacklibs"), "lookup": looked_up["value"]}
    assert got == {"stored": want, "lookup": want}


# --- a cloned source's sync asks no API --------------------------------------


def test_forced_clone_sync_asks_no_api(rig):
    out = run_probe(rig, [sync("hijacklibs")])
    assert out["ops"][0]["value"]["status"] == "success", out["ops"][0]
    assert api_requests(out["ops"][0]) == []


def test_forced_clone_sync_stores_the_clone_head(rig):
    out = run_probe(rig, [sync("hijacklibs")])
    assert out["ops"][0]["value"]["status"] == "success", out["ops"][0]
    assert stored(rig.data, "hijacklibs") == rig.main_tip[:12]


def test_release_build_of_a_cloned_source_passes(rig):
    plant_config(rig.data, only("hijacklibs"))
    out = run_probe(rig, [release_build(rig)])
    built = out["ops"][0]
    value = built["value"] or {}
    assert value.get("status") == "success", built["stdout"][-1500:]
    assert value.get("errors") == []


def test_fallback_build_of_a_cloned_source_asks_no_api(rig):
    plant_config(rig.data, only("hijacklibs"))
    out = run_probe(rig, [fallback_build(rig)])
    built = out["ops"][0]
    assert built["rc"] == 0, built["stdout"][-1500:]
    ls_remote = git_calls(out, "ls-remote")
    assert len(ls_remote) <= 1, ls_remote
    for call in ls_remote:
        assert HIJACK in call and call.split()[-1] in ("main", "refs/heads/main")
    assert api_requests(built) == []


# --- a failed lookup keeps what was there ------------------------------------


def kept(rig: Rig, name: str, plant: tuple[bytes, bytes], synced: dict) -> dict:
    value = synced["value"] or {}
    jsonl = rig.data / "sources" / f"{name}.jsonl"
    message = value.get("message", "")
    return {
        "status": value.get("status"),
        "names_lookup": bool(re.search(r"lookup|version", message)),
        "state_kept": (rig.data / "sources_state.json").read_bytes() == plant[0],
        "jsonl_kept": jsonl.exists() and jsonl.read_bytes() == plant[1],
    }


KEPT = {"status": "error", "names_lookup": True, "state_kept": True, "jsonl_kept": True}


def test_failed_tag_lookup_keeps_the_planted_state(rig):
    plant = plant_source(rig, "mitre_attack", "v19.0")
    out = run_probe(
        rig,
        [sync("mitre_attack")],
        lookups={"release": {MITRE: None}},
        responses=fixture_responses(rig),
    )
    assert kept(rig, "mitre_attack", plant, out["ops"][0]) == KEPT


def test_release_build_fails_naming_the_failed_lookup(rig):
    plant_source(rig, "mitre_attack", "v19.0")
    plant_config(rig.data, only("mitre_attack"))
    out = run_probe(
        rig,
        [release_build(rig)],
        lookups={"release": {MITRE: None}},
        responses=fixture_responses(rig),
    )
    value = out["ops"][0]["value"] or {}
    assert value.get("status") == "error", out["ops"][0]["stdout"][-1500:]
    assert any("mitre_attack" in e for e in value.get("errors", [])), value


def test_working_tag_lookup_stores_the_tag(rig):
    plant_source(rig, "mitre_attack", "v19.0")
    out = run_probe(
        rig,
        [sync("mitre_attack")],
        lookups={"release": {MITRE: "v20.1"}},
        responses=fixture_responses(rig),
    )
    assert out["ops"][0]["value"]["status"] == "success", out["ops"][0]
    assert stored(rig.data, "mitre_attack") == "v20.1"


# --- a tag source downloads at the tag it looked up --------------------------


def test_tag_source_downloads_at_the_looked_up_tag(rig):
    out = run_probe(
        rig,
        [sync("mitre_attack")],
        lookups={"release": {MITRE: "v20.1"}},
        responses=fixture_responses(rig),
    )
    refs = [u[len(STIX_PREFIX) :].split("/")[0] for u in downloads(out["ops"][0])]
    got = {"stored": stored(rig.data, "mitre_attack"), "refs": refs}
    assert got == {"stored": "v20.1", "refs": ["v20.1"]}


def test_failed_tag_lookup_downloads_nothing(rig):
    out = run_probe(
        rig,
        [sync("mitre_attack")],
        lookups={"release": {MITRE: None}},
        responses=fixture_responses(rig),
    )
    assert downloads(out["ops"][0]) == []


def test_tag_source_is_not_cloned(rig):
    out = run_probe(
        rig,
        [sync("mitre_attack")],
        lookups={"release": {MITRE: "v20.1"}},
        responses=fixture_responses(rig),
    )
    assert git_calls(out, "clone") == []


# --- a feed source keeps its plant when the feed lookup fails ----------------


@pytest.mark.parametrize("failure", ["returns_none", "raises"])
def test_failed_feed_lookup_keeps_the_planted_feed(rig, failure):
    plant = plant_source(rig, "cisa_kev", "2026.01.01")
    answer = None if failure == "returns_none" else {"raise": True}
    # a forced sync, as the release build and refresh run it
    out = run_probe(
        rig,
        [sync("cisa_kev", force=True)],
        lookups={"feed": {KEV_URL: answer}},
        responses=fixture_responses(rig),
    )
    assert kept(rig, "cisa_kev", plant, out["ops"][0]) == KEPT


# --- the fallback build names a failed lookup --------------------------------


FAILING = {
    "mitre_attack": {"release": {MITRE: None}},
    "cisa_kev": {"feed": {KEV_URL: None}},
}


def lookup_lines(stdout: str, name: str) -> list[int]:
    lines = stdout.splitlines()
    return [i for i, ln in enumerate(lines) if name in ln and LOOKUP_FAILED.search(ln)]


@pytest.mark.parametrize("target", list(FAILING))
def test_fallback_build_names_the_failed_lookup(rig, target):
    plant_config(rig.data, only(target, *EMBEDDED))
    out = run_probe(
        rig,
        [fallback_build(rig)],
        lookups=FAILING[target],
        responses=fixture_responses(rig),
    )
    built = out["ops"][0]
    assert built["rc"] == 0, built["stdout"][-1500:]
    assert lookup_lines(built["stdout"], target), built["stdout"][-1500:]


def test_working_lookup_builds_the_source(rig):
    plant_config(rig.data, only("mitre_attack", *EMBEDDED))
    out = run_probe(
        rig,
        [fallback_build(rig)],
        lookups={"release": {MITRE: "v20.1"}},
        responses=fixture_responses(rig),
    )
    built = out["ops"][0]
    assert built["rc"] == 0, built["stdout"][-1500:]
    assert built_records(built["stdout"]).get("mitre_attack", 0) > 0
    assert stored(rig.data, "mitre_attack") == "v20.1"


@pytest.fixture(scope="module")
def lone_source_run(tmp_path_factory):
    """The failing source the only enabled source in RAG_INDEX_DIR's config,
    while the package data dir's config disables only sigma; every clone and
    fetch other than the stubbed lookup fails."""
    root = tmp_path_factory.mktemp("rag-lone") / "rig"
    lone = make_rig(root, redirect_hijacklibs=False)
    index_dir = lone.root / "index"
    plant_config(index_dir, only("mitre_attack"))
    plant_config(lone.data, ["sigma"])
    out = run_probe(
        lone,
        [fallback_build(lone)],
        lookups={"release": {MITRE: None}},
        index_dir=index_dir,
    )
    return out["ops"][0]


def test_lone_failing_source_names_the_lookup_before_no_records(lone_source_run):
    stdout = lone_source_run["stdout"]
    lines = stdout.splitlines()
    end = [i for i, ln in enumerate(lines) if "No records to index!" in ln]
    named = lookup_lines(stdout, "mitre_attack")
    got = {
        "no_records": bool(end),
        "named_first": bool(end and named and named[0] < end[0]),
    }
    assert got == {"no_records": True, "named_first": True}, "\n".join(lines[-40:])


def test_no_network_build_indexes_only_embedded_records(lone_source_run):
    counts = built_records(lone_source_run["stdout"])
    with_records = {n for n, c in counts.items() if c > 0}
    assert with_records <= set(EMBEDDED), counts


# --- a recorded latest without a cache is still synced -----------------------


RECORDED = {
    "mitre_attack": ("v20.1", {"release": {MITRE: "v20.1"}}),
    "cisa_kev": ("2026.11.01", {"feed": {KEV_URL: "2026.11.01"}}),
}


def synced_and_indexed(rig: Rig, name: str, built: dict) -> dict:
    jsonl = rig.data / "sources" / f"{name}.jsonl"
    indexed = built_records(built["stdout"]).get(name, 0) > 0
    return {"jsonl": jsonl.exists(), "indexed": indexed}


@pytest.mark.parametrize("name", list(RECORDED))
def test_recorded_latest_without_cache_is_synced(rig, name):
    version, lookups = RECORDED[name]
    plant_state([rig.data], {name: entry(version)})
    plant_config(rig.data, only(name))
    out = run_probe(
        rig, [fallback_build(rig)], lookups=lookups, responses=fixture_responses(rig)
    )
    built = out["ops"][0]
    got = synced_and_indexed(rig, name, built)
    assert got == {"jsonl": True, "indexed": True}, built["stdout"][-1500:]


def test_recorded_commit_without_cache_is_synced(rig):
    plant_state([rig.data], {"fx_com": entry(rig.dev_tip[:12])})
    plant_config(rig.data, only("fx_com"))
    out = run_probe(
        rig,
        [fallback_build(rig)],
        lookups={"commit": {"fixture/fx": {"tip": str(rig.bare)}}},
        extra=[FX_COM],
    )
    built = out["ops"][0]
    got = synced_and_indexed(rig, "fx_com", built)
    assert got == {"jsonl": True, "indexed": True}, built["stdout"][-1500:]


@pytest.mark.parametrize("name", ["mitre_attack", "fx_com"])
def test_recorded_source_with_cache_is_not_synced(rig, name):
    if name == "fx_com":
        version = rig.dev_tip[:12]
        lookups = {"commit": {"fixture/fx": {"tip": str(rig.bare)}}}
        extra = [FX_COM]
    else:
        version, lookups, extra = "v20.1", {"release": {MITRE: "v20.1"}}, []
    plant_source(rig, name, version)
    plant_config(rig.data, only(name))
    out = run_probe(
        rig,
        [fallback_build(rig)],
        lookups=lookups,
        responses=fixture_responses(rig),
        extra=extra,
    )
    built = out["ops"][0]
    assert f"Syncing {name}..." not in built["stdout"], built["stdout"][-1500:]
    assert git_calls(out, "clone") == [] and downloads(built) == []


# --- the update check per (stored, looked-up) pair ---------------------------


PAIRS = {
    # name: (stored, looked up, has_update, error)
    "equal": ("aaaaaaaaaaaa", "aaaaaaaaaaaa", False, False),
    "different": ("aaaaaaaaaaaa", "bbbbbbbbbbbb", True, False),
    "none": ("aaaaaaaaaaaa", None, False, True),
    "empty": ("aaaaaaaaaaaa", "", False, True),
    "old_tag": ("v1.0.0", "cccccccccccc", True, False),
    "unknown": ("unknown", "dddddddddddd", True, False),
    "no_entry": (None, "eeeeeeeeeeee", True, False),
}


@pytest.fixture(scope="module")
def pairs_run(tmp_path_factory):
    pr = make_rig(tmp_path_factory.mktemp("rag-pairs") / "rig")
    extra, commits, entries = [], {}, {}
    for key, (current, looked_up, _update, _error) in PAIRS.items():
        repo = f"fixture/pair-{key.replace('_', '-')}"
        extra.append({**FX_COM, "name": f"pair_{key}", "repo": repo, "branch": "main"})
        commits[repo] = looked_up
        if current is not None:
            entries[f"pair_{key}"] = entry(current)
    plant_state([pr.data], entries)
    out = run_probe(
        pr, [{"op": "check"}], lookups={"commit": commits}, extra=extra, replace=True
    )
    return {row["name"]: row for row in out["ops"][0]["value"]}


@pytest.mark.parametrize("pair", list(PAIRS))
def test_update_check_pair(pairs_run, pair):
    _current, _looked_up, has_update, error = PAIRS[pair]
    row = pairs_run[f"pair_{pair}"]
    got = {"has_update": row["has_update"], "error": bool(row["error"])}
    assert got == {"has_update": has_update, "error": error}, row


# --- status with no state yet, and the embedded source -----------------------


STUBS = {"commit": {SIGMA: HEX, "*": None}, "feed": {"*": None}, "release": {"*": None}}


def status_run(root: Path, plant: dict | None) -> dict:
    """status --json (check on), status --json --no-check and the update check
    on a readable one-document index in RAG_INDEX_DIR, the lookups stubbed;
    plant, if given, is written into both RAG_INDEX_DIR and the package data
    dir with the same content."""
    sr = make_rig(root)
    index_dir = sr.root / "index"
    index_dir.mkdir()
    if plant is not None:
        plant_state([index_dir, sr.data], plant)
    ops = [
        {"op": "index", "dir": str(index_dir)},
        {"op": "status", "argv": ["--json"]},
        {"op": "status", "argv": ["--json", "--no-check"]},
        {"op": "check"},
    ]
    out = run_probe(sr, ops, lookups=STUBS, index_dir=index_dir)
    _index, checked, unchecked, check = out["ops"]
    for op in (checked, unchecked):
        js = op["json"] or {}
        if not js.get("index_exists") or js.get("document_count") != 1:
            raise RuntimeError(f"the fixture index was not read: {op['stdout'][-800:]}")
    return {
        "status": checked["json"],
        "no_check": unchecked["json"],
        "check": {row["name"]: row for row in check["value"]},
        "plant": plant,
    }


def every_entry(embedded_version: str | None) -> dict:
    """A state for every online source, sigma at the stubbed commit, and for
    the embedded source only if embedded_version is given."""
    entries = {n: entry("v1.0.0") for n in ONLINE}
    entries["sigma"] = entry(HEX)
    if embedded_version is not None:
        entries.update({n: entry(embedded_version) for n in EMBEDDED})
    return entries


@pytest.fixture(scope="module")
def no_state_run(tmp_path_factory):
    return status_run(tmp_path_factory.mktemp("rag-no-state") / "rig", None)


@pytest.fixture(scope="module")
def no_embedded_entry_run(tmp_path_factory):
    root = tmp_path_factory.mktemp("rag-no-embedded") / "rig"
    return status_run(root, every_entry(None))


@pytest.fixture(scope="module")
def embedded_entry_run(tmp_path_factory):
    root = tmp_path_factory.mktemp("rag-embedded") / "rig"
    return status_run(root, every_entry("embedded"))


def online(run: dict) -> dict:
    return {s["name"]: s for s in run["status"]["online_sources"]}


def freshness(run: dict) -> dict:
    fresh = run["status"].get("freshness")
    assert fresh is not None, "status --json has no freshness object"
    return fresh


def test_no_state_yet_returned_version_is_an_update(no_state_run):
    assert online(no_state_run)["sigma"]["has_update"] is True


def test_no_state_yet_failed_lookup_is_an_error_not_an_update(no_state_run):
    rows = online(no_state_run)
    failed = [n for n in ONLINE if n != "sigma"]
    wrong = {
        n: rows.get(n)
        for n in failed
        if n not in rows or rows[n]["has_update"] or not rows[n]["error"]
    }
    assert not wrong, wrong


def test_no_state_yet_freshness_lists(no_state_run):
    fresh = freshness(no_state_run)
    got = {
        "state": fresh.get("state"),
        "updates": sorted(fresh.get("updates", [])),
        "unchecked": sorted(fresh.get("unchecked", [])),
    }
    want = {
        "state": "updates",
        "updates": ["sigma"],
        "unchecked": [n for n in ONLINE if n != "sigma"],
    }
    assert got == want


def test_no_state_yet_line(no_state_run):
    assert "no state yet" in freshness(no_state_run).get("line", "")


def test_state_equal_to_the_lookups_gives_no_update(embedded_entry_run):
    updates = [n for n, s in online(embedded_entry_run).items() if s["has_update"]]
    assert updates == []


@pytest.mark.parametrize("which", ["no_embedded_entry_run", "embedded_entry_run"])
def test_no_check_reports_the_planted_versions(request, which):
    run = request.getfixturevalue(which)
    rows = run["no_check"]["online_sources"]
    reported = {s["name"]: s["current_version"] for s in rows}
    planted = {n: e["version"] for n, e in run["plant"].items()}
    assert {n: reported.get(n) for n in planted} == planted


EMBEDDED_RUNS = ["no_state_run", "no_embedded_entry_run", "embedded_entry_run"]


@pytest.mark.parametrize("which", EMBEDDED_RUNS)
def test_embedded_source_is_in_neither_freshness_list(request, which):
    fresh = freshness(request.getfixturevalue(which))
    listed = set(fresh.get("updates", [])) | set(fresh.get("unchecked", []))
    assert not listed & set(EMBEDDED), fresh


@pytest.mark.parametrize("which", EMBEDDED_RUNS)
def test_embedded_source_is_never_an_update(request, which):
    rows = request.getfixturevalue(which)["check"]
    flagged = {n: rows[n] for n in EMBEDDED if n in rows and rows[n]["has_update"]}
    assert not flagged, flagged
