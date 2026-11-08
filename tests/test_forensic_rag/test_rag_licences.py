"""What a release carries of its sources' licence files and of ATTRIBUTION.md.

Each RAG build runs the release script's own main() through
_rag_versions_probe.py on a scratch copy of the package, as in
test_rag_versions.py, over fixture sources only: each is a local bare repo
reached through insteadOf in the rig's isolated HOME, and the release's record
floor is lowered to 1, the fixture's size. A fixture bundle is installed by the
download script's own main with its index check stubbed, since a fixture index
is far below the record count that check asks for; the attribution rows pack a
20,000-record index and install it with the check as shipped. The triage half
runs ``import_all.py --fetch`` and then ``build-release.sh`` as test_fetch.py
and test_build_release_checks.py run them.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from test_windows_triage import test_fetch as triage

from .test_rag_bundle_state import (
    DOC,
    VERIFY_FLOOR,
    fill_data_dir,
    knowledge,
    members,
    succeeded,
)
from .test_rag_versions import _git, make_rig, run_probe, sources

zstd = pytest.importorskip("zstandard")
pytestmark = pytest.mark.skipif(
    shutil.which("git") is None, reason="the fixture repos need git"
)

REPO = Path(__file__).resolve().parents[2]
ATTRIBUTION = REPO / "packages" / "forensic-rag" / "ATTRIBUTION.md"
MIB = 1024 * 1024
CC_HEADING = "Attribution-NonCommercial-ShareAlike 4.0 International"
CC_EXCERPT = CC_HEADING.encode() + b"\n\nA fixture excerpt of the legal code.\n"
OWNER = "fixture-upstream"
YML = b"Name: fixture.dll\nAuthor: Fixture\nDescription: A fixture entry.\n"
CHAINSAW_RULE = b"title: Fixture rule\nkind: evtx\nlevel: info\n"
ARTIFACT = b"name: Fixture.Artifact\ndescription: A fixture artifact.\n"
MEMBER_FILES = {
    "fx_terms": {
        "LICENSE": b"Fixture licence for fx_terms.\n",
        "NOTICE": b"Fixture notice for fx_terms.\n",
        "README": b"Not a licence file.\n",
        "yml/one.yml": YML,
    },
    "chainsaw": {
        "LICENCE": b"Fixture licence for chainsaw.\n",
        "rules/fixture.yml": CHAINSAW_RULE,
    },
    "velociraptor": {
        "LICENSE": CC_EXCERPT,
        "content/exchange/artifacts/Fixture.yaml": ARTIFACT,
    },
}
LICENCE_FILE = re.compile(r"^(LICEN[CS]E|NOTICE|COPYING)", re.I)


def real(name: str) -> dict:
    """A shipped source's own fields, as the probe adds an extra source."""
    s = sources.SOURCES[name]
    return {
        "name": s.name,
        "source_type": s.source_type,
        "repo": s.repo,
        "branch": s.branch,
        "parser": s.parser,
    }


def fixture_source(name: str) -> dict:
    return {
        "name": name,
        "source_type": "github_commits",
        "repo": f"{OWNER}/{name}",
        "branch": "main",
        "parser": "parse_hijacklibs",
    }


def upstream(rig, repo: str, branch: str, files: dict, links=None) -> None:
    """A bare repo on branch holding files (and symlinks), which clones of
    https://github.com/<repo> reach through insteadOf."""
    name = repo.replace("/", "--")
    work = rig.root / "upstream-work" / name
    work.mkdir(parents=True)
    _git(rig.home, "init", "-q", "-b", branch, str(work))
    for rel, body in files.items():
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_bytes(body)
    for rel, target in (links or {}).items():
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).symlink_to(target)
    _git(rig.home, "add", "-A", cwd=work)
    _git(rig.home, "commit", "-q", "-m", "fixture", cwd=work)
    remote = rig.root / "remotes" / name
    _git(rig.home, "clone", "-q", "--bare", str(work), f"{remote}.git")
    with open(rig.home / ".gitconfig", "a", encoding="utf-8") as f:
        f.write(f'[url "file://{remote}"]\n')
        f.write(f"\tinsteadOf = https://github.com/{repo}\n")


def release(rig, out: Path, extra: list[dict]) -> dict:
    """The release build of the extra sources only, into out."""
    shutil.copyfile(ATTRIBUTION, rig.root / "pkg" / "ATTRIBUTION.md")
    op = {"op": "release", "out": str(out), "floor": 1}
    env = {"RAG_KNOWLEDGE_DIR": str(rig.empty)}
    res = run_probe(rig, [op], extra=extra, replace=True, env=env)
    return res["ops"][0]


def install_bundle(root: Path, assets: Path, doc: bytes | None) -> dict:
    """Install a bundle as the lite installer does, into a new data dir. With
    no doc the knowledge dir is empty and the index check is stubbed."""
    rig = make_rig(root / "install-rig")
    dest = root / "dest"
    dest.mkdir()
    tmp = root / "tmp"
    tmp.mkdir()
    folder = rig.empty if doc is None else knowledge(root / "knowledge", doc)
    env = {
        "TMPDIR": str(tmp),
        "RAG_KNOWLEDGE_DIR": str(folder),
        "GITHUB_TOKEN": "fixture-token-not-used",
    }
    op = {"op": "install", "assets": str(assets), "argv": ["--dest", str(dest)]}
    if doc is None:
        op["verify"] = False
    res = run_probe(rig, [op], index_dir=dest, env=env)
    return {"dest": dest, "op": res["ops"][0]}


def bundle_files(bundle: Path) -> dict[str, bytes]:
    """Each regular file member of a bundle, with its bytes; none if no bundle."""
    out = {}
    if not bundle.is_file():
        return out
    with open(bundle, "rb") as f, zstd.ZstdDecompressor().stream_reader(f) as r:
        with tarfile.open(fileobj=r, mode="r|") as tar:
            for member in tar:
                if member.isfile():
                    out[member.name] = tar.extractfile(member).read()
    return out


def read_or_none(path: Path) -> bytes | None:
    return path.read_bytes() if path.is_file() else None


def failures(op: dict) -> list[str]:
    return [ln for ln in op["stdout"].splitlines() if ln.startswith("Build failed")]


def naming(lines: list[str], name: str, word: str, flags=0) -> list[str]:
    return [ln for ln in lines if name in ln and re.search(word, ln, flags)]


def attribution_rows(needle: str) -> list[str]:
    text = ATTRIBUTION.read_text(encoding="utf-8")
    return [ln for ln in text.splitlines() if ln.startswith("|") and needle in ln]


# --- a release bundle carries each cloned source's root licence files --------


@pytest.fixture(scope="module")
def licensed(tmp_path_factory):
    """A release build of three fixture sources, each with root licence files,
    and that bundle installed."""
    root = tmp_path_factory.mktemp("members")
    rig = make_rig(root / "rig")
    upstream(rig, f"{OWNER}/fx_terms", "main", MEMBER_FILES["fx_terms"])
    for name in ("chainsaw", "velociraptor"):
        cfg = real(name)
        upstream(rig, cfg["repo"], cfg["branch"], MEMBER_FILES[name])
    extra = [fixture_source("fx_terms"), real("chainsaw"), real("velociraptor")]
    out = root / "release"
    built = release(rig, out, extra)
    files = bundle_files(out / "rag-index.tar.zst")
    installed = install_bundle(root / "install", out, None)
    return {"built": built, "files": files, **installed}


def test_release_build_of_the_licensed_fixtures_passes(licensed):
    built = licensed["built"]
    assert built["rc"] == 0 and built["error"] is None, built["stdout"][-2000:]
    assert failures(built) == []


def test_bundle_holds_each_root_licence_file_byte_equal(licensed):
    prefix = "sources/licenses/"
    got = {
        name.removeprefix(prefix): body
        for name, body in licensed["files"].items()
        if name.startswith(prefix)
    }
    want = {
        f"{source}/{rel}": body
        for source, files in MEMBER_FILES.items()
        for rel, body in files.items()
        if "/" not in rel and LICENCE_FILE.match(rel)
    }
    assert got == want


def test_bundle_holds_the_velociraptor_records(licensed):
    body = licensed["files"].get("sources/velociraptor.jsonl", b"")
    rows = [ln for ln in body.decode("utf-8").splitlines() if ln.strip()]
    got = [json.loads(ln)["metadata"].get("source") for ln in rows]
    assert "velociraptor" in got


def test_fixture_bundle_installs(licensed):
    assert succeeded(licensed["op"]), licensed["op"]["stdout"][-2000:]


def test_bundle_and_install_hold_the_attribution_file(licensed):
    want = ATTRIBUTION.read_bytes()
    got = {
        "member": licensed["files"].get("ATTRIBUTION.md"),
        "installed": read_or_none(licensed["dest"] / "ATTRIBUTION.md"),
    }
    assert got == {"member": want, "installed": want}


def test_attribution_credits_velociraptor_with_its_licence():
    rows = attribution_rows("Velocidex/velociraptor-docs")
    assert len(rows) == 1, rows
    assert "CC BY-NC-SA 4.0" in rows[0] and "AGPL" not in rows[0]


def test_velociraptor_licence_ships_and_installs_byte_equal(licensed):
    rel = "sources/licenses/velociraptor/LICENSE"
    got = {
        "member": licensed["files"].get(rel),
        "installed": read_or_none(licensed["dest"] / rel),
    }
    assert got == {"member": CC_EXCERPT, "installed": CC_EXCERPT}
    assert CC_HEADING in got["installed"].decode("utf-8")


# --- a cloned source whose only licence file is not a root file fails --------

NOT_AT_ROOT = {
    "fx_link": {
        "files": {"legal/terms.txt": b"Fixture terms.\n", "yml/one.yml": YML},
        "links": {"LICENSE": "legal/terms.txt"},
    },
    "fx_nested": {
        "files": {
            "docs/LICENSE": b"Fixture licence, not at the root.\n",
            "yml/one.yml": YML,
        },
        "links": {},
    },
}


@pytest.fixture(scope="module")
def not_at_root(tmp_path_factory):
    runs = {}
    for name, case in NOT_AT_ROOT.items():
        root = tmp_path_factory.mktemp(f"case-{name}")
        rig = make_rig(root / "rig")
        upstream(rig, f"{OWNER}/{name}", "main", case["files"], case["links"])
        runs[name] = release(rig, root / "release", [fixture_source(name)])
    return runs


@pytest.mark.parametrize("name", list(NOT_AT_ROOT), ids=["symlink", "subdir"])
def test_no_root_licence_file_fails_the_build_naming_the_source(not_at_root, name):
    built = not_at_root[name]
    named = naming(failures(built), name, r"licen[cs]e", re.I)
    assert named, built["stdout"][-2000:]


# --- a licence file over 1 MiB fails the build, in both packages -------------

SIZES = {"over": MIB + 1, "limit": MIB}
TRIAGE_NAMES = {"over": "Oversized", "limit": "AtLimit"}


def licence_body(size: int) -> bytes:
    return b"x" * (size - 1) + b"\n"


def rag_build(root: Path, case: str) -> dict:
    name = f"fx_{case}"
    rig = make_rig(root / "rig")
    files = {"LICENSE": licence_body(SIZES[case]), "yml/one.yml": YML}
    upstream(rig, f"{OWNER}/{name}", "main", files)
    out = root / "release"
    built = release(rig, out, [fixture_source(name)])
    lines = failures(built)
    copied = bundle_files(out / "rag-index.tar.zst")
    return {
        "name": name,
        "ok": built["rc"] == 0 and built["error"] is None and not lines,
        "errors": lines,
        "copied": copied.get(f"sources/licenses/{name}/LICENSE"),
        "tail": built["stdout"][-2000:],
    }


def triage_build(tmp: Path, case: str) -> dict:
    name = TRIAGE_NAMES[case]
    key = name.lower()
    entry = {
        "name": name,
        "db": "context.db",
        "db_source_key": key,
        "repo": f"fixture-owner/{name}",
        "url": f"https://github.com/fixture-owner/{name}.git",
        "clone_timeout": 600,
        "description": "A fixture source with a large root licence file",
    }
    with pytest.MonkeyPatch.context() as mp:
        home = tmp / "home"
        home.mkdir()
        mp.setenv("HOME", str(home))
        mp.setenv("XDG_CONFIG_HOME", str(home / ".config"))
        mp.setenv("GIT_CONFIG_NOSYSTEM", "1")
        mp.delenv("GIT_CONFIG_GLOBAL", raising=False)
        triage._upstreams(tmp, home)
        body = licence_body(SIZES[case]).decode("ascii")
        files = {"LICENSE": body, "README": "A fixture upstream.\n"}
        triage._remote(tmp, home, entry["repo"], "main", files)
        root = triage._tree(tmp)
        fetched = triage._fetch(tmp, root, sources={key: entry})
        env = triage._env(tmp, {key: entry}, "")
        env["VENV"] = str(Path(sys.executable).parent.parent)
        script = root / "scripts" / "build-release.sh"
        built = subprocess.run(
            ["bash", str(script), "--output", str(tmp / "release-out")],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
    out = triage._out(fetched).splitlines()
    lines = [ln for ln in out if ln.startswith("ERROR:")]
    if built.returncode != 0:
        lines += built.stderr.splitlines()
    tail = f"fetch {triage._tail(fetched)}; build rc {built.returncode}"
    tail += f": {built.stderr[-1500:]}"
    return {
        "name": name,
        "ok": fetched.returncode == 0 and built.returncode == 0,
        "errors": lines,
        "copied": read_or_none(root / "data" / "licenses" / name / "LICENSE"),
        "tail": tail,
    }


@pytest.fixture(scope="module")
def sized(tmp_path_factory):
    runs = {}
    for case in SIZES:
        rag_dir = tmp_path_factory.mktemp(f"rag-{case}")
        runs["rag", case] = rag_build(rag_dir, case)
        triage_dir = tmp_path_factory.mktemp(f"triage-{case}")
        runs["triage", case] = triage_build(triage_dir, case)
    return runs


PACKAGES = ["rag", "triage"]


@pytest.mark.parametrize("package", PACKAGES)
def test_licence_over_one_mib_fails_naming_the_source_and_file(sized, package):
    run = sized[package, "over"]
    assert naming(run["errors"], run["name"], r"\bLICENSE\b"), run["tail"]


@pytest.mark.parametrize("package", PACKAGES)
def test_licence_of_exactly_one_mib_does_not_fail_the_build(sized, package):
    run = sized[package, "limit"]
    assert run["ok"] and run["errors"] == [], run["tail"]


@pytest.mark.parametrize("package", PACKAGES)
def test_licence_of_exactly_one_mib_is_copied_byte_equal(sized, package):
    assert sized[package, "limit"]["copied"] == licence_body(MIB)


# --- the attribution file in a shipped-size bundle and its install -----------


@pytest.fixture(scope="module")
def attributed(tmp_path_factory):
    """A bundle packed from a 20,000-record index, installed with the index
    check as shipped."""
    root = tmp_path_factory.mktemp("attribution")
    rig = make_rig(root / "rig")
    shutil.copyfile(ATTRIBUTION, rig.root / "pkg" / "ATTRIBUTION.md")
    build = root / "build"
    fill_data_dir(build)
    out = root / "release"
    ops = [
        {"op": "index", "dir": str(build), "count": VERIFY_FLOOR},
        {"op": "pack", "out": str(out)},
    ]
    made = run_probe(rig, ops, index_dir=build)
    bundle = out / "rag-index.tar.zst"
    names = members(bundle) if bundle.is_file() else []
    installed = install_bundle(root / "install", out, DOC)
    return {"packed": made["ops"], "names": names, **installed}


def test_shipped_size_bundle_installs(attributed):
    assert [op["rc"] for op in attributed["packed"]] == [0, 0]
    assert succeeded(attributed["op"]), attributed["op"]["stdout"][-2000:]


def test_shipped_size_bundle_lists_the_attribution_file(attributed):
    assert "ATTRIBUTION.md" in attributed["names"]


def test_shipped_size_install_leaves_the_attribution_file(attributed):
    got = read_or_none(attributed["dest"] / "ATTRIBUTION.md")
    assert got == ATTRIBUTION.read_bytes()


@pytest.mark.parametrize("needle", ["ATT&CK", "D3FEND", "KEV"])
def test_attribution_has_a_row_for(needle):
    assert attribution_rows(needle)
