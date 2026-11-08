"""The source state a release bundle carries, and what status says about the
state file an install leaves.

Every run goes through _rag_versions_probe.py in a fresh process on a scratch
copy of the package, as in test_rag_versions.py. A bundle is packed by the
release script from a fixture data dir and installed by the download script's
own main, its release lookup answered with local file URLs; the index holds
the 20,000 records the install's verify step asks for, embedded with a
stand-in model. Two forms are run, as the two installers call the scripts:
"lite" passes the data dir as --dest and RAG_INDEX_DIR, "setup_sift" passes
neither, so the package's own data dir is used.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from .test_rag_versions import (
    ALL,
    EMBEDDED,
    ONLINE,
    entry,
    make_rig,
    plant_state,
    run_probe,
    sources,
)

zstd = pytest.importorskip("zstandard")

MODEL = "BAAI/bge-base-en-v1.5"
VERIFY_FLOOR = 20000
DOC_REL = "fixture/doc.md"
DOC = b"# Fixture\n\nA bundled fixture document.\n"
DOC_CHANGED = b"# Fixture\n\nA bundled fixture document, changed after the build.\n"
TRUNCATED = b'{"version": 1, "sources": {"sigma": {"vers'
PLANT = "abcdef012345"
OLDER = "000000000000"
FORMS = ["lite", "setup_sift"]


def _hash(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def version_of(name: str) -> str:
    """The version the fixture build records for name, and its lookup returns."""
    if name in EMBEDDED:
        return "embedded"
    return hashlib.sha256(sources.SOURCES[name].repo.encode()).hexdigest()[:12]


VERSIONS = {n: version_of(n) for n in ALL}
KIND = {
    "github_commits": "commit",
    "github_releases": "release",
    "json_feed": "feed",
}


def lookups_for(versions: dict) -> dict:
    """Stubbed lookups answering each online source with versions[name]."""
    tables: dict = {"commit": {}, "release": {}, "feed": {}}
    for name in ONLINE:
        cfg = sources.SOURCES[name]
        tables[KIND[cfg.source_type]][cfg.repo] = versions[name]
    return tables


ANSWER_PLANT = {"commit": {"*": PLANT}, "release": {"*": PLANT}, "feed": {"*": PLANT}}


def entries(version: str) -> dict:
    """A state entry per source: version, except the embedded source's own."""
    return {n: entry("embedded" if n in EMBEDDED else version) for n in ALL}


def knowledge(root: Path, body: bytes) -> Path:
    """A knowledge folder holding one bundled document."""
    folder = root / "fixture"
    folder.mkdir(parents=True)
    (folder / ".bundled").write_text("", encoding="utf-8")
    (folder / "doc.md").write_bytes(body)
    return root


def fill_data_dir(d: Path) -> None:
    """A built data dir but its index: sources, licences, metadata and both states."""
    (d / "sources" / "licenses" / "fixture").mkdir(parents=True)
    (d / "sources" / "licenses" / "fixture" / "LICENSE").write_text(
        "Fixture licence.\n", encoding="utf-8"
    )
    (d / "sources" / "fixture.jsonl").write_text(
        '{"text": "fixture", "metadata": {"source": "fixture"}}\n', encoding="utf-8"
    )
    (d / "metadata.json").write_text(json.dumps({"model": MODEL}), encoding="utf-8")
    user_state = {
        "version": 1,
        "files": {DOC_REL: {"hash": _hash(DOC), "records": 1, "record_ids": []}},
    }
    (d / "user_state.json").write_text(json.dumps(user_state), encoding="utf-8")
    plant_state([d], {n: entry(VERSIONS[n]) for n in ALL})


def members(bundle: Path) -> list[str]:
    with open(bundle, "rb") as f, zstd.ZstdDecompressor().stream_reader(f) as r:
        with tarfile.open(fileobj=r, mode="r|") as tar:
            return [m.name for m in tar]


def cut_stream(build: Path, out: Path) -> None:
    """A bundle whose tar stream holds the state first and ends inside chroma."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(build / "sources_state.json", arcname="sources_state.json")
        for name in ("chroma", "metadata.json", "user_state.json", "sources"):
            tar.add(build / name, arcname=name)
    raw = buf.getvalue()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r") as tar:
        listed = tar.getmembers()
    state = next(m for m in listed if m.name == "sources_state.json")
    big = max((m for m in listed if m.name.startswith("chroma/")), key=lambda m: m.size)
    cut = big.offset_data + big.size // 2
    assert state.offset_data + state.size < cut
    out.mkdir(parents=True)
    bundle = out / "rag-index.tar.zst"
    bundle.write_bytes(zstd.ZstdCompressor(level=1).compress(raw[:cut]))
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    (out / "rag-checksums.sha256").write_text(
        f"{digest} rag-index.tar.zst\n", encoding="utf-8"
    )


def pack(rig, build: Path, out: Path) -> dict:
    res = run_probe(rig, [{"op": "pack", "out": str(out)}], index_dir=build)
    return res["ops"][0]


@pytest.fixture(scope="module")
def bundles(tmp_path_factory):
    """Four bundles: good, one without sigma's state, a small index, a cut stream."""
    root = tmp_path_factory.mktemp("bundles")
    rig = make_rig(root / "rig")
    build = root / "build"
    fill_data_dir(build)
    made = run_probe(
        rig,
        [
            {"op": "index", "dir": str(build), "count": VERIFY_FLOOR},
            {"op": "pack", "out": str(root / "good")},
        ],
        index_dir=build,
    )
    out = {"build": build, "good": root / "good", "packed": made["ops"]}
    out["state"] = (build / "sources_state.json").read_bytes()
    cut_stream(build, root / "cut")
    out["cut"] = root / "cut"
    plant_state([build], {n: entry(VERSIONS[n]) for n in ALL if n != "sigma"})
    out["packed"].append(pack(rig, build, root / "no_sigma"))
    out["no_sigma"] = root / "no_sigma"
    small = root / "small"
    fill_data_dir(small)
    made = run_probe(
        rig,
        [
            {"op": "index", "dir": str(small), "count": 1},
            {"op": "pack", "out": str(root / "small_index")},
        ],
        index_dir=small,
    )
    out["packed"] += made["ops"]
    out["small_index"] = root / "small_index"
    return out


def install(root: Path, assets: Path, form: str, doc: bytes, state: bytes | None):
    """Install a bundle as the installer of form does, into a new data dir."""
    rig = make_rig(root / "rig")
    dest = root / "dest" if form == "lite" else rig.data
    dest.mkdir(parents=True, exist_ok=True)
    if state is not None:
        (dest / "sources_state.json").write_bytes(state)
    tmp = root / "tmp"
    tmp.mkdir()
    env = {
        "TMPDIR": str(tmp),
        "RAG_KNOWLEDGE_DIR": str(knowledge(root / "knowledge", doc)),
        "GITHUB_TOKEN": "fixture-token-not-used",
    }
    argv = ["--dest", str(dest)] if form == "lite" else []
    if form != "lite":
        env["RAG_INDEX_DIR"] = None
    op = {"op": "install", "assets": str(assets), "argv": argv}
    res = run_probe(rig, [op], index_dir=dest, env=env)
    return {"rig": rig, "dest": dest, "tmp": tmp, "env": env, "op": res["ops"][0]}


def status_of(run: dict, argv: list[str], lookups: dict | None = None) -> dict:
    res = run_probe(
        run["rig"],
        [{"op": "status", "argv": argv}],
        lookups=lookups,
        index_dir=run["dest"],
        env=run["env"],
    )
    return res["ops"][0]["json"] or {}


def online(js: dict) -> dict:
    return {s["name"]: s for s in js.get("online_sources", [])}


def succeeded(op: dict) -> bool:
    return (
        op["error"] is None
        and op["rc"] == 0
        and "RAG index installed successfully." in op["stdout"]
    )


def leftovers(run: dict) -> list[str]:
    dest = [
        p.name
        for p in run["dest"].iterdir()
        if p.name.startswith("sources_state") and p.name != "sources_state.json"
    ]
    tmp = [p.name for p in run["tmp"].iterdir() if p.name.startswith("rag-index-")]
    return dest + tmp


# --- a good bundle carries the build's source state --------------------------

GOOD_CASES = ["empty_dest", "older_state", "changed_document"]


@pytest.fixture(scope="module")
def good_installs(bundles, tmp_path_factory):
    runs = {}
    for case in GOOD_CASES:
        root = tmp_path_factory.mktemp(case)
        older = json.dumps({"version": 1, "sources": entries(OLDER)}).encode()
        state = older if case == "older_state" else None
        doc = DOC_CHANGED if case == "changed_document" else DOC
        run = install(root, bundles["good"], "lite", doc, state)
        run["status"] = status_of(run, ["--json", "--no-check"])
        runs[case] = run
    return runs


def test_fixture_bundles_are_packed(bundles):
    assert [op["rc"] for op in bundles["packed"]] == [0, 0, 0, 0, 0]
    for name in ("good", "no_sigma", "small_index", "cut"):
        names = {p.name for p in bundles[name].iterdir()}
        assert {"rag-checksums.sha256", "rag-index.tar.zst"} <= names


def test_published_bundle_lists_the_source_state(bundles):
    assert "sources_state.json" in members(bundles["good"] / "rag-index.tar.zst")


@pytest.mark.parametrize("case", GOOD_CASES)
def test_good_bundle_installs(good_installs, case):
    assert succeeded(good_installs[case]["op"]), good_installs[case]["op"]["stdout"]


def test_changed_document_is_refreshed_at_install(good_installs):
    run = good_installs["changed_document"]
    assert "Updating bundled documents in the downloaded index" in run["op"]["stdout"]
    state = json.loads((run["dest"] / "user_state.json").read_text(encoding="utf-8"))
    assert state["files"][DOC_REL]["hash"] == _hash(DOC_CHANGED)


@pytest.mark.parametrize("case", GOOD_CASES)
def test_installed_state_is_the_builds_byte_for_byte(bundles, good_installs, case):
    path = good_installs[case]["dest"] / "sources_state.json"
    assert path.exists() and path.read_bytes() == bundles["state"]


@pytest.mark.parametrize("case", GOOD_CASES)
def test_installed_index_reports_the_builds_versions(good_installs, case):
    got = online(good_installs[case]["status"])
    assert {n: got.get(n, {}).get("current_version") for n in ONLINE} == {
        n: VERSIONS[n] for n in ONLINE
    }


# --- a failed install leaves the state it found ------------------------------

FAILED_CASES = [
    ("small_index", "older_state"),
    ("small_index", "no_state"),
    ("cut", "older_state"),
    ("cut", "no_state"),
]
FAILED_IDS = [f"{b}-{s}" for b, s in FAILED_CASES]
OLDER_BYTES = json.dumps({"version": 1, "sources": entries(OLDER)}, indent=2).encode()


@pytest.fixture(scope="module")
def failed_installs(bundles, tmp_path_factory):
    runs = {}
    for bundle, state in FAILED_CASES:
        key = f"{bundle}-{state}"
        root = tmp_path_factory.mktemp(key)
        before = OLDER_BYTES if state == "older_state" else None
        runs[key] = install(root, bundles[bundle], "lite", DOC, before)
        runs[key]["before"] = before
    return runs


@pytest.mark.parametrize("key", FAILED_IDS)
def test_failed_install_fails_where_it_should(failed_installs, key):
    run = failed_installs[key]
    assert not succeeded(run["op"])
    if key.startswith("small_index"):
        assert "Index verification failed." in run["op"]["stdout"]
    else:
        assert not (run["dest"] / "metadata.json").exists()


@pytest.mark.parametrize("key", FAILED_IDS)
def test_failed_install_keeps_the_previous_state(failed_installs, key):
    run = failed_installs[key]
    path = run["dest"] / "sources_state.json"
    got = path.read_bytes() if path.exists() else None
    assert got == run["before"]


@pytest.mark.parametrize("key", FAILED_IDS)
def test_failed_install_leaves_no_temp_file(failed_installs, key):
    assert leftovers(failed_installs[key]) == []


# --- status on a truncated or absent state file ------------------------------


def status_rig(root: Path, form: str, state_here, package_state=None) -> dict:
    """An index in the form's data dir, state_here written beside it (bytes,
    a dict of entries, or None), and package_state in the package's data dir."""
    rig = make_rig(root / "rig")
    dest = root / "index" if form == "lite" else rig.data
    dest.mkdir(parents=True, exist_ok=True)
    if isinstance(state_here, bytes):
        (dest / "sources_state.json").write_bytes(state_here)
    elif state_here is not None:
        plant_state([dest], state_here)
    if package_state is not None:
        plant_state([rig.data], package_state)
    env = {"RAG_KNOWLEDGE_DIR": str(knowledge(root / "knowledge", DOC))}
    if form != "lite":
        env["RAG_INDEX_DIR"] = None
    res = run_probe(rig, [{"op": "index", "dir": str(dest)}], index_dir=dest, env=env)
    assert res["ops"][0]["error"] is None
    return {"rig": rig, "dest": dest, "env": env}


@pytest.fixture(scope="module")
def truncated(tmp_path_factory):
    """The truncated file in the form's data dir; for lite, a well-formed
    state of PLANT in the package's data dir as well."""
    runs = {}
    for form in FORMS:
        root = tmp_path_factory.mktemp(f"truncated-{form}")
        package = entries(PLANT) if form == "lite" else None
        run = status_rig(root, form, TRUNCATED, package)
        runs[form] = status_of(run, ["--json"], ANSWER_PLANT)
    return runs


@pytest.fixture(scope="module")
def absent(tmp_path_factory):
    """No state file in the form's data dir; for lite, a well-formed state of
    PLANT in the package's data dir."""
    runs = {}
    for form in FORMS:
        root = tmp_path_factory.mktemp(f"absent-{form}")
        package = entries(PLANT) if form == "lite" else None
        run = status_rig(root, form, None, package)
        runs[form] = status_of(run, ["--json"], ANSWER_PLANT)
    return runs


@pytest.mark.parametrize("form", FORMS)
def test_truncated_state_is_reported_unreadable(truncated, form):
    assert (truncated[form].get("freshness") or {}).get("state") == "unreadable"


@pytest.mark.parametrize("form", FORMS)
def test_truncated_state_is_not_one_update_per_source(truncated, form):
    got = {n: s for n, s in online(truncated[form]).items() if n in ONLINE}
    assert got and sum(bool(s["has_update"]) for s in got.values()) < len(got)


def test_truncated_state_read_is_the_index_dirs_not_the_package_dirs(truncated):
    got = online(truncated["lite"])
    assert [n for n in ONLINE if got.get(n, {}).get("current_version") == PLANT] == []


def test_package_state_is_the_file_read_without_check(tmp_path):
    run = status_rig(tmp_path, "setup_sift", entries(PLANT))
    got = online(status_of(run, ["--json", "--no-check"]))
    assert {n: got.get(n, {}).get("current_version") for n in ONLINE} == {
        n: PLANT for n in ONLINE
    }


@pytest.mark.parametrize("form", FORMS)
def test_state_matching_the_lookups_gives_no_update_in_each_form(tmp_path, form):
    package = entries(PLANT) if form == "lite" else None
    run = status_rig(tmp_path, form, entries(PLANT), package)
    got = online(status_of(run, ["--json"], ANSWER_PLANT))
    assert {n: got.get(n, {}).get("current_version") for n in ONLINE} == {
        n: PLANT for n in ONLINE
    }
    assert [n for n, s in got.items() if s["has_update"]] == []


@pytest.mark.parametrize("form", FORMS)
def test_absent_state_line_says_no_state_yet(absent, form):
    assert "no state yet" in (absent[form].get("freshness") or {}).get("line", "")


@pytest.mark.parametrize("form", FORMS)
def test_absent_state_is_not_unreadable(absent, form):
    assert (absent[form].get("freshness") or {}).get("state") != "unreadable"


def test_absent_state_read_is_the_index_dirs_not_the_package_dirs(absent):
    got = online(absent["lite"])
    assert [n for n in ONLINE if got.get(n, {}).get("current_version") == PLANT] == []


# --- the installer's check after a bundle whose state lacks one source -------


@pytest.fixture(scope="module")
def no_sigma_installs(bundles, tmp_path_factory):
    runs = {}
    for form in FORMS:
        root = tmp_path_factory.mktemp(f"no-sigma-{form}")
        run = install(root, bundles["no_sigma"], form, DOC, None)
        run["status"] = status_of(run, ["--json"], lookups_for(VERSIONS))
        runs[form] = run
    return runs


@pytest.mark.parametrize("form", FORMS)
def test_bundle_without_one_source_installs(no_sigma_installs, form):
    op = no_sigma_installs[form]["op"]
    assert succeeded(op), op["stdout"]


@pytest.mark.parametrize("form", FORMS)
def test_installer_check_after_bundle_names_the_missing_source(no_sigma_installs, form):
    got = online(no_sigma_installs[form]["status"])
    assert sorted(n for n, s in got.items() if s["has_update"]) == ["sigma"]
