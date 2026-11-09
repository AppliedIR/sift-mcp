"""When a RAG refresh records refreshed_at in metadata.json, the time an
online source's recorded version last changed.

Every run goes through _rag_versions_probe.py in a fresh process on a scratch
copy of the package, as in test_rag_versions.py, with one online source: a
fixture repo cloned through insteadOf, its version lookup answered from the
fixture's branch head. A bundle is packed from a fixture data dir and
installed as setup-sift installs it (the package's own data dir), with a
bundled document changed since the build so the install's drift refresh
runs; refreshes then follow in one order, each reading metadata.json after
it: one with no online change, one after a commit lands on the fixture
branch, then --skip-online, no change again, --source on the unchanged
source, --check-only, and one whose sync fails after another commit lands.
A second install goes over a data dir whose metadata.json already holds the
key. KEY is the key each row reads.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from .test_rag_bundle_state import DOC_CHANGED, MODEL, fill_data_dir, knowledge
from .test_rag_versions import (
    FX_COM,
    entry,
    git_calls,
    make_rig,
    plant_state,
    run_probe,
    stored,
)

KEY = "refreshed_at"
NAME = FX_COM["name"]
PLANTED_TIME = "2026-01-02T03:04:05+00:00"
LATER = ["skip_online", "no_change_after", "single_source", "failed_sync"]


def read_meta(d: Path) -> dict:
    path = d / "metadata.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def lookups(rig, rule: str) -> dict:
    """The fixture source's lookup: its branch head ("tip"), or a commit
    landed on the branch first ("advance")."""
    return {"commit": {FX_COM["repo"]: {rule: str(rig.bare)}}}


def no_fixture_remote(rig) -> str:
    """The rig's git config without the fixture repo's redirect, so its clone
    goes to the path that does not exist; identity and the rest are kept."""
    lines = (rig.home / ".gitconfig").read_text(encoding="utf-8").splitlines()
    cut = next(i for i, x in enumerate(lines) if x.endswith(FX_COM["repo"])) - 1
    assert lines[cut].startswith('[url "file://'), lines
    return "\n".join(lines[:cut]) + "\n"


def install_env(root: Path) -> dict:
    tmp = root / "tmp"
    tmp.mkdir(parents=True)
    return {
        "TMPDIR": str(tmp),
        "RAG_KNOWLEDGE_DIR": str(knowledge(root / "knowledge", DOC_CHANGED)),
        "GITHUB_TOKEN": "fixture-token-not-used",
        "RAG_INDEX_DIR": None,
    }


def install_op(bundle: Path) -> list[dict]:
    return [{"op": "install", "assets": str(bundle), "argv": [], "verify": False}]


def refresh_op(*argv: str) -> list[dict]:
    return [{"op": "refresh", "argv": list(argv)}]


@pytest.fixture(scope="module")
def chain(tmp_path_factory):
    root = tmp_path_factory.mktemp("record")
    rig = make_rig(root / "rig")
    build = root / "build"
    fill_data_dir(build)
    plant_state([build], {NAME: entry(rig.dev_tip[:12])})
    bundle = root / "bundle"
    made = run_probe(
        rig,
        [{"op": "index", "dir": str(build)}, {"op": "pack", "out": str(bundle)}],
        index_dir=build,
        extra=[FX_COM],
        replace=True,
    )
    runs: dict = {"pack": made["ops"]}
    env = install_env(root)
    broken = root / "broken.gitconfig"
    broken.write_text(no_fixture_remote(rig), encoding="utf-8")

    def step(name, ops, rule="tip", more=None, on=rig, run_env=env):
        out = run_probe(
            on,
            ops,
            lookups=lookups(on, rule),
            extra=[FX_COM],
            replace=True,
            index_dir=on.data,
            env={**run_env, **(more or {})},
        )
        runs[name] = {
            "op": out["ops"][-1],
            "clones": git_calls(out, "clone"),
            "meta": read_meta(on.data),
            "version": stored(on.data, NAME),
        }

    step("install", install_op(bundle))
    step("no_change", refresh_op())
    step("changed", refresh_op(), rule="advance")
    step("skip_online", refresh_op("--skip-online"))
    step("no_change_after", refresh_op())
    step("single_source", refresh_op("--source", NAME))
    step("check_only", refresh_op("--check-only"))
    step(
        "failed_sync",
        refresh_op(),
        rule="advance",
        more={"GIT_CONFIG_GLOBAL": str(broken)},
    )

    over = make_rig(root / "rig2")
    (over.data / "metadata.json").write_text(
        json.dumps({"model": MODEL, KEY: PLANTED_TIME}), encoding="utf-8"
    )
    step("install_over", install_op(bundle), on=over, run_env=install_env(root / "2"))
    return runs


# --- each step ran as its row needs ------------------------------------------


def test_the_bundle_is_packed(chain):
    assert [op["rc"] for op in chain["pack"]] == [0, 0], chain["pack"]


@pytest.mark.parametrize("name", ["install", "install_over"])
def test_the_install_ran_its_drift_refresh(chain, name):
    op = chain[name]["op"]
    assert op["error"] is None and op["rc"] == 0, op["stdout"][-600:]
    assert "RAG index installed successfully." in op["stdout"]
    assert "Updating bundled documents in the downloaded index" in op["stdout"]


@pytest.mark.parametrize(
    "name", ["no_change", "changed", *LATER[:3], "check_only", "failed_sync"]
)
def test_each_refresh_ran(chain, name):
    op = chain[name]["op"]
    assert op["error"] is None, op["stdout"][-600:]


def test_the_steps_changed_the_recorded_version_only_where_meant(chain):
    got = {n: chain[n]["version"] for n in ("install", "no_change", "changed")}
    got.update({n: chain[n]["version"] for n in LATER})
    first, moved = got["install"], got["changed"]
    assert first and moved and moved != first, got
    assert got == {
        "install": first,
        "no_change": first,
        "changed": moved,
        "skip_online": moved,
        "no_change_after": moved,
        "single_source": moved,
        "failed_sync": moved,
    }


def test_the_single_source_refresh_synced_its_source(chain):
    assert chain["single_source"]["clones"], chain["single_source"]["op"]["stdout"]


def test_the_failed_sync_named_its_source(chain):
    run = chain["failed_sync"]
    assert run["clones"], run["op"]["stdout"][-600:]
    assert NAME in run["op"]["stdout"], run["op"]["stdout"][-600:]


# --- the record ---------------------------------------------------------------


def test_an_install_whose_drift_refresh_ran_has_no_record(chain):
    assert KEY not in chain["install"]["meta"], chain["install"]["meta"]


def test_a_refresh_with_no_online_change_writes_no_record(chain):
    assert KEY not in chain["no_change"]["meta"], chain["no_change"]["meta"]


def test_a_refresh_that_changed_a_version_records_it_and_keeps_the_tag(chain):
    meta = chain["changed"]["meta"]
    assert meta.get("bundle_tag"), meta
    assert meta["bundle_tag"] == chain["install"]["meta"].get("bundle_tag"), meta
    assert KEY in meta, meta


@pytest.mark.parametrize("name", LATER)
def test_a_later_refresh_that_changed_no_version_keeps_the_record(chain, name):
    want = chain["changed"]["meta"].get(KEY)
    assert chain[name]["meta"].get(KEY) == want, chain[name]["meta"]


def test_a_check_only_refresh_changes_neither_time_nor_the_tag(chain):
    keys = ("refreshed_at", "refreshed", "bundle_tag")
    before = chain["single_source"]["meta"]
    after = chain["check_only"]["meta"]
    assert {k: after.get(k) for k in keys} == {k: before.get(k) for k in keys}


def test_an_install_over_a_dir_with_a_record_leaves_none(chain):
    assert KEY not in chain["install_over"]["meta"], chain["install_over"]["meta"]
