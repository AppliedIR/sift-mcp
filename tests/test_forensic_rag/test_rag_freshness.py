"""The freshness summary status gives the installers: the state of the index
and of the update check, the sources with updates and those not checked, the
counts, the one line both installers print, and status's overall time limit.

Every run goes through _rag_versions_probe.py in a fresh process on a scratch
copy of the package, as in test_rag_versions.py. The lookups run through the
package's own fetch path and are answered at urlopen from the probe's Net
table: a 403, a lookup that hangs for the whole timeout it is given, or a
version; any URL the table does not name fails at once, as with no network.
Where the index dir matters two forms are run, as the two installers call
status: "lite" sets RAG_INDEX_DIR to its own dir, "setup_sift" sets none, so
the package's own data dir is used.
"""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path

import pytest

from .test_rag_versions import (
    ALL,
    EMBEDDED,
    ONLINE,
    entry,
    make_rig,
    plant_config,
    plant_state,
    run_probe,
    sources,
)

DEADLINE = 45  # status's own overall limit, counted from its start
INSTALLER_LIMIT = 60  # the installers' timeout around a status run
FORMS = ["lite", "setup_sift"]
INSTALLERS = ["setup-sift.sh", "quickstart-lite.sh"]
REPO = Path(__file__).resolve().parents[2]
FORBIDDEN = {"status": 403}
HANG = {"hang": True}
NEWER = "111111111111"
OTHER = "abcdef012345"
NO_NETWORK: list = []


def version_of(name: str) -> str:
    if name in EMBEDDED:
        return "embedded"
    return hashlib.sha256(sources.SOURCES[name].repo.encode()).hexdigest()[:12]


VERSIONS = {n: version_of(n) for n in ALL}


def entries(versions: dict) -> dict:
    return {n: entry(versions[n]) for n in ALL}


def table(rules: dict | None = None, rest: dict | None = None) -> list:
    """A Net table with one row per online source: rules[name] if given,
    else rest, else the version planted for it."""
    rows = []
    for name in ONLINE:
        cfg = sources.SOURCES[name]
        match = cfg.repo if cfg.source_type == "json_feed" else f"/repos/{cfg.repo}/"
        rule = (rules or {}).get(name) or rest or {"version": VERSIONS[name]}
        rows.append([match, rule])
    return rows


def index_rig(root: Path, form: str = "setup_sift", **plant) -> dict:
    """A rig whose form's index dir holds the planted state and, unless
    index is False, a chroma dir: count documents in the named collection."""
    rig = make_rig(root / "rig")
    dest = root / "index" if form == "lite" else rig.data
    dest.mkdir(parents=True, exist_ok=True)
    env = {"RAG_KNOWLEDGE_DIR": str(rig.empty), "GITHUB_TOKEN": None}
    if form != "lite":
        env["RAG_INDEX_DIR"] = None
    plant_state([dest], entries(VERSIONS))
    if plant.get("package_versions"):
        plant_state([rig.data], entries(plant["package_versions"]))
    if plant.get("disabled"):
        plant_config(dest, plant["disabled"])
    if plant.get("index", True):
        op = {
            "op": "index",
            "dir": str(dest),
            "count": plant.get("count", 1),
            "collection": plant.get("collection", "ir_knowledge"),
        }
        res = run_probe(rig, [op], index_dir=dest, env=env, net=NO_NETWORK)
        assert res["ops"][0]["error"] is None
    return {"rig": rig, "dest": dest, "env": env}


def status_run(run: dict, argv: list[str], net: list, open_delay=None) -> dict:
    """One status run alone in its process, timed from the test's side too."""
    op: dict = {"op": "status", "argv": argv}
    if open_delay:
        op["open_delay"] = open_delay
    began = time.monotonic()
    res = run_probe(run["rig"], [op], index_dir=run["dest"], env=run["env"], net=net)
    out = res["ops"][0]
    out["wall"] = time.monotonic() - began
    return out


def fresh(op: dict) -> dict:
    js = op["json"] or {}
    assert "freshness" in js, f"no freshness object in: {sorted(js)}"
    return js["freshness"]


def listed(op: dict) -> dict:
    return {s["name"]: s for s in (op["json"] or {}).get("online_sources", [])}


CASES = {
    "all_current": (["--json"], table(), None),
    "all_forbidden": (["--json"], table(rest=FORBIDDEN), None),
    "one_forbidden": (["--json"], table({"sigma": FORBIDDEN}), None),
    "one_hung": (["--json"], table({"sigma": HANG}), None),
    "slow_open_and_hung": (["--json"], table({"sigma": HANG}, rest=FORBIDDEN), 30),
    "updates_and_forbidden": (
        ["--json"],
        table(
            {
                "sigma": {"version": NEWER},
                "atomic": {"version": NEWER},
                "elastic": FORBIDDEN,
                "splunk_security": FORBIDDEN,
            }
        ),
        None,
    ),
    "no_check": (["--json", "--no-check"], table(), None),
}
UNCHECKED_CASES = [
    "all_forbidden",
    "one_forbidden",
    "one_hung",
    "slow_open_and_hung",
    "updates_and_forbidden",
    "no_check",
]
TIMED_CASES = ["one_hung", "slow_open_and_hung"]


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    """Each case's status run over one index with every source's version
    planted, run once when a test first asks for it."""
    run = index_rig(tmp_path_factory.mktemp("current"))
    done: dict = {}

    def get(name: str) -> dict:
        if name not in done:
            argv, net, delay = CASES[name]
            done[name] = status_run(run, argv, net, delay)
        return done[name]

    return get


def test_all_lookups_matching_the_state_is_current(case):
    fr = fresh(case("all_current"))
    assert (fr["state"], fr["updates"], fr["unchecked"]) == ("current", [], [])


def test_current_line_says_current(case):
    assert "current" in fresh(case("all_current"))["line"].lower()


def test_counts_are_every_source_and_its_lookups(case):
    fr = fresh(case("all_current"))
    assert (fr["enabled"], fr["checked"]) == (len(ALL), len(ONLINE))


def test_counts_in_the_line_name_the_embedded_source(case):
    line = fresh(case("all_current"))["line"]
    assert str(len(ALL)) in line
    assert str(len(ONLINE)) in line
    assert all(name in line for name in EMBEDDED)


def test_every_lookup_forbidden_leaves_every_online_source_unchecked(case):
    fr = fresh(case("all_forbidden"))
    assert (fr["state"], fr["updates"]) == ("unchecked", [])
    assert sorted(fr["unchecked"]) == ONLINE


def test_one_forbidden_lookup_is_the_only_unchecked_source(case):
    fr = fresh(case("one_forbidden"))
    assert (fr["state"], fr["updates"], fr["unchecked"]) == ("unchecked", [], ["sigma"])


def test_hung_lookup_is_unchecked(case):
    fr = fresh(case("one_hung"))
    assert (fr["state"], fr["updates"]) == ("unchecked", [])
    assert "sigma" in fr["unchecked"]


def test_slow_open_and_hung_lookup_leave_every_source_unchecked(case):
    fr = fresh(case("slow_open_and_hung"))
    assert (fr["state"], fr["updates"]) == ("unchecked", [])
    assert sorted(fr["unchecked"]) == ONLINE


@pytest.mark.parametrize("name", TIMED_CASES)
def test_status_run_ends_within_its_deadline(case, name):
    op = case(name)
    assert op["seconds"] < DEADLINE
    assert op["wall"] < DEADLINE
    assert (op["rc"], op["error"]) == (0, None)


@pytest.mark.parametrize("name", TIMED_CASES)
def test_status_process_ends_within_the_installers_limit(case, name):
    assert case(name)["wall"] < INSTALLER_LIMIT


def test_updates_and_forbidden_lookups_keep_both_lists(case):
    fr = fresh(case("updates_and_forbidden"))
    assert fr["state"] == "updates"
    assert sorted(fr["updates"]) == ["atomic", "sigma"]
    assert sorted(fr["unchecked"]) == ["elastic", "splunk_security"]


def test_updates_line_names_both_lists(case):
    line = fresh(case("updates_and_forbidden"))["line"]
    assert all(n in line for n in ["atomic", "sigma", "elastic", "splunk_security"])


def test_no_check_leaves_every_online_source_unchecked(case):
    fr = fresh(case("no_check"))
    assert (fr["state"], fr["updates"]) == ("unchecked", [])
    assert sorted(fr["unchecked"]) == ONLINE


@pytest.mark.parametrize("name", UNCHECKED_CASES)
def test_line_with_an_unchecked_source_never_says_current(case, name):
    fr = fresh(case(name))
    assert fr["unchecked"]
    assert "current" not in fr["line"].lower()


@pytest.mark.parametrize("name", UNCHECKED_CASES)
def test_line_names_every_unchecked_source(case, name):
    fr = fresh(case(name))
    assert [n for n in fr["unchecked"] if n not in fr["line"]] == []


CHECK_ARGV = {"check": ["--json"], "no_check": ["--json", "--no-check"]}


@pytest.fixture(scope="module")
def disabled(tmp_path_factory):
    """sigma disabled in the index dir's config, every other lookup current."""
    run = index_rig(tmp_path_factory.mktemp("disabled"), disabled=["sigma"])
    return {k: status_run(run, argv, table()) for k, argv in CHECK_ARGV.items()}


@pytest.mark.parametrize("mode", list(CHECK_ARGV))
def test_disabled_source_is_not_listed(disabled, mode):
    assert "sigma" not in listed(disabled[mode])


@pytest.mark.parametrize("mode", list(CHECK_ARGV))
def test_disabled_source_is_in_no_list(disabled, mode):
    fr = fresh(disabled[mode])
    assert "sigma" not in fr["updates"] + fr["unchecked"]
    assert fr["enabled"] == len(ALL) - 1


def test_no_check_lists_only_the_enabled_online_sources(disabled):
    fr = fresh(disabled["no_check"])
    assert sorted(fr["unchecked"]) == [n for n in ONLINE if n != "sigma"]


@pytest.fixture(scope="module")
def no_collection(tmp_path_factory):
    """A chroma dir holding a collection, but not the knowledge collection."""
    runs = {}
    for form in FORMS:
        root = tmp_path_factory.mktemp(f"no-collection-{form}")
        run = index_rig(root, form, collection="unrelated")
        runs[form] = status_run(run, ["--json"], NO_NETWORK)
    return runs


@pytest.mark.parametrize("form", FORMS)
def test_index_without_the_knowledge_collection_warns(no_collection, form):
    warnings = (no_collection[form]["json"] or {}).get("warnings", [])
    assert any(w.startswith("Error reading ChromaDB") for w in warnings)


@pytest.mark.parametrize("form", FORMS)
def test_index_without_the_knowledge_collection_is_unreadable(no_collection, form):
    assert fresh(no_collection[form])["state"] == "unreadable"


@pytest.mark.parametrize("form", FORMS)
def test_unreadable_line_says_unreadable_never_current(no_collection, form):
    line = fresh(no_collection[form])["line"].lower()
    assert "unreadable" in line
    assert "current" not in line


@pytest.fixture(scope="module")
def absent(tmp_path_factory):
    """The state planted, but no chroma dir."""
    runs = {}
    for form in FORMS:
        run = index_rig(tmp_path_factory.mktemp(f"absent-{form}"), form, index=False)
        runs[form] = status_run(run, ["--json"], NO_NETWORK)
    return runs


@pytest.mark.parametrize("form", FORMS)
def test_absent_index_warns_index_not_found(absent, form):
    warnings = (absent[form]["json"] or {}).get("warnings", [])
    assert any(w.startswith("Index not found") for w in warnings)


@pytest.mark.parametrize("form", FORMS)
def test_absent_index_is_the_absent_state(absent, form):
    assert fresh(absent[form])["state"] == "absent"


@pytest.mark.parametrize("form", FORMS)
def test_absent_line_says_index_not_found(absent, form):
    assert "Index not found" in fresh(absent[form])["line"]


@pytest.mark.parametrize("form", FORMS)
def test_absent_line_is_never_current_or_empty(absent, form):
    line = fresh(absent[form])["line"].lower()
    assert "current" not in line
    assert "empty" not in line


@pytest.mark.parametrize("form", FORMS)
def test_absent_line_carries_no_build_hint(absent, form):
    assert "rag_mcp.build" not in fresh(absent[form])["line"]


@pytest.fixture(scope="module")
def empty(tmp_path_factory):
    """An index that opens and holds 0 documents; for lite, a different,
    well-formed state in the package's data dir as well."""
    runs = {}
    for form in FORMS:
        package = {n: OTHER for n in ONLINE} | {n: "embedded" for n in EMBEDDED}
        run = index_rig(
            tmp_path_factory.mktemp(f"empty-{form}"),
            form,
            count=0,
            package_versions=package if form == "lite" else None,
        )
        runs[form] = {k: status_run(run, a, NO_NETWORK) for k, a in CHECK_ARGV.items()}
    return runs


@pytest.mark.parametrize("form", FORMS)
def test_index_with_no_documents_is_empty(empty, form):
    assert fresh(empty[form]["check"])["state"] == "empty"


@pytest.mark.parametrize("form", FORMS)
def test_empty_line_says_empty_never_current(empty, form):
    line = fresh(empty[form]["check"])["line"].lower()
    assert "empty" in line
    assert "current" not in line


@pytest.mark.parametrize("mode", list(CHECK_ARGV))
def test_empty_index_state_read_is_the_index_dirs_not_the_package_dirs(empty, mode):
    got = listed(empty["lite"][mode])
    assert {n: got.get(n, {}).get("current_version") for n in ONLINE} == {
        n: VERSIONS[n] for n in ONLINE
    }


@pytest.mark.parametrize("script", INSTALLERS)
def test_installer_does_not_read_has_update(script):
    text = (REPO / script).read_text(encoding="utf-8")
    assert [i for i, ln in enumerate(text.splitlines(), 1) if "has_update" in ln] == []


@pytest.mark.parametrize("script", INSTALLERS)
def test_installer_holds_no_literal_source_count(script):
    text = (REPO / script).read_text(encoding="utf-8")
    found = re.compile(r"\b\d+ sources\b")
    assert [i for i, ln in enumerate(text.splitlines(), 1) if found.search(ln)] == []
