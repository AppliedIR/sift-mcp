"""What record_finding stores for an artifact: its chain as traced, each step
once (each ingest's steps once, then the records that resolved through it), and
its content whole, checked against its source, up to the 64K limit.

Uses test_finding_chains' own case, entries and helpers.
"""

import collections
import gzip
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from forensic_mcp.case import manager
from sift_common import provenance as pv
from test_case_dashboard.test_portal_chain_steps_once import chain_panel
from test_case_dashboard.test_portal_provenance_display import DRIVER, PAGE

from .test_finding_chains import (  # noqa: F401
    _doc,
    _extract,
    _ingested_samples,
    _mount,
    _search,
    _seven_zip,
    _unregistered_ingest,
    c,
    g,
    sha,
    two_images,
)

CAP = 5000


def _key(link) -> str:
    return json.dumps(link, sort_keys=True)


def _fan_in(c):
    """One run reading two files that one recorded extraction made from one
    registered 7z: both inputs trace through the same steps."""
    z = _seven_zip(c)
    s1, s2 = _extract(c, "sift-tester-20261009-001", z)
    c.run(
        "sift-tester-20261009-002",
        ["cat", s1, s2],
        [s1, s2],
        "sample one\nsample two\n",
    )
    return "sift-tester-20261009-002"


def test_a_fan_in_chain_stores_each_step_once(c):
    aid = _fan_in(c)
    res, st = c.find([{"content": "sample one\nsample two", "audit_id": aid}])
    chain = st["artifacts"][0]["provenance_chain"]
    n = collections.Counter(_key(x) for x in chain)
    assert g(res, st)[0] == "FULL", g(res, st)
    assert chain and max(n.values()) == 1, n


def test_the_stored_chain_is_the_traces_links_each_step_once(c):
    aid = _fan_in(c)
    t = pv.trace_artifact(pv.load_case(c.d), aid, "sample one\nsample two")
    keys = [_key(x) for x in t.links]
    assert len(keys) == len(set(keys))  # both inputs' shared steps, once
    res, st = c.find([{"content": "sample one\nsample two", "audit_id": aid}])
    a = st["artifacts"][0]
    assert a["provenance_chain"] == json.loads(json.dumps(t.links))
    assert (a["provenance_grade"], res["provenance_grade"]) == (t.grade, t.grade)


def test_a_chain_with_no_repeats_is_stored_as_traced(c):
    z = _seven_zip(c)
    s1, _s2 = _extract(c, "sift-tester-20261009-001", z)
    c.run("sift-tester-20261009-002", ["cat", s1], [s1], "sample one\n")
    t = pv.trace_artifact(pv.load_case(c.d), "sift-tester-20261009-002", "sample one")
    res, st = c.find(
        [{"content": "sample one", "audit_id": "sift-tester-20261009-002"}]
    )
    assert g(res, st)[0] == "FULL", g(res, st)
    assert st["artifacts"][0]["provenance_chain"] == json.loads(json.dumps(t.links))


def test_a_stored_fan_in_chain_keeps_each_link_once_first_kept():
    fixture = Path(__file__).parents[1] / "fixtures" / "fan_in_chain.json.gz"
    chain = json.loads(gzip.decompress(fixture.read_bytes()))[0]["artifacts"][0][
        "provenance_chain"
    ]
    kept = manager._distinct_links(chain)
    assert (len(chain), len(kept)) == (1082, 364)
    assert [_key(x) for x in kept] == list(dict.fromkeys(_key(x) for x in chain))
    assert kept[0] is chain[0]


# --- each shape: record_finding -> the stored chain -> the Portal's chain -------

X = "opensearch-ingest-7-20261009-010"
I1, I2 = "opensearch-ingest-7-20261009-011", "opensearch-ingest-7-20261009-012"
O = "opensearch-tester-20261003-004"  # an ingest from before 0.6.4, no origin
M, R = "sift-tester-20261009-001", "sift-tester-20261009-002"  # a mount, a run
# the registered root's link (no audit id), the extraction's two links, the
# ingests, the old ingest, the mount's links, the run
NAMES = {"": "Z", X: "X", I1: "I1", I2: "I2", O: "O", M: "M", R: "R"}
Z_X = ["Z", "X", "X"]
STEP = "border-left:2px solid var(--border)"
FULL = ("FULL", None)


def _two_ingests_of_one_sample(c):
    """Two recorded ingests of sample two, both reached through one extraction:
    each record's chain is that step, then its own ingest."""
    s2 = _extract(c, X, _seven_zip(c), log="opensearch-ingest-7", tool="extract_archive")[1]  # fmt: skip
    for aid, tool in ((I1, "ingest_vol3_pslist"), (I2, "ingest_vol3_netscan")):
        c.op(
            "opensearch-ingest-7",
            aid,
            tool=tool,
            params={"run_id": "run-m", "image": s2},
            input_files=[s2],
            input_sha256s=[sha(s2)],
            input_detection_method="parsed",
        )


def _records(*ingests, **fields):
    """A quote in records d1, d2, ... returned from `ingests` in turn."""

    def build(c):
        _two_ingests_of_one_sample(c)
        docs = [
            _doc(f"d{i}", ing, **{"process.name": "evil.exe", **fields})
            for i, ing in enumerate(ingests, 1)
        ]
        return _search(c, docs), "evil.exe"

    return build


def _stamps(c):
    """Two records of one ingest: d1 stamped with the root it reaches, d2 with
    another registered file."""
    _two_ingests_of_one_sample(c)
    other = c.file("evidence/other.7z", "other bytes")
    c.register(other)
    root = str(c.d / "evidence" / "mem.7z")
    docs = [
        _doc("d1", I1, **{"process.name": "evil.exe", "vhir.original": sha(root)}),
        _doc("d2", I1, **{"process.name": "evil.exe", "vhir.original": sha(other)}),
    ]
    return _search(c, docs), "evil.exe"


def _mount_fan_in(c):
    """One run reading three files under one recorded mount of a registered
    image: each input reaches the image and the mount the same way."""
    a, _b = two_images(c)
    mp = c.d / "mnt"
    logs = "mnt/Windows/System32/winevt/Logs"
    files = [c.file(f"{logs}/{n}.evtx", f"{n} inside A") for n in ("Security", "System", "Setup")]  # fmt: skip
    _mount(c, a, str(mp), 2049, M)
    c.run(R, ["cat", *files], files, "4624 alice\n", input_realpaths=files,
          input_st_devs=[2049] * len(files))  # fmt: skip
    return R, "4624 alice"


def _stamped_then_not(c):
    """Two records of an ingest from before 0.6.4 with no recorded origin: d1
    stamped (made outside recorded tools), d2 never stamped (indexed before
    0.6.4). d2's relabel stays d2's: the artifact keeps d1's break."""
    _unregistered_ingest(c, O)
    docs = [
        _doc("d1", O, **{"event.code": "4624"}),
        _doc("d2", O, **{"event.code": "4624", "vhir.content_hash": ""}),
    ]
    return _search(c, docs), "4624"


def _short(chain) -> list:
    return [
        x["document"]["_id"] if isinstance(x.get("document"), dict)
        else NAMES.get(x.get("audit_id"), "?")
        for x in chain
    ]  # fmt: skip


def _old_form(chain) -> list:
    """The chain as record_finding stored it before 0.6.6.2: each record, in the
    order it was returned, after its ingest's whole chain."""
    pending, chain_of, records = [], [], []
    for link in chain:
        if isinstance(link.get("document"), dict):
            chain_of = pending or chain_of
            pending = []
            records.append((link["document"]["_id"], chain_of, link))
        else:
            pending.append(link)
    return [
        x
        for _id, ch, rec in sorted(records, key=lambda r: int(r[0][1:]))
        for x in [*ch, rec]
    ]


def _portal(st, aid) -> list:
    """The finding's chain as the Portal renders it, a name per step."""
    node = shutil.which("node") or pytest.skip("node isn't installed")
    audit = [{"audit_id": aid, "tool": "idx_search"}]
    r = subprocess.run([node, "-e", DRIVER], capture_output=True, text=True, timeout=120,
                       input=json.dumps({"page": str(PAGE), "findings": [st], "audit": audit}))  # fmt: skip
    assert r.returncode == 0, r.stderr[-2000:]
    shown = []
    for step in chain_panel(json.loads(r.stdout), st["id"]).split(STEP)[1:]:
        doc = re.search(r"record (d\d+) in ", step)
        a = re.search(r'data-audit-id="([^"]*)"', step)
        shown.append(doc[1] if doc else NAMES.get(a[1] if a else "", "?"))
    return shown


SEVENTEEN = [f"d{i}" for i in range(1, 18)]
SHAPES = [
    pytest.param(_records(*[I1] * 17), FULL, [*Z_X, "I1", *SEVENTEEN], False,
                 id="one_ingest_17_records"),
    pytest.param(_records(I1, I2), FULL, [*Z_X, "I1", "d1", *Z_X, "I2", "d2"], False,
                 id="two_ingests_one_record_each"),
    pytest.param(_records(I1, I1, I2, I2), FULL,
                 [*Z_X, "I1", "d1", "d2", *Z_X, "I2", "d3", "d4"], False,
                 id="two_ingests_two_records_each_apart"),
    pytest.param(_records(I1, I2, I1, I2), FULL,
                 [*Z_X, "I1", "d1", "d3", *Z_X, "I2", "d2", "d4"], False,
                 id="two_ingests_two_records_each_interleaved"),
    pytest.param(_mount_fan_in, FULL, ["Z", "M", "M", "M", "M", "R"], False,
                 id="fan_in_three_inputs_one_mount"),
    pytest.param(_stamps, ("BROKEN", "stamp-mismatch"), [*Z_X, "I1", "d1", "d2"], False,
                 id="a_stamp_mismatch_beside_a_match"),
    pytest.param(_stamped_then_not, ("BROKEN", "no-recorded-origin"), ["O", "d1", "d2"],
                 False, id="a_records_relabel_stays_its_own"),
    pytest.param(_records(I1, I2, I1), FULL, [*Z_X, "I1", "d1", "d3", *Z_X, "I2", "d2"],
                 True, id="a_chain_stored_before_0_6_6_2"),
]  # fmt: skip


@pytest.mark.parametrize(("build", "grade", "steps", "old"), SHAPES)
def test_each_ingests_steps_are_stored_once_and_render_with_their_records(
    c, build, grade, steps, old
):
    """The stored chain is the trace's links: each ingest's steps once, then the
    records that resolved through it. The grade is the one each shape always
    had. The Portal renders the stored steps in order, and
    a chain stored before 0.6.6.2 (each record after its ingest's steps) the same."""
    aid, quote = build(c)
    res, st = c.find([{"content": quote, "audit_id": aid}])
    assert g(res, st)[:2] == grade, g(res, st)
    chain = st["artifacts"][0]["provenance_chain"]
    t = pv.trace_artifact(pv.load_case(c.d), aid, quote)
    assert chain == json.loads(json.dumps(t.links))
    assert _short(chain) == steps
    if old:
        stored = _old_form(chain)
        assert _short(stored) == [*Z_X, "I1", "d1", *Z_X, "I2", "d2", *Z_X, "I1", "d3"]
        st["artifacts"][0]["provenance_chain"] = stored
    assert _portal(st, aid) == steps


LINK_SHAPES = [
    {"document": d, **({} if t is None else {"to": t})}
    for d in ({"_id": "d1"}, {}, [], None, "d1", 0, 1)
    for t in (None, {}, {"path": ""}, {"path": "/x"}, {"path": []}, {"path": {}},
              {"path": 0}, {"path": float("nan")}, "/x", [], 1)
] + [{}, {"to": {"path": "/x"}}, "x", 1, []]  # fmt: skip


def test_a_record_link_is_the_one_the_portal_groups_records_by():
    """manager's record test answers as the page's isRecord for each shape (each
    shape is JSON text, NaN read as JS reads it)."""
    js = re.search(r"function isRecord\(step\) \{.*?\n    \}", PAGE.read_text(), re.S)
    node = shutil.which("node") or pytest.skip("node isn't installed")
    script = (
        js[0]
        + """
const shapes = JSON.parse(require('fs').readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(shapes.map(s => !!isRecord(eval('(' + s + ')')))));"""
    )
    r = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60,
                       input=json.dumps([json.dumps(x) for x in LINK_SHAPES]))  # fmt: skip
    assert r.returncode == 0, r.stderr[-2000:]
    mine = [manager._is_record_link(x) for x in LINK_SHAPES]
    assert mine == json.loads(r.stdout) and sum(mine) == 24, mine


# --- content over 5000 chars ---------------------------------------------------


def _long_doc():
    fields = {
        f"winlog.event_data.Field{i:03d}": f"value-{i:03d}-" + "A" * 40
        for i in range(120)
    }
    return _doc(
        "d1", "opensearch-ingest-7-20261009-011", **{"event.code": "4624", **fields}
    )


def _quote(doc, limit=None):
    """The record's lines as an indented JSON reply shows them, up to `limit`
    chars on whole lines."""
    lines = [
        ln.strip().rstrip(",") for ln in json.dumps(doc, indent=1).splitlines()[1:-1]
    ]
    out = []
    for ln in lines:
        if limit is not None and len("\n".join(out + [ln])) > limit:
            break
        out.append(ln)
    return "\n".join(out)


def _searched(c):
    _ingested_samples(c)
    d = _long_doc()
    return d, _search(c, [d])


def test_a_quote_under_5000_is_stored_whole_with_no_warning(c):
    d, aid = _searched(c)
    q = _quote(d, 4900)
    res, st = c.find([{"content": q, "audit_id": aid}])
    assert g(res, st)[0] == "FULL", g(res, st)
    assert st["artifacts"][0]["content"] == q
    assert "cut" not in res.get("warning", "")


def test_a_quote_over_5000_is_stored_whole_with_no_warning(c):
    d, aid = _searched(c)
    q = _quote(d)
    assert len(q) > CAP
    res, st = c.find([{"content": q, "audit_id": aid}])
    assert g(res, st)[0] == "FULL", g(res, st)
    assert st["artifacts"][0]["content"] == q
    assert "cut" not in res.get("warning", "")
    t = pv.trace_artifact(pv.load_case(c.d), aid, q)
    assert t.grade == "FULL"


def test_each_long_artifact_is_stored_whole_after_its_whitespace_is_stripped(c):
    d, aid = _searched(c)
    q = _quote(d)
    short = _quote(d, 200)
    res, st = c.find(
        [
            {"content": short, "audit_id": aid},
            {"content": q, "audit_id": aid},
            {"content": q + "\n" + "\t", "audit_id": aid},
        ]
    )
    assert [a["content"] for a in st["artifacts"]] == [short, q, q]
    assert "cut" not in res.get("warning", "")


def test_a_long_quote_that_doesnt_verify_is_stored_whole_and_cited_unverified(c):
    d, aid = _searched(c)
    q = _quote(d) + "\n" + '"winlog.event_data.Planted": "not in the record"'
    res, st = c.find([{"content": q, "audit_id": aid}])
    assert g(res, st)[0] == "CITED-UNVERIFIED", g(res, st)
    assert st["artifacts"][0]["content"] == q


# --- the longest quote checked -------------------------------------------------

QUOTE_CAP = 64 << 10


def test_a_quote_at_the_check_limit_is_checked_and_stored_whole(c):
    _d, aid = _searched(c)
    q = ("A" * 63 + "\n") * (QUOTE_CAP // 64 - 1) + "A" * 64
    res, st = c.find([{"content": q, "audit_id": aid}])
    assert len(q) == QUOTE_CAP
    assert res["status"] == "STAGED", res
    assert st["artifacts"][0]["content"] == q
    assert "cut" not in res.get("warning", "")


def test_a_quote_over_the_limit_is_refused_by_its_place(c):
    d, aid = _searched(c)
    q = "A" * (QUOTE_CAP + 1)
    res, st = c.find(
        [{"content": _quote(d, 200), "audit_id": aid}, {"content": q, "audit_id": aid}]
    )
    assert st is None
    assert res == {
        "status": "REJECTED",
        "error": (
            f"Artifact 2: content is {QUOTE_CAP + 1:,} chars, over the {QUOTE_CAP:,} "
            f"limit. Send at most {QUOTE_CAP:,} chars: the output lines the cited "
            "operation produced, as returned. The finding wasn't recorded."
        ),
    }
    assert (c.d / "findings.json").read_text() == "[]"


def test_whitespace_around_a_quote_doesnt_count_toward_the_limit(c):
    _d, aid = _searched(c)
    q = "\n" * 10 + "A" * QUOTE_CAP + " \t\n" * 10
    res, _st = c.find([{"content": q, "audit_id": aid}])
    assert res["status"] == "STAGED", res
