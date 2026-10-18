"""A folder run_command reads is recorded with its members' digest, and a cite
of that run grades FULL only when exactly one registered folder's manifest
rows, or one earlier run's recorded outputs, under it give that digest; an
ineligible folder keeps today's record and today's break."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time

import pytest
from sift_common import file_identity as fi
from sift_common import file_place
from sift_common import provenance as pv
from sift_mcp.server import create_server

PRODUCE = (
    "import os, sys\n"
    "open(sys.argv[1]).read()\n"
    "for kv in sys.argv[4:]:\n"
    "    n, _, v = kv.partition('=')\n"
    "    os.makedirs(os.path.dirname(os.path.join(sys.argv[3], n)), exist_ok=True)\n"
    "    open(os.path.join(sys.argv[3], n), 'w').write(v)\n"
)
READ_ALL = (
    "import os, sys\n"
    "p = sys.argv[1]\n"
    "fs = [p] if os.path.isfile(p) else [os.path.join(r, n)\n"
    "    for r, _, ns in sorted(os.walk(p)) for n in sorted(ns)]\n"
    "for f in fs:\n"
    "    print('row ' + os.path.basename(f) + ':' + open(f).read())\n"
)
MEMBERS = ["a.csv=alpha", ".hidden=dot", "sub/b.csv=" + "b" * 400]


@pytest.fixture
def case(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "examiner1")
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    d = tmp_path / "cases" / "case-a"
    (d / "evidence").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: case-a\nstatus: open\n")
    (home / ".vhir" / "active_case").write_text(str(d))
    src = d / "evidence" / "disk.raw"
    src.write_bytes(b"DISK")
    _registry(d, {"path": str(src.resolve()), "sha256": _sha(b"DISK")})
    return d


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _registry(case, *rows) -> None:
    reg = case / "evidence.json"
    old = json.loads(reg.read_text())["files"] if reg.exists() else []
    reg.write_text(json.dumps({"files": old + list(rows)}))


def _register_folder(case, folder) -> None:
    """As vhir writes a folder root: a manifest of case-relative rows."""
    base = case.resolve()
    rows = [{"path": os.path.relpath(os.path.join(r, n), base),
             "sha256": _sha(open(os.path.join(r, n), "rb").read())}
            for r, _, ns in sorted(os.walk(folder)) for n in sorted(ns)]  # fmt: skip
    data = json.dumps({"folder": str(folder), "files": rows}).encode()
    (case / "evidence-manifests").mkdir(exist_ok=True)
    (case / "evidence-manifests" / "1.json").write_bytes(data)
    _registry(case, {"kind": "folder", "path": os.path.realpath(folder),
                     "manifest_path": "evidence-manifests/1.json",
                     "manifest_sha256": _sha(data), "file_count": len(rows)})  # fmt: skip


def _run(case, *args) -> str:
    r = asyncio.run(
        create_server().call_tool(
            "run_command", {"command": [sys.executable, "-c", *args], "purpose": "t"}
        )
    )
    r = r[0] if isinstance(r, tuple) else r
    return json.loads(r[0].text)["audit_id"]


def _entry(case, aid) -> dict:
    lines = (case / "audit" / "sift-mcp.jsonl").read_text().splitlines()
    (e,) = [e for e in map(json.loads, lines) if e["audit_id"] == aid]
    return e


def _produce(case, folder, members=MEMBERS, wait=True) -> str:
    aid = _run(case, PRODUCE, str(case / "evidence" / "disk.raw"), "--csv",
               str(folder), *members)  # fmt: skip
    log = case / "audit" / "file-identity.jsonl"
    for o in _entry(case, aid)["outputs"] if wait else []:
        deadline = time.monotonic() + 30
        while o["sha256"].startswith("pending:") and time.monotonic() < deadline:
            if o["sha256"][8:] in (log.read_text() if log.exists() else ""):
                break
            time.sleep(0.05)
    return aid


def _cite(case, folder, quote="row a.csv:alpha"):
    aid = _run(case, READ_ALL, str(folder))
    return pv.trace_artifact(pv.load_case(case), aid, quote), _entry(case, aid)


def test_a_folder_of_one_runs_outputs_is_full_one_link_past_a_files(case, monkeypatch):
    folder = case / "extractions" / "out"
    folder.mkdir(parents=True)
    monkeypatch.setattr(fi, "INLINE_LIMIT", 100)  # sub/b.csv goes to a job
    producer = _produce(case, folder)
    assert any(o["sha256"].startswith("pending:")
               for o in _entry(case, producer)["outputs"])  # fmt: skip
    monkeypatch.setattr(fi, "INLINE_LIMIT", 1_000_000_000)
    t, e = _cite(case, folder)
    (rec,) = [i for i in e["inputs"] if i["realpath"] == str(folder.resolve())]
    assert rec["folder"]["files"] == 3 and not rec.get("sha256")  # the dotfile counts
    assert t.grade == "FULL", t
    assert t.root["sha256"] == _sha(b"DISK")
    (link,) = [x for x in t.links if x["method"] == "folder-digest"]
    assert link["audit_id"] == producer and link["entry_sha256"]
    one, _ = _cite(case, folder / "a.csv")  # a member hashed in the call
    methods = [[x["method"] for x in c.links] for c in (t, one)]
    assert one.grade == "FULL" and len(t.links) == len(one.links) + 1, methods


def test_a_sub_folder_of_a_registered_folder_outside_the_case_is_full(case, tmp_path):
    srv = tmp_path / "srv" / "velo"
    (srv / "artifacts").mkdir(parents=True)
    (srv / "artifacts" / "a.csv").write_text("alpha")
    (srv / "artifacts" / "b.json").write_text("{}")
    (srv / "other.txt").write_text("not cited")
    _register_folder(case, srv)
    (tmp_path / "alias").symlink_to(srv)  # cited by another path: by realpath
    t, _ = _cite(case, tmp_path / "alias" / "artifacts")
    assert t.grade == "FULL", t
    assert t.root["path"] == str(srv.resolve())
    assert "folder-digest" in [x["method"] for x in t.links]


def _modify(case, f):
    _produce(case, f)
    (f / "a.csv").write_text("alpha changed")


def _add(case, f):
    _produce(case, f)
    (f / "c.csv").write_text("added")


def _remove(case, f):
    _produce(case, f)
    (f / ".hidden").unlink()


def _mixed(case, f):
    _produce(case, f, ["a.csv=alpha"])
    _produce(case, f, ["b.csv=beta"])


def _registered_changed(case, f):
    f.mkdir(parents=True, exist_ok=True)
    (f / "a.csv").write_text("alpha")
    _register_folder(case, f.parent)
    (f / "a.csv").write_text("alpha rewritten")


def _registered_alone(case, f):
    _produce(case, f)
    _registry(case, {"path": str((f / "a.csv").resolve()), "sha256": _sha(b"alpha")})
    (f / "a.csv").write_text("alpha changed")


def _all_empty(case, f):
    _produce(case, f, ["a.csv=", "b.csv="])


@pytest.mark.parametrize("mutate", [_modify, _add, _remove, _mixed, _registered_changed,
                                    _registered_alone, _all_empty, "producer-after"])  # fmt: skip
def test_a_folder_that_isnt_exactly_one_origin_breaks(case, mutate):
    f = case / "extractions" / "out" / "f"
    if mutate == "producer-after":
        f.mkdir(parents=True)
        (f / "a.csv").write_text("alpha")
        aid = _run(case, READ_ALL, str(f))
        _produce(case, f, ["a.csv=alpha"])  # the same bytes, written later
        t = pv.trace_artifact(pv.load_case(case), aid, "row a.csv:")
        e = _entry(case, aid)
    else:
        mutate(case, f)
        t, e = _cite(case, f, "row a.csv:")
    assert t.grade == "BROKEN" and t.break_["kind"] == "no-recorded-origin", t
    if any("folder" in i for i in e["inputs"]):  # a digest: the folder's reason
        assert "files: no registered folder or single earlier recorded run" in t.reason


def _member_link(f):
    os.symlink("a.csv", f / "l.csv")


def _dir_link(f):
    (f.parent / "D").mkdir()
    (f.parent / "D" / "b.evtx").write_text("outside")
    os.symlink("../D", f / "linkdir")


@pytest.mark.parametrize("shape", ["eligible", "member symlink", "dir symlink", "count",
                                   "bytes", "off case mount", "dir on another mount"])  # fmt: skip
def test_an_ineligible_folder_keeps_todays_record_and_break(case, monkeypatch, shape):
    f = case / "extractions" / "out" / "f"
    _produce(case, f, ["a.csv=alpha", "s/b.csv=beta"])
    {"member symlink": _member_link, "dir symlink": _dir_link}.get(shape, str)(f)
    if shape == "count":
        monkeypatch.setattr(fi, "FOLDER_FILES", 1, raising=False)
    if shape == "bytes":
        monkeypatch.setattr(fi, "FOLDER_BYTES", 8, raising=False)
    real, place, mnt = str(f.resolve()), file_place.place, file_place.mnt_id
    if shape == "off case mount":
        monkeypatch.setattr(file_place, "mnt_id",
                            lambda p: -1 if p == str(case.resolve()) else mnt(p))  # fmt: skip
    if shape == "dir on another mount":
        monkeypatch.setattr(file_place, "place", lambda p: (lambda r: {
            **r, "st_dev": r["st_dev"] + 1} if r.get("realpath") == real else r)(place(p)))  # fmt: skip
    t, e = _cite(case, f)
    (rec,) = [i for i in e["inputs"] if i["realpath"] == real]
    if shape == "eligible":  # the twin: the same fixture carries the field
        assert rec["folder"]["files"] == 2 and t.grade == "FULL", t
        return
    today = {k: v for k, v in rec.items() if k != "folder"}
    assert rec == today == file_place.input_record(case, f)[0]
    assert not (case / "audit" / "file-identity.jsonl").exists()  # no job
    assert t.grade == "BROKEN" and t.reason == pv.NO_ORIGIN, t


def test_two_runs_that_wrote_the_same_folder_are_ambiguous(case):
    f = case / "extractions" / "out"
    one = _produce(case, f, ["a.csv=alpha"])
    two = _produce(case, f, ["a.csv=alpha"])
    t, _ = _cite(case, f)
    assert t.grade == "AMBIGUOUS", t
    assert sorted(c["audit_id"] for c in t.candidates) == sorted([one, two])


def test_a_member_whose_hash_is_still_pending_is_hash_pending(case, monkeypatch):
    f = case / "extractions" / "out"
    monkeypatch.setattr(fi, "INLINE_LIMIT", 100)
    monkeypatch.setattr(fi, "_job", lambda *a: None)  # the job never closes
    _produce(case, f, wait=False)
    monkeypatch.setattr(fi, "INLINE_LIMIT", 1_000_000_000)
    t, _ = _cite(case, f)
    assert t.grade == "BROKEN" and t.break_["kind"] == "hash-pending", t


def test_the_folder_digest_is_one_encoding_of_the_sorted_pairs():
    raw = os.fsdecode(b"bad\xff.evtx")  # a non-UTF-8 name, surrogate-escaped
    pairs = [("b\nc", "1" * 64), (raw, "2" * 64), ("a", "3" * 64)]
    want = json.dumps(sorted(map(list, pairs)), separators=(",", ":")).encode()
    assert fi.folder_digest(pairs) == _sha(want) == fi.folder_digest(pairs[::-1])
    # a newline in a name can't stand in for a pair boundary
    assert fi.folder_digest([("a\n" + "3" * 64, "x")]) != fi.folder_digest(
        [("a", "3" * 64), ("x", "")]
    )
    assert fi.folder_digest([("a", "1" * 64)]) != fi.folder_digest([("A", "1" * 64)])
