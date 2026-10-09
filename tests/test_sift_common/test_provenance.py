"""Provenance: a file or a recorded operation traced to the registered evidence
it came from, through recorded links only.

The finding resolver searched for candidates after the fact: the first ingest
in the trail, a registered file under a folder input, any file with an equal
hash wherever it sat, the last entry that wrote a path. Here each link is one
the case recorded (a registered path, a folder's manifest, an operation's
recorded output at the same path with the same hash, a recorded mount, an
operation's recorded inputs), and a trace that can't be built says where it
breaks: FULL, DECLARED, AMBIGUOUS or BROKEN.
"""

from __future__ import annotations

import hashlib

import pytest
from sift_common import provenance as pv

from .provenance_case import TrailCase, sha


@pytest.fixture
def c(tmp_path):
    return TrailCase(tmp_path / "case")


def test_the_case_is_read_once_with_each_entrys_line_bytes(c):
    z = c.file("evidence/mem.7z", "7z bytes")
    root = c.register(z)
    line = c.op("sift-mcp", "sift-tester-20261009-001", tool="run_command")
    c.op("opensearch-mcp", "opensearch-tester-20261009-001", tool="idx_search")
    with open(c.d / "audit" / "sift-mcp.jsonl", "a") as f:
        f.write("not json\n")  # skipped
    case = pv.load_case(c.d)
    assert case.roots == [root]
    ((entry, raw),) = case.by_id["sift-tester-20261009-001"]
    assert raw == line and entry["tool"] == "run_command"
    assert set(case.by_id) == {
        "sift-tester-20261009-001",
        "opensearch-tester-20261009-001",
    }


def test_an_operation_the_trail_doesnt_hold_is_a_named_break(c):
    t = pv.trace_op(pv.load_case(c.d), "sift-tester-20261009-404")
    assert t.grade == "BROKEN" and t.break_["kind"] == "no-entry"
    assert "sift-tester-20261009-404" in t.reason
    assert t.as_dict()["break"] == t.break_ and t.as_dict()["grade"] == "BROKEN"


def test_a_file_with_no_recorded_origin_is_a_named_break_with_a_fix(c):
    loose = c.file("extractions/loose/sample2.raw", "sample two")
    t = pv.trace_file(pv.load_case(c.d), loose, sha(loose))
    assert t.grade == "BROKEN" and t.break_["kind"] == "no-recorded-origin"
    assert t.reason == "no recorded origin: made outside recorded tools"
    assert loose in t.break_["detail"] and t.break_["fix"]
    assert (t.root, t.roots, t.links, t.candidates) == (None, [], [], [])


def test_an_entry_line_hash_is_the_sha256_of_its_bytes():
    assert pv.entry_sha256(b'{"a": 1}') == hashlib.sha256(b'{"a": 1}').hexdigest()


def test_a_registered_file_links_by_its_path_with_the_registry_hash(c, tmp_path):
    z = c.file("evidence/mem.7z", "7z bytes")
    root = c.register(z)
    with open(z, "w") as f:
        f.write(
            "changed after registration"
        )  # not re-hashed: that's the approval check's
    link = tmp_path / "via-link.7z"
    link.symlink_to(z)
    for p in (z, str(link)):
        t = pv.trace_file(pv.load_case(c.d), p, "")
        assert t.grade == "FULL" and t.root["path"] == root["path"], t
        assert t.root["sha256"] == root["sha256"] and t.roots == [t.root]
        (first,) = t.links
        assert first["method"] == "registered-path"
        assert first["to"] == {"path": root["path"], "sha256": root["sha256"]}


def test_a_file_in_a_registered_folders_manifest_links_by_the_manifest(c):
    f1 = c.file(
        "evidence/kape/C/Windows/System32/winevt/Logs/System.evtx", "system evtx"
    )
    folder = c.register_folder(str(c.d / "evidence/kape"))
    t = pv.trace_file(pv.load_case(c.d), f1, sha(f1))
    assert t.grade == "FULL" and t.root["sha256"] == sha(f1), t
    assert t.root["path"] == f1 and t.root["folder"] == folder["path"]
    assert [link["method"] for link in t.links] == ["manifest"]


def test_a_folder_file_outside_its_manifest_or_behind_a_changed_one_doesnt_link(c):
    f1 = c.file("evidence/kape/a.evtx", "a")
    folder = c.register_folder(str(c.d / "evidence/kape"))
    late = c.file("evidence/kape/late.evtx", "added later")
    case = pv.load_case(c.d)
    assert pv.trace_file(case, late, sha(late)).break_["kind"] == "no-recorded-origin"
    manifest = c.d / folder["manifest_path"]
    manifest.write_bytes(manifest.read_bytes() + b" ")
    assert pv.trace_file(pv.load_case(c.d), f1, sha(f1)).grade == "BROKEN"
