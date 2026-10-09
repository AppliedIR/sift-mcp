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


def test_an_input_that_is_the_registered_folder_itself_traces_to_the_folder(c):
    c.file("evidence/kape/C/System.evtx", "system evtx")
    folder = c.register_folder(str(c.d / "evidence/kape"))
    t = pv.trace_file(pv.load_case(c.d), str(c.d / "evidence/kape"))
    assert t.grade == "FULL", t
    assert t.root == {"path": folder["path"], "sha256": folder["manifest_sha256"],
                      "label": "examiner"}  # fmt: skip
    assert [link["method"] for link in t.links] == ["registered-path"]


def test_vol_on_sample_two_traces_through_the_7z_extraction_to_the_7z(c):
    z = c.file("evidence/mem.7z", "7z bytes")
    c.register(z)
    s1, s2 = c.extract("sift-tester-20261009-001", z)
    c.run(
        "sift-tester-20261009-002", ["vol", "-f", s2, "windows.pslist"], [s2], "PID 4\n"
    )
    t = pv.trace_op(pv.load_case(c.d), "sift-tester-20261009-002")
    assert t.grade == "FULL", t
    assert t.root == {"path": z, "sha256": sha(z), "label": "examiner"}
    assert [(link["method"], link["audit_id"]) for link in t.links] == [
        ("registered-path", ""),
        ("recorded-id", "sift-tester-20261009-001"),
        ("hash+place", "sift-tester-20261009-001"),
        ("recorded-id", "sift-tester-20261009-002"),
    ]
    assert t.links[2]["to"] == {"path": s2, "sha256": sha(s2)}
    assert "sample1" not in str(t.as_dict())


def test_an_unrecorded_copy_of_the_7z_doesnt_link_by_its_hash(c):
    z = c.file("evidence/mem.7z", "7z bytes")
    c.register(z)
    copy = c.file(
        "extractions/work/copy-of-mem.7z", "7z bytes"
    )  # same hash, other path
    c.run("sift-tester-20261009-001", ["7z", "x", copy], [copy], "sample2.raw\n")
    t = pv.trace_op(pv.load_case(c.d), "sift-tester-20261009-001")
    assert t.grade == "BROKEN" and t.break_["kind"] == "no-recorded-origin", t
    assert t.reason == "no recorded origin: made outside recorded tools"


def test_an_output_at_the_same_path_with_another_hash_doesnt_link(c):
    z = c.file("evidence/mem.7z", "7z bytes")
    c.register(z)
    _, s2 = c.extract("sift-tester-20261009-001", z)
    with open(s2, "w") as f:
        f.write("rewritten after the extraction")
    t = pv.trace_file(pv.load_case(c.d), s2, sha(s2))
    assert t.break_["kind"] == "no-recorded-origin" and sha(s2) in t.break_["detail"]


def test_an_input_hashed_in_the_background_links_through_its_completed_job(c):
    z = c.file("evidence/mem.7z", "7z bytes")
    c.register(z)
    _, s2 = c.extract("sift-tester-20261009-001", z)
    c.op(
        "file-identity",
        "fileidentity-tester-20261009-001",
        tool="hash_complete",
        job_id="hash-0123456789abcdef",
        path=s2,
        sha256=sha(s2),
    )
    t = pv.trace_file(pv.load_case(c.d), s2, "pending:hash-0123456789abcdef")
    assert t.grade == "FULL" and t.links[-1]["from"]["sha256"] == sha(s2), t
    unclosed = pv.trace_file(pv.load_case(c.d), s2, "pending:hash-fedcba9876543210")
    assert unclosed.break_["kind"] == "hash-pending", unclosed


def test_sample_two_extracted_twice_to_one_path_is_ambiguous_naming_both(c):
    z = c.file("evidence/mem.7z", "7z bytes")
    c.register(z)
    s2 = c.file("extractions/shared/sample2.raw", "sample two")
    for aid in ("sift-tester-20261009-001", "sift-tester-20261009-002"):
        c.op("sift-mcp", aid, tool="run_command", params={"command": ["7z", "x", z]},
             input_files=[z], input_sha256s=[""],
             result_summary={"output_files": [s2], "output_sha256s": [sha(s2)]})  # fmt: skip
    c.run("sift-tester-20261009-003", ["vol", "-f", s2], [s2], "PID 4\n")
    t = pv.trace_op(pv.load_case(c.d), "sift-tester-20261009-003")
    assert t.grade == "AMBIGUOUS", t  # never the last writer
    assert {x["audit_id"] for x in t.candidates} == {
        "sift-tester-20261009-001", "sift-tester-20261009-002",
    }  # fmt: skip
    assert "2 operations" in t.reason


def test_one_id_on_two_entries_is_ambiguous_never_the_last_copy(c):
    z = c.file("evidence/mem.7z", "7z bytes")
    c.register(z)
    s1, s2 = c.extract("sift-tester-20261009-001", z)
    c.run("sift-tester-20261009-002", ["vol", "-f", s1], [s1], "PID 4\n")
    c.run("sift-tester-20261009-002", ["vol", "-f", s2], [s2], "PID 4\n")
    t = pv.trace_op(pv.load_case(c.d), "sift-tester-20261009-002")
    assert t.grade == "AMBIGUOUS" and len(t.candidates) == 2, t
    assert len({x["entry_sha256"] for x in t.candidates}) == 2


def test_an_operation_whose_inputs_reach_two_roots_is_ambiguous(c):
    a = c.file("evidence/imgA.raw", "image A")
    b = c.file("evidence/imgB.raw", "image B")
    c.register(a)
    c.register(b)
    c.run("sift-tester-20261009-001", ["cmp", a, b], [a, b], "differ\n")
    t = pv.trace_op(pv.load_case(c.d), "sift-tester-20261009-001")
    assert t.grade == "AMBIGUOUS" and {r["path"] for r in t.roots} == {a, b}, t
    assert {x["path"] for x in t.candidates} == {a, b}


@pytest.mark.parametrize("hook", [True, False], ids=["hook and declared", "declared"])
def test_a_bash_extraction_declared_with_log_external_action_is_declared(c, hook):
    z = c.file("evidence/mem.7z", "7z bytes")
    c.register(z)
    s2 = c.file("extractions/bash/sample2.raw", "sample two")
    if hook:  # the hook records the command, not what it made
        c.op("claude-code", "hook-tester-20261009-001", tool="Bash",
             params={"command": f"7z x {z} -oextractions/bash"})  # fmt: skip
    c.op("case-mcp", "case-tester-20261009-001", tool="log_external_action",
         params={"command": f"7z x {z} -oextractions/bash", "purpose": "p"},
         result_summary={"output_files": [s2], "output_sha256s": [sha(s2)]},
         input_files=[z], declared=True)  # fmt: skip
    c.run("sift-tester-20261009-002", ["vol", "-f", s2], [s2], "PID 4\n")
    t = pv.trace_op(pv.load_case(c.d), "sift-tester-20261009-002")
    assert t.grade == "DECLARED" and t.root["path"] == z, t
    methods = {(link["method"], link["audit_id"]) for link in t.links}
    assert ("declared", "case-tester-20261009-001") in methods
    assert "case-tester-20261009-001" in t.reason


def test_an_operation_with_no_recorded_inputs_is_a_named_break(c):
    c.op("sift-mcp", "sift-tester-20261009-001", tool="run_command",
         params={"command": ["hostname"]}, result_summary={"exit_code": 0})  # fmt: skip
    t = pv.trace_op(pv.load_case(c.d), "sift-tester-20261009-001")
    assert t.grade == "BROKEN" and t.break_["kind"] == "no-inputs", t


def test_each_link_carries_its_entry_lines_hash_and_the_root_its_label(c):
    z = c.file("evidence/mem.7z", "7z bytes")
    c.register(z)
    _, s2 = c.extract("sift-tester-20261009-001", z)
    c.run("sift-tester-20261009-002", ["vol", "-f", s2], [s2], "PID 4\n")
    lines = (c.d / "audit" / "sift-mcp.jsonl").read_bytes().splitlines()
    t = pv.trace_op(pv.load_case(c.d), "sift-tester-20261009-002")
    by = {(link["method"], link["audit_id"]): link for link in t.links}
    for method, aid, n in (("recorded-id", "sift-tester-20261009-001", 0),
                           ("hash+place", "sift-tester-20261009-001", 0),
                           ("recorded-id", "sift-tester-20261009-002", 1)):  # fmt: skip
        assert by[(method, aid)]["entry_sha256"] == hashlib.sha256(lines[n]).hexdigest()
    for link in t.links:
        assert set(link) == {"method", "audit_id", "entry_sha256", "from", "to"}


@pytest.mark.parametrize(
    "extra,label",
    [({}, "examiner"), ({"registered_via": "mcp"}, "AI-registered"),
     ({"acquired_by": "wt-tester-20261009-005"}, "acquired by wt-tester-20261009-005")],
    ids=["examiner", "the AI", "an acquisition"],
)  # fmt: skip
def test_the_root_says_who_registered_it(c, extra, label):
    mem = c.file("evidence/acquired/mem.raw", "acquired memory")
    c.register(mem, **extra)
    c.run("sift-tester-20261009-001", ["vol", "-f", mem], [mem], "PID 4\n")
    t = pv.trace_op(pv.load_case(c.d), "sift-tester-20261009-001")
    assert t.grade == "FULL" and t.root["label"] == label, t


def _mounted(c, st_dev, **read):
    a = c.file("evidence/imgA.raw", "image A")
    c.register(a)
    mp = str(c.d / "mnt")
    sec = c.file("mnt/Windows/System32/winevt/Logs/Security.evtx", "evtx inside A")
    c.mount("sift-tester-20261009-001", a, mp, 2049, ts="2026-10-09T01:00:00Z",
            **read.pop("mount_extra", {}))  # fmt: skip
    c.run("sift-tester-20261009-002", ["EvtxECmd", "-f", sec], [sec], "4624 alice\n",
          input_realpaths=[sec], input_st_devs=[st_dev],
          ts=read.pop("ts", "2026-10-09T02:00:00Z"))  # fmt: skip
    return a, pv.trace_op(pv.load_case(c.d), "sift-tester-20261009-002")


def test_a_read_through_a_recorded_mount_links_by_the_mount_to_the_image(c):
    a, t = _mounted(c, 2049)
    assert t.grade == "FULL" and t.root["path"] == a, t
    assert [(link["method"], link["audit_id"]) for link in t.links] == [
        ("registered-path", ""),
        ("recorded-id", "sift-tester-20261009-001"),
        ("recorded-mount", "sift-tester-20261009-001"),
        ("recorded-id", "sift-tester-20261009-002"),
    ]


def test_another_filesystem_under_the_mount_point_breaks(c):
    _, t = _mounted(c, 64768)
    assert t.grade == "BROKEN" and t.break_["kind"] == "mount-mismatch", t


def test_a_read_after_the_recorded_unmount_or_before_the_mount_breaks(c):
    c.op("sift-mcp", "sift-tester-20261009-009", tool="run_command",
         params={"command": ["umount"]}, ts="2026-10-09T01:30:00Z")  # fmt: skip
    _, t = _mounted(c, 2049, mount_extra={"unmounted_by": "sift-tester-20261009-009"})
    assert t.break_["kind"] == "mount-mismatch", t
    _, early = _mounted(
        TrailCase(c.d.parent / "case2"), 2049, ts="2026-10-09T00:30:00Z"
    )
    assert early.break_["kind"] == "mount-mismatch", early
