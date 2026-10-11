"""Provenance after a restore to another folder.

The trail is restored byte for byte, so its entries still name the folder the
case was in. Restore appends a relocation entry (the folder it came from and
the one it's in now) to every log; the tracer takes a path an entry recorded
through each relocation entry after it in its own log, and only when the
last one ends at this case's folder. A former root of `/`, of this folder or
of a folder above it is ignored, a path already in the case is kept, and an
entry recorded after the restore keeps its paths. Hashes must still match.
"""

from __future__ import annotations

import json
import os

import pytest
from sift_common import provenance as pv

from .provenance_case import TrailCase, sha

AID = "sift-tester-20261011-001"
LATER = "sift-tester-20261011-002"
ING = "opensearch-ingest-tester-20261011-001"
QUERY = "opensearch-tester-20261011-001"


def _mapper(case, entry, path):
    """The tracer's mapper; the path unchanged where there is none."""
    fn = getattr(pv, "relocated", None)
    return fn(case, entry, path) if fn else path


class Moved(TrailCase):
    """A case at <tmp>/C whose trail was recorded at another folder (`old`):
    its files are here and the registry names them here, as restore leaves
    it, while the entries still name `old`."""

    def __init__(self, tmp, old="old/C"):
        super().__init__(tmp / "C")
        self.here = os.path.realpath(self.d)
        self.old = str(tmp / old)
        self.disk = self.file("evidence/disk.bin", b"EVIDENCE" * 100)
        self.register(self.disk)
        self.out = self.file("extractions/op1/out.csv", "line-a\nline-b\n")
        self.stdout = self.file("extractions/op1.txt", "line-a\n")
        self.op("sift-mcp", "sift-tester-20261011-000", tool="list_available_tools")

    def at_old(self, p) -> str:
        return os.path.join(self.old, os.path.relpath(p, self.d))

    def relocate(self, frm, to=None, ts="2026-10-11T00:00:00Z") -> None:
        """Restore's relocation entry, appended to every log."""
        for log in sorted((self.d / "audit").glob("*.jsonl")):
            self.op(log.stem, "restore-tester-20261011-001", tool="restore", ts=ts,
                    relocated_from=frm if isinstance(frm, list) else [frm],
                    to=to or self.here, manifest_sha256="0" * 64)  # fmt: skip

    def run_record(self, aid=AID, base=None, **extra) -> None:
        """A run_command entry in record form, its paths under `base`."""
        at = (
            (lambda p: os.path.join(base, os.path.relpath(p, self.d)))
            if base
            else self.at_old
        )
        disk, out, stdout = at(self.disk), at(self.out), at(self.stdout)
        self.op("sift-mcp", aid, tool="run_command",
                params={"command": ["strings", disk]},
                inputs=extra.pop("inputs", [{"path": disk, "realpath": disk,
                                             "st_dev": 1, "mnt_id": 1}]),
                input_registered=[{"path": disk, "sha256": sha(self.disk)}],
                outputs=extra.pop("outputs", [{"path": out, "realpath": out,
                                               "sha256": sha(self.out)}]),
                result_summary={"exit_code": 0, "output_file": stdout,
                                "output_sha256": sha(self.stdout)}, **extra)  # fmt: skip

    def grades(self) -> tuple[str, str, str]:
        case = pv.load_case(self.d)
        return (
            pv.trace_file(case, self.out, sha(self.out)).grade,
            pv.trace_op(case, AID).grade,
            pv.trace_artifact(case, AID, "line-a").grade,
        )


def _entry(case, aid):
    return case.by_id[aid][0][0]


@pytest.fixture
def m(tmp_path):
    return Moved(tmp_path)


# --- the recorded run, in each of the forms a run is recorded in ---------------


def test_a_run_recorded_before_the_restore_traces_full_at_the_new_folder(m):
    m.run_record()
    m.relocate(m.old)
    assert m.grades() == ("FULL", "FULL", "FULL")
    case = pv.load_case(m.d)
    assert _mapper(case, _entry(case, AID), m.at_old(m.out)) == m.out


def test_a_saved_stdout_over_the_size_cap_is_still_read_at_the_new_folder(
    m, monkeypatch
):
    """The saved stdout is read whatever its size; output files only up to the cap."""
    monkeypatch.setattr(pv, "_QUOTE_FILE_CAP", 1)
    m.run_record()
    m.relocate(m.old)
    assert pv.trace_artifact(pv.load_case(m.d), AID, "line-a").grade == "FULL"


def test_an_input_recorded_by_its_path_alone_is_found_at_the_new_folder(m):
    disk = m.at_old(m.disk)
    m.run_record(inputs=[{"path": disk}])
    m.relocate(m.old)
    assert m.grades() == ("FULL", "FULL", "FULL")


def test_a_run_recorded_in_parallel_lists_traces_full_at_the_new_folder(m):
    disk, out = m.at_old(m.disk), m.at_old(m.out)
    m.op("sift-mcp", AID, tool="run_command", params={"command": ["strings", disk]},
         input_files=[disk], input_sha256s=[""], input_realpaths=[disk],
         input_detection_method="parsed",
         result_summary={"exit_code": 0, "output_files": [out],
                         "output_sha256s": [sha(m.out)]})  # fmt: skip
    m.relocate(m.old)
    case = pv.load_case(m.d)
    assert pv.trace_file(case, m.out, sha(m.out)).grade == "FULL"
    assert pv.trace_op(case, AID).grade == "FULL"


def test_an_output_hashed_by_a_background_job_traces_full_at_the_new_folder(m):
    out = m.at_old(m.out)
    m.run_record(outputs=[{"path": out, "realpath": out, "sha256": "pending:hash-j1"}])
    m.op("file-identity", "fileidentity-tester-20261011-001", tool="hash_complete",
         job_id="hash-j1", path=out, sha256=sha(m.out))  # fmt: skip
    m.relocate(m.old)
    t = pv.trace_file(pv.load_case(m.d), m.out, sha(m.out))
    assert t.grade == "FULL", t


def test_a_saved_query_response_and_a_reference_lookup_are_found_at_the_new_folder(m):
    disk = m.at_old(m.disk)
    m.op("opensearch-ingest", ING, tool="ingest_delimited", input_files=[disk],
         input_sha256s=[""], input_detection_method="parsed")  # fmt: skip
    doc = {"_index": "case-x-evtx", "_id": "d1", "msg": "line-a"}
    resp = m.file(f"extractions/{QUERY}/response.json", json.dumps({"results": [doc]}))
    m.op("opensearch-mcp", QUERY, tool="idx_search",
         params={"query": "line-a", "result_ingests": [ING],
                 "result_docs": [{"_index": "case-x-evtx", "_id": "d1",
                                  "ingest_audit_id": ING, "content_hash": "h1",
                                  "original_sha256": sha(m.disk)}]},
         response={"path": m.at_old(resp), "sha256": sha(resp)})  # fmt: skip
    ref = m.file("extractions/ref/reply.json", json.dumps({"ioc": "line-a"}))
    m.op("threatintel-mcp", "threatintel-tester-20261011-001", tool="lookup_ioc",
         reference={"source": "opencti", "response": {"path": m.at_old(ref),
                                                       "sha256": sha(ref)}})  # fmt: skip
    m.relocate(m.old)
    case = pv.load_case(m.d)
    t = pv.trace_artifact(case, QUERY, "line-a")
    assert t.grade == "FULL", t
    r = pv.trace_artifact(case, "threatintel-tester-20261011-001", "line-a")
    assert (r.break_ or {}).get("kind") == "reference", r  # its response was found


# --- chains --------------------------------------------------------------------


def test_a_chain_of_restores_maps_through_each_to_this_folder(tmp_path):
    m = Moved(tmp_path, old="old/A")
    m.run_record()
    b = str(tmp_path / "old" / "B")
    m.relocate(m.old, to=b)
    m.relocate(b)
    assert m.grades() == ("FULL", "FULL", "FULL")
    case = pv.load_case(m.d)
    assert _mapper(case, _entry(case, AID), m.at_old(m.out)) == m.out


@pytest.mark.timeout(10)
def test_a_restore_back_to_this_folder_ends_and_keeps_its_own_paths(tmp_path):
    m = Moved(tmp_path, old="old/B")
    m.run_record(base=m.here)
    m.run_record(aid=LATER)  # recorded at B
    m.relocate(m.here, to=m.old)  # C -> B
    m.relocate(m.old)  # B -> C
    case = pv.load_case(m.d)
    assert _mapper(case, _entry(case, AID), m.out) == m.out
    assert _mapper(case, _entry(case, LATER), m.at_old(m.out)) == m.out


# --- the trust bounds ----------------------------------------------------------


def _outside(tmp_path, m):
    """A registered file outside the case, and an op that read it."""
    ext = tmp_path / "ext"
    ext.mkdir()
    e01 = str(ext / "disk.E01")
    with open(e01, "wb") as f:
        f.write(b"E01 bytes")
    m.register(e01)
    m.op("sift-mcp", LATER, tool="run_command", params={"command": ["ewfinfo", e01]},
         input_files=[e01], input_sha256s=[""], input_realpaths=[e01],
         input_detection_method="parsed")  # fmt: skip
    return e01


@pytest.mark.parametrize("root", ["/", "parent", "here"])
def test_a_former_root_of_slash_or_this_folder_or_above_it_is_ignored(tmp_path, root):
    m = Moved(tmp_path)
    e01 = _outside(tmp_path, m)
    m.relocate({"/": "/", "parent": str(tmp_path), "here": m.here}[root])
    case = pv.load_case(m.d)
    assert _mapper(case, _entry(case, LATER), e01) == e01
    assert pv.trace_file(case, e01, sha(e01)).grade == "FULL"
    assert pv.trace_op(case, LATER).grade == "FULL"


def test_a_chain_that_ends_at_another_folder_isnt_used(m, tmp_path):
    m.run_record()
    m.relocate(m.old, to=str(tmp_path / "elsewhere" / "D"))
    case = pv.load_case(m.d)
    assert _mapper(case, _entry(case, AID), m.at_old(m.out)) == m.at_old(m.out)
    assert m.grades() == ("BROKEN", "BROKEN", "CITED-UNVERIFIED")


def test_an_op_recorded_after_the_restore_keeps_the_originals_path(m, tmp_path):
    """A copy beside the original reading the original's registered file."""
    m.relocate(m.old)
    orig = m.at_old(m.disk)
    os.makedirs(os.path.dirname(orig))
    with open(orig, "wb") as f:
        f.write(b"EVIDENCE" * 100)
    m.register(orig)
    m.op("sift-mcp", LATER, tool="run_command", params={"command": ["strings", orig]},
         input_files=[orig], input_sha256s=[""], input_realpaths=[orig],
         input_detection_method="parsed")  # fmt: skip
    case = pv.load_case(m.d)
    assert _mapper(case, _entry(case, LATER), orig) == orig
    t = pv.trace_op(case, LATER)
    assert t.grade == "FULL" and t.root["path"] == orig, t


def test_an_op_appended_after_the_restore_with_an_earlier_time_isnt_mapped(m):
    m.relocate(m.old, ts="2026-10-11T12:00:00Z")
    m.run_record(ts="2026-01-01T00:00:00Z")  # back-dated, but after the entry
    case = pv.load_case(m.d)
    assert _mapper(case, _entry(case, AID), m.at_old(m.out)) == m.at_old(m.out)
    assert m.grades()[:2] == ("BROKEN", "BROKEN")


def test_a_log_begun_after_the_restore_maps_nothing(m):
    m.relocate(m.old)
    disk = m.at_old(m.disk)
    m.op("late-mcp", LATER, tool="run_command", params={"command": ["strings", disk]},
         input_files=[disk], input_sha256s=[""], input_realpaths=[disk],
         input_detection_method="parsed")  # fmt: skip
    case = pv.load_case(m.d)
    assert _mapper(case, _entry(case, LATER), disk) == disk
    assert pv.trace_op(case, LATER).grade == "BROKEN"


# --- controls: no wider than intended ------------------------------------------


def test_a_look_alike_folder_isnt_under_the_former_root(m):
    other = m.old + "-other"
    out = os.path.join(other, "extractions/op1/out.csv")
    m.op("sift-mcp", AID, tool="run_command", input_files=[os.path.join(other, "x")],
         input_sha256s=["0" * 64], input_detection_method="parsed",
         result_summary={"output_files": [out], "output_sha256s": [sha(m.out)]})  # fmt: skip
    m.relocate(m.old)
    case = pv.load_case(m.d)
    assert _mapper(case, _entry(case, AID), out) == out
    t = pv.trace_file(case, m.out, sha(m.out))
    assert t.break_["kind"] == "no-recorded-origin", t


def test_only_restores_relocation_entries_count(m):
    m.run_record()
    m.op("sift-mcp", LATER, tool="run_command", relocated_from=[m.old], to=m.here)
    assert m.grades() == ("BROKEN", "BROKEN", "CITED-UNVERIFIED")


def test_a_path_already_in_the_case_keeps_its_grade(m):
    m.run_record(base=m.here)
    m.relocate(m.old)
    m.relocate(os.path.join(m.here, "extractions"))  # a former root inside it
    case = pv.load_case(m.d)
    assert _mapper(case, _entry(case, AID), m.out) == m.out
    assert m.grades() == ("FULL", "FULL", "FULL")


def test_the_mapped_output_with_one_byte_changed_is_broken(m):
    m.run_record()
    m.relocate(m.old)
    with open(m.out, "r+b") as f:
        f.write(b"L")
    t = pv.trace_file(pv.load_case(m.d), m.out, sha(m.out))
    assert t.grade == "BROKEN", t


@pytest.mark.parametrize("relocated", [True, False])
def test_an_input_registered_again_with_new_bytes_is_a_hash_mismatch(m, relocated):
    m.run_record(base=None if relocated else m.here)
    if relocated:
        m.relocate(m.old)
    with open(m.disk, "wb") as f:
        f.write(b"OTHER BYTES")
    reg = json.loads((m.d / "evidence.json").read_text())
    reg["files"][0]["sha256"] = sha(m.disk)
    (m.d / "evidence.json").write_text(json.dumps(reg))
    t = pv.trace_op(pv.load_case(m.d), AID)
    assert t.grade == "BROKEN" and t.break_["kind"] == "hash-mismatch", t


def test_with_no_relocation_entry_the_grades_are_todays(m):
    """A case restored before relocation entries were written."""
    m.run_record()
    assert m.grades() == ("BROKEN", "BROKEN", "CITED-UNVERIFIED")
