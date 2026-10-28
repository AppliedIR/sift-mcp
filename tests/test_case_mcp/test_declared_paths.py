"""log_external_action records a relative path where the AI meant it, the
active case folder, and says what it couldn't record. Each row calls the tools
as a client does (call_tool), with the server's cwd a folder that isn't the
case, and reads the record back with the readers that use it.

- A relative entry is recorded absolute under the case folder, normalized;
  an absolute one as given. VHIR_AUDIT_DIR moves only where the entry goes.
- Through a symlinked case folder the record still links.
- With no active case the reply says the action wasn't recorded.
- The reply names every entry recorded without a hash (a `pending:` hash
  isn't one); for a folder output, that its files weren't recorded and the
  step can't be cited by its summary.
- The texts that point here (evidence_register, the grader's fix) name the
  way out the same way.
"""

import asyncio
import hashlib
import json
from datetime import datetime, timezone

import pytest
import yaml
from case_mcp.server import create_server

WAYS_OUT = (
    "Ways out, in this order: (1) re-make it with run_command from registered "
    "evidence or a recorded output, the only route an ingest accepts; (2) for a "
    "finding only, declare how it was made with log_external_action, naming the "
    "inputs (registered evidence or recorded outputs) in input_files and this "
    "file in output_files. Declare first: reads made before the declaration don't "
    "link, so re-run them after it or cite the declaration's audit_id. For a "
    "folder, name each file."
)
FIX_ORIGIN = (
    "re-make it with run_command from registered evidence or a recorded output; "
    "or, for a finding only, declare how it was made with log_external_action, "
    "naming registered evidence or recorded outputs in input_files and this file "
    "in output_files. Declare first: reads made before the declaration don't link, "
    "so re-run them after it or cite the declaration's audit_id"
)


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def case(tmp_path, monkeypatch):
    for var in (
        "VHIR_CASE_DIR",
        "VHIR_CASES_DIR",
        "VHIR_ACTIVE_CASE",
        "VHIR_AUDIT_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))  # no ~/.vhir/active_case to fall back on
    cd = tmp_path / "cases" / "CASE-1"
    for sub in ("evidence", "extractions/manual", "audit"):
        (cd / sub).mkdir(parents=True)
    meta = {"case_id": "CASE-1", "name": "t", "status": "open", "examiner": "tester",
            "created": datetime.now(timezone.utc).isoformat()}  # fmt: skip
    (cd / "CASE.yaml").write_text(yaml.dump(meta))
    (cd / "evidence.json").write_text('{"files": []}')
    (cd / "evidence" / "orig.bin").write_bytes(b"original bytes\n")
    monkeypatch.setenv("VHIR_CASES_DIR", str(cd.parent))
    monkeypatch.setenv("VHIR_CASE_DIR", str(cd))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    import case_mcp.server as cs

    monkeypatch.setattr(cs, "_ACTIVE_CASE_FILE", home / ".vhir" / "active_case")
    neutral = tmp_path / "neutral"
    neutral.mkdir()
    monkeypatch.chdir(neutral)
    return cd


def _call(srv, name: str, args: dict) -> dict:
    r = asyncio.run(srv.call_tool(name, args))
    blocks = r[0] if isinstance(r, tuple) else r
    return json.loads("".join(b.text for b in blocks))


def _declare(srv, inputs, outputs) -> dict:
    return _call(srv, "log_external_action", {
        "command": "python make.py", "output_summary": "wrote the file",
        "purpose": "make it", "input_files": inputs, "output_files": outputs,
    })  # fmt: skip


def _entry(audit_dir, audit_id) -> dict:
    lines = (audit_dir / "case-mcp.jsonl").read_text().splitlines()
    (e,) = [e for e in map(json.loads, lines) if e.get("audit_id") == audit_id]
    return e


def _bash_made(case, name="rec.bin", data=b"made by bash\n"):
    p = case / "extractions" / "manual" / name
    p.write_bytes(data)
    return p


@pytest.fixture
def srv(case):
    s = create_server()
    assert _call(s, "evidence_register", {"path": "evidence/orig.bin"})["sha256"]
    return s


def _trace(case, path):
    from sift_common import provenance as pv

    return pv.trace_file(pv.load_case(case), str(path), _sha(path.read_bytes()))


# --- where a relative entry is recorded ---------------------------------------


def test_a_relative_entry_is_recorded_under_the_case_folder(case, srv):
    rec = _bash_made(case)
    r = _declare(srv, ["evidence/orig.bin"], ["extractions/manual/rec.bin"])
    e = _entry(case / "audit", r["audit_id"])
    assert [i["path"] for i in e["inputs"]] == [str(case / "evidence" / "orig.bin")]
    (o,) = e["outputs"]
    assert (o["path"], o["sha256"]) == (str(rec), _sha(rec.read_bytes()))
    assert e["result_summary"]["output_files"] == [str(rec)]
    assert r["status"] == "logged" and "files_warning" not in r


def test_every_reader_links_a_relative_declaration_from_another_cwd(case, srv):
    from sift_common import provenance as pv

    rec = _bash_made(case)
    aid = _declare(srv, ["evidence/orig.bin"], ["extractions/manual/rec.bin"])[
        "audit_id"
    ]
    assert _call(srv, "evidence_register", {"path": "extractions/manual/rec.bin"}) == {
        "error": f"{rec} is an output this case recorded ({aid}): register the "
        "original evidence it was made from."
    }
    assert _trace(case, rec).grade == "DECLARED"
    quote = pv.trace_artifact(pv.load_case(case), aid, "made by bash")
    assert quote.grade == "DECLARED"


def test_a_relative_entry_with_dot_dot_is_normalized(case, srv):
    rec = _bash_made(case)
    r = _declare(srv, ["evidence/orig.bin"],
                 ["extractions/../extractions/manual/rec.bin"])  # fmt: skip
    (o,) = _entry(case / "audit", r["audit_id"])["outputs"]
    assert o["path"] == str(rec) and ".." not in o["path"]
    assert _trace(case, rec).grade == "DECLARED"


def test_an_absolute_entry_is_recorded_as_given(case, srv):
    rec = _bash_made(case)
    orig = case / "evidence" / "orig.bin"
    r = _declare(srv, [str(orig)], [str(rec)])
    e = _entry(case / "audit", r["audit_id"])
    assert (e["inputs"][0]["path"], e["outputs"][0]["path"]) == (str(orig), str(rec))
    assert _trace(case, rec).grade == "DECLARED"


def test_absolute_entries_through_a_symlinked_case_folder_link(case, srv, tmp_path):
    link = tmp_path / "linkcase"
    link.symlink_to(case)
    rec = _bash_made(case)
    r = _declare(srv, [str(link / "evidence" / "orig.bin")],
                 [str(link / "extractions" / "manual" / "rec.bin")])  # fmt: skip
    (o,) = _entry(case / "audit", r["audit_id"])["outputs"]
    assert o["realpath"] == str(rec)
    assert _trace(case, rec).grade == "DECLARED"


def test_a_relative_entry_in_a_case_reached_through_a_symlink(
    case, srv, tmp_path, monkeypatch
):
    link = tmp_path / "linkcase"
    link.symlink_to(case)
    monkeypatch.setenv("VHIR_CASE_DIR", str(link))
    rec = _bash_made(case)
    r = _declare(srv, ["evidence/orig.bin"], ["extractions/manual/rec.bin"])
    (o,) = _entry(case / "audit", r["audit_id"])["outputs"]
    assert o["path"] == str(link / "extractions" / "manual" / "rec.bin")
    assert o["realpath"] == str(rec)
    assert _trace(case, rec).grade == "DECLARED"


def test_vhir_audit_dir_moves_the_entry_not_the_paths(case, srv, tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere" / "audit"
    elsewhere.mkdir(parents=True)
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(elsewhere))
    rec = _bash_made(case)
    r = _declare(srv, ["evidence/orig.bin"], ["extractions/manual/rec.bin"])
    e = _entry(elsewhere, r["audit_id"])
    assert e["inputs"][0]["path"] == str(case / "evidence" / "orig.bin")
    assert e["outputs"][0]["path"] == str(rec)


def test_with_no_active_case_the_reply_says_not_recorded(case, monkeypatch):
    monkeypatch.delenv("VHIR_CASE_DIR")
    srv = create_server()
    r = _declare(srv, ["evidence/orig.bin"], ["extractions/manual/rec.bin"])
    assert r["status"] == "not_recorded" and r["audit_id"] is None
    assert r["audit"] == "not recorded: no case was active for this call"


# --- what the reply says it couldn't record -------------------------------------

_UNHASHED = (
    "Recorded without a hash, so nothing can link through them (missing, "
    "misspelled, or not a regular file): {}."
)
_FOLDER = (
    " {} is a folder: its files weren't recorded. Name each one in output_files; "
    "until then this step can't be cited by its output_summary."
)


def test_a_missing_input_and_a_misspelled_output_are_named(case, srv):
    _bash_made(case)
    r = _declare(srv, ["evidence/orig.bin", "evidence/nosuch.bin"],
                 ["extractions/manual/rec.bin", "extractions/manual/rec.bni"])  # fmt: skip
    assert r["status"] == "logged" and r["audit_id"]
    assert r["files_warning"] == _UNHASHED.format(
        f"{case / 'evidence' / 'nosuch.bin'}, {case / 'extractions' / 'manual' / 'rec.bni'}"
    )


@pytest.mark.parametrize("nested", [False, True], ids=["folder", "nested-folder"])
def test_a_folder_output_says_its_files_werent_recorded(case, srv, nested):
    out = case / "extractions" / "manual" / "msgtrk"
    (out / "sub" if nested else out).mkdir(parents=True)
    (out / "sub" / "a.log" if nested else out / "a.log").write_text("x\n")
    r = _declare(srv, ["evidence/orig.bin"], ["extractions/manual/msgtrk"])
    assert r["files_warning"] == _UNHASHED.format(out) + _FOLDER.format(out)


def test_a_pending_hash_and_a_registered_input_are_not_named(case, srv, monkeypatch):
    from sift_common import file_identity as fi

    monkeypatch.setattr(fi, "INLINE_LIMIT", 1)
    _bash_made(case)
    r = _declare(srv, ["evidence/orig.bin", "evidence/nosuch.bin"],
                 ["extractions/manual/rec.bin"])  # fmt: skip
    (o,) = _entry(case / "audit", r["audit_id"])["outputs"]
    assert o["sha256"].startswith("pending:")
    assert r["files_warning"] == _UNHASHED.format(case / "evidence" / "nosuch.bin")


# --- the texts that send the AI here --------------------------------------------


def test_the_graders_fix_for_a_file_with_no_origin_names_both_ways(case, srv):
    t = _trace(case, _bash_made(case))
    assert t.grade == "BROKEN" and t.break_["fix"] == FIX_ORIGIN


def _description(srv, name):
    (tool,) = [t for t in asyncio.run(srv.list_tools()) if t.name == name]
    return " ".join(tool.description.split())


def test_the_docstrings_say_where_paths_resolve_and_the_way_out(case, srv):
    assert (
        "Files under extractions/ are never registered as originals. For one "
        "that no record names: re-make it with run_command from registered "
        "evidence or a recorded output, or, for a finding only, declare how it "
        "was made with log_external_action first."
    ) in _description(srv, "evidence_register")
    assert (
        "A relative path in input_files or output_files resolves against the "
        "active case folder here; run_command resolves one against its op "
        "folder, and evidence_register against the case folder."
    ) in _description(srv, "log_external_action")
