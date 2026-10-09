"""run_command's audit entry: one case per call, and cut output says so.

The id used to be minted when the command started, in the case active then,
and written when it ended, into the case active then. A command that switched
cases (or started with none) wrote an id the other case already held. Now the
case is resolved once, when the call starts: the id is minted there, and the
entry and the output are kept there, so a switch during the command moves
nothing and the other case gets nothing. Output cut at the size limit is
marked as cut in the audit entry and in the response's data.

The real run_command runs in-process on scratch cases under a scratch HOME.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sift_mcp.server import create_server

TODAY = datetime.now(timezone.utc).strftime("%Y%m%d")
OWN_001 = f"sift-examiner1-{TODAY}-001"


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "examiner1")
    for var in (
        "VHIR_CASE_DIR",
        "VHIR_AUDIT_DIR",
        "VHIR_ACTIVE_CASE",
        "SIFT_MAX_OUTPUT",
    ):
        monkeypatch.delenv(var, raising=False)
    return home


def _case(tmp_path: Path, name: str) -> Path:
    d = tmp_path / "cases" / name
    d.mkdir(parents=True)
    (d / "CASE.yaml").write_text(f"case_id: {name}\nstatus: open\n")
    return d


def _point(home: Path, case: Path | None) -> None:
    pointer = home / ".vhir" / "active_case"
    if case is None:
        pointer.unlink(missing_ok=True)
    else:
        pointer.write_text(str(case))


def _entries(case: Path) -> list[dict]:
    f = case / "audit" / "sift-mcp.jsonl"
    if not f.exists():
        return []
    return [json.loads(line) for line in f.read_text().splitlines() if line.strip()]


def _preload_own_001(case: Path) -> None:
    (case / "audit").mkdir(parents=True, exist_ok=True)
    entry = {
        "audit_id": OWN_001,
        "mcp": "sift-mcp",
        "tool": "run_command",
        "case_id": case.name,
    }
    (case / "audit" / "sift-mcp.jsonl").write_text(json.dumps(entry) + "\n")


def _run(tmp_path: Path, code: str, **args) -> dict:
    script = tmp_path / f"cmd{len(list(tmp_path.glob('cmd*.py')))}.py"
    script.write_text(code)
    r = asyncio.run(
        create_server().call_tool(
            "run_command",
            {"command": [sys.executable, str(script)], "purpose": "t", **args},
        )
    )
    r = r[0] if isinstance(r, tuple) else r
    return json.loads(r[0].text)


def _switch_to(case: Path, home: Path) -> str:
    return f"open({str(home / '.vhir' / 'active_case')!r}, 'w').write({str(case)!r})\n"


def _only_own_001(case: Path) -> bool:
    return [e["audit_id"] for e in _entries(case)] == [OWN_001]


def test_a_command_that_switches_cases_is_audited_in_the_case_it_started_in(
    tmp_path, home
):
    a, b = _case(tmp_path, "case-a"), _case(tmp_path, "case-b")
    _preload_own_001(b)
    _point(home, a)
    r = _run(tmp_path, _switch_to(b, home) + "print('done')\n")
    assert [e["audit_id"] for e in _entries(a)] == [r["audit_id"]]
    assert _only_own_001(b) and not (b / "extractions").exists()


def test_a_command_that_switches_cases_and_times_out_stays_in_its_case(tmp_path, home):
    a, b = _case(tmp_path, "case-a"), _case(tmp_path, "case-b")
    _preload_own_001(b)
    _point(home, a)
    r = _run(tmp_path, _switch_to(b, home) + "import time; time.sleep(30)\n", timeout=2)
    assert r["success"] is False
    assert [(e["audit_id"], e["case_id"]) for e in _entries(a)] == [
        (r["audit_id"], "case-a")
    ]
    assert _only_own_001(b)


def test_a_command_started_with_no_case_is_not_written_to_a_case_opened_during_it(
    tmp_path, home
):
    b = _case(tmp_path, "case-b")
    _preload_own_001(b)
    _point(home, None)
    r = _run(tmp_path, _switch_to(b, home) + "print('done')\n")
    assert r["audit_id"] is None and "not recorded" in r["warning"]
    assert _only_own_001(b) and not (b / "extractions").exists()


def test_a_case_moved_away_during_a_command_is_not_recreated(tmp_path, home):
    a = _case(tmp_path, "case-a")
    _point(home, a)
    moved = tmp_path / "cases" / "case-a-moved"
    _run(tmp_path, f"import os; os.rename({str(a)!r}, {str(moved)!r})\n")
    assert not a.exists()


def _summary(case: Path) -> dict:
    (entry,) = _entries(case)
    return entry["result_summary"]


def test_output_just_over_the_limit_is_marked_cut(tmp_path, home, monkeypatch):
    # one 20,100-byte line: the preview holds all of what was read, so only
    # the size limit says it's cut
    a = _case(tmp_path, "case-a")
    _point(home, a)
    monkeypatch.setenv("SIFT_MAX_OUTPUT", "20000")
    r = _run(tmp_path, "import sys; sys.stdout.write('x' * 20100)\n")
    assert r["metadata"]["exit_code"] == 0
    assert r["data"]["truncated"] is True
    assert _summary(a)["truncated"] is True


def test_output_cut_on_the_small_output_path_is_marked_in_the_audit(
    tmp_path, home, monkeypatch
):
    a = _case(tmp_path, "case-a")
    _point(home, a)
    monkeypatch.setenv("SIFT_MAX_OUTPUT", "5000")
    r = _run(tmp_path, "import sys; sys.stdout.write('line\\n' * 20000)\n")
    assert r["data"]["truncated"] is True
    assert _summary(a)["truncated"] is True


def test_output_that_was_not_cut_is_not_marked(tmp_path, home):
    # 15 KB, under the limit: only the response preview is shorter
    a = _case(tmp_path, "case-a")
    _point(home, a)
    _run(tmp_path, "import sys; sys.stdout.write('line\\n' * 3000)\n")
    assert "truncated" not in _summary(a)


def test_a_command_without_a_switch_is_audited_in_its_case(tmp_path, home):
    a = _case(tmp_path, "case-a")
    _point(home, a)
    r = _run(tmp_path, "print('done')\n")
    assert [(e["audit_id"], e["case_id"]) for e in _entries(a)] == [
        (r["audit_id"], "case-a")
    ]
    assert os.path.isdir(a / "audit")


def test_saved_output_and_its_audit_stay_in_the_same_case(tmp_path, home, monkeypatch):
    a, b = _case(tmp_path, "case-a"), _case(tmp_path, "case-b")
    _point(home, b)
    monkeypatch.setenv("VHIR_CASE_DIR", str(a))
    r = _run(tmp_path, "import sys; sys.stdout.write('line\\n' * 3000)\n")
    saved = Path(r["full_output_path"])
    assert (
        saved.parents[2] == a and saved.parent.name == r["audit_id"]
    )  # its op's folder
    assert len(_entries(a)) == 1 and _entries(b) == []
