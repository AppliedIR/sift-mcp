"""Codex's apply_patch is checked by the case-data guard as Claude Code's Edit
deny checks an edit: a patch that adds, updates, deletes or moves onto a case
record, an audit log or an evidence file is refused (exit 2, a "refused" line
in the case's audit), by the paths its headers name. The patch's lines are
never read as shell, so a context line like ` rm audit/x` refuses nothing."""

import json
import subprocess

import pytest

from .test_case_data_guard import HOOK, box  # noqa: F401


def patch(box, cwd, body):  # noqa: F811
    root, cases, case, out = box
    payload = {"session_id": "s", "cwd": str(cwd), "hook_event_name": "PreToolUse",
               "tool_name": "apply_patch", "tool_input": {"command": body}, "tool_use_id": "t"}  # fmt: skip
    return subprocess.run(
        ["bash", str(HOOK)], input=json.dumps(payload), capture_output=True, text=True, cwd=cwd,
        env={"HOME": str(root), "PATH": "/usr/bin:/bin", "VHIR_CASES_DIR": str(cases), "VHIR_CASE_DIR": str(case)}, timeout=30,
    )  # fmt: skip


def body(*sections):
    return "*** Begin Patch\n" + "".join(sections) + "*** End Patch\n"


def update(path, old="x", new="y"):
    return f"*** Update File: {path}\n@@\n-{old}\n+{new}\n"


BLOCKED = {
    "update a record": lambda C, O: body(update(f"{C}/findings.json")),
    "update an audit log": lambda C, O: body(update(f"{C}/audit/forensic-mcp.jsonl")),
    "update pending-reviews": lambda C, O: body(update(f"{C}/pending-reviews.json")),
    "add a host record": lambda C, O: body(
        f"*** Add File: {C}/host-observations.jsonl\n+{{}}\n"
    ),
    "delete a record": lambda C, O: body(f"*** Delete File: {C}/timeline.json\n"),
    "move onto a record": lambda C, O: body(
        update(f"{C}/notes.txt") + f"*** Move to: {C}/findings.json\n"
    ),
    "update an evidence file": lambda C, O: body(update(f"{C}/evidence/disk.E01")),
    "a relative path from the case": lambda C, O: body(update("findings.json")),
}


@pytest.mark.parametrize("label", sorted(BLOCKED))
def test_a_patch_onto_case_data_is_refused_and_recorded(box, label):  # noqa: F811
    root, cases, case, out = box
    r = patch(box, case, BLOCKED[label](case, out))
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "BLOCKED: apply_patch" in r.stderr
    lines = [
        json.loads(x)
        for x in (case / "audit" / "claude-code.jsonl").read_text().splitlines()
    ]
    assert lines[-1]["event"] == "refused" and lines[-1]["reason"].startswith(
        "apply_patch"
    )


ALLOWED = {
    "update a report": lambda C, O: body(update(f"{C}/reports/draft.md")),
    "add a new file to evidence": lambda C, O: body(
        f"*** Add File: {C}/evidence/new-notes.txt\n+n\n"
    ),
    "update a file outside the cases": lambda C, O: body(update(f"{O}/x")),
    "context lines that read like shell": lambda C, O: body(
        f"*** Update File: {C}/notes.txt\n@@\n rm audit/forensic-mcp.jsonl\n"
        " echo x > findings.json\n-x\n+y\n"
    ),
}


@pytest.mark.parametrize("label", sorted(ALLOWED))
def test_a_patch_to_ordinary_files_passes(box, label):  # noqa: F811
    root, cases, case, out = box
    r = patch(box, case, ALLOWED[label](case, out))
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert not (case / "audit" / "claude-code.jsonl").exists()
