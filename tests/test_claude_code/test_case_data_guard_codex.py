"""Codex runs the same case-data guard as Claude Code, on the same payload
shape: a command that would delete or overwrite a case record is refused,
relative or absolute, with cd followed; any other write, relative ones at
the case root included, runs. The cases tree is the guard tests' box; values
are synthetic."""

import json
import subprocess

import pytest

from .test_case_data_guard import HOOK, box  # noqa: F401 (a fixture)


def _codex(box, cmd):  # noqa: F811
    root, cases, case, out = box
    payload = {"session_id": "s", "cwd": str(case), "hook_event_name": "PreToolUse",
               "tool_name": "Bash", "tool_input": {"command": cmd}, "tool_use_id": "t",
               "turn_id": "u", "model": "gpt-5.5"}  # fmt: skip
    return subprocess.run(
        ["bash", str(HOOK)], input=json.dumps(payload), capture_output=True, text=True,
        cwd=case, env={"HOME": str(root), "PATH": "/usr/bin:/bin", "VHIR_CASES_DIR": str(cases)},
        timeout=30,
    )  # fmt: skip


@pytest.mark.parametrize(
    "cmd",
    [
        "mv findings.json x",
        "rm *.json",
        "find . -name findings.json -delete",
        "cp /etc/hostname timeline.json",
    ],  # fmt: skip
)
def test_a_case_record_is_refused(box, cmd):  # noqa: F811
    r = _codex(box, cmd)
    assert r.returncode == 2 and "BLOCKED" in r.stderr
    assert (box[2] / "findings.json").read_text() == "x\n"


def test_ordinary_writes_at_the_case_root_run(box):  # noqa: F811
    assert _codex(box, "echo x > notes.txt").returncode == 0
    assert _codex(box, "rm notes.txt").returncode == 0


def test_cd_is_followed(box):  # noqa: F811
    root, cases, case, out = box
    assert _codex(box, f"cd {out} && rm x").returncode == 0
    assert _codex(box, f"cd {out} && cd {case} && rm findings.json").returncode == 2
