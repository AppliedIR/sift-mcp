"""Codex (`--client codex`) doesn't say which folder a command runs in: its
shell tool takes its own working directory. So, until the command itself cds
to an absolute path, the guard refuses a relative operand, glob, find root or
redirection target of the commands it checks, naming it; absolute paths are
judged as they always are. Claude Code's calls are unchanged. The cases tree
is the guard tests' box; values are synthetic."""

import json
import subprocess

import pytest

from .test_case_data_guard import HOOK, box  # noqa: F401 (a fixture)


def _run(box, cmd, codex=True):  # noqa: F811
    root, cases, case, out = box
    payload = {"session_id": "s", "cwd": str(case), "hook_event_name": "PreToolUse",
               "tool_name": "Bash", "tool_input": {"command": cmd}, "tool_use_id": "t"}  # fmt: skip
    return subprocess.run(
        ["bash", str(HOOK), *(["--client", "codex"] if codex else [])],
        input=json.dumps(payload), capture_output=True, text=True, cwd=case,
        env={"HOME": str(root), "PATH": "/usr/bin:/bin", "VHIR_CASES_DIR": str(cases)},
        timeout=30,
    )  # fmt: skip


@pytest.mark.parametrize(
    "cmd,named",
    [
        ("mv findings.json x", "findings.json"),
        ("rm *.json", "*.json"),
        ("find . -name findings.json -delete", "."),
        ("rm notes.txt", "notes.txt"),
        ("echo x > notes.txt", "notes.txt"),
        ("cp /etc/hostname timeline.json", "timeline.json"),
    ],
)
def test_a_relative_path_is_refused_for_codex(box, cmd, named):  # noqa: F811
    r = _run(box, cmd)
    assert r.returncode == 2
    assert f"{named} is a relative path, and Codex doesn't say which folder" in r.stderr
    assert (box[2] / "findings.json").read_text() == "x\n"


def test_an_absolute_path_is_judged_as_always(box):  # noqa: F811
    root, cases, case, out = box
    assert _run(box, f"rm {case}/findings.json").returncode == 2
    assert _run(box, f"rm {out}/x").returncode == 0


def test_an_absolute_cd_makes_the_folder_known(box):  # noqa: F811
    root, cases, case, out = box
    assert _run(box, f"cd {case} && rm notes.txt").returncode == 0
    r = _run(box, f"cd {case} && rm findings.json")
    assert r.returncode == 2 and "rm on findings.json" in r.stderr


def test_commands_the_guard_doesnt_check_still_run(box):  # noqa: F811
    assert _run(box, "ls -la && grep -r x .").returncode == 0


def test_claude_codes_calls_are_unchanged(box):  # noqa: F811
    assert _run(box, "rm notes.txt", codex=False).returncode == 0
    assert _run(box, "echo x > notes.txt", codex=False).returncode == 0
