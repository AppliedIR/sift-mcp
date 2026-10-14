"""A skill load is a lookup, not an evidence action: Claude Code's PostToolUse
hook with matcher "Skill" (measured to fire on 2.1.296, tool_input {"skill"})
runs forensic-audit.sh, which appends one line to ~/.vhir/logs/lookups.jsonl,
with or without an active case, and writes nothing to the case's audit. The
line has exactly the keys every lookups-log writer uses: ts (UTC,
Z), source, lookup, case (the active case's name, or null) and args (each
string cut to 120). A Bash call is audited as before. The hook runs under
/bin/sh, as Claude Code runs it. Values are synthetic."""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent
HOOK = ROOT / "claude-code" / "shared" / "hooks" / "forensic-audit.sh"
KEYS = {"ts", "source", "lookup", "case", "args"}


def _case(home):
    case = home / "cases" / "INC-7"
    (case / "audit").mkdir(parents=True)
    (home / ".vhir").mkdir(exist_ok=True)
    (home / ".vhir" / "active_case").write_text(str(case))
    return case


def _hook(home, payload):
    env = {k: v for k, v in os.environ.items() if not k.startswith("VHIR_")}
    env.update(HOME=str(home), VHIR_EXAMINER="tester")
    return subprocess.run(
        ["/bin/sh", str(HOOK)], input=json.dumps(payload), capture_output=True,
        text=True, env=env, cwd=home, timeout=30,
    )  # fmt: skip


def _skill(name, home):
    # the shape measured from Claude Code 2.1.296
    return {"hook_event_name": "PostToolUse", "session_id": "s1", "tool_use_id": "t1",
            "cwd": str(home), "tool_name": "Skill", "tool_input": {"skill": name},
            "tool_response": {"commandName": name, "success": True}}  # fmt: skip


def _lookups(home):
    p = home / ".vhir" / "logs" / "lookups.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def test_a_skill_load_is_one_lookup_line_and_no_audit_entry(tmp_path):
    case = _case(tmp_path)
    r = _hook(tmp_path, _skill("vhir-playbooks", tmp_path))
    assert (r.returncode, r.stderr) == (0, "")
    (line,) = _lookups(tmp_path)
    assert set(line) == KEYS
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", line["ts"]), line
    assert (line["source"], line["lookup"], line["case"]) == (
        "claude-code",
        "Skill",
        "INC-7",
    )
    assert line["args"] == {"skill": "vhir-playbooks"}
    assert list((case / "audit").iterdir()) == []


def test_with_no_active_case_the_line_says_none(tmp_path):
    r = _hook(tmp_path, _skill("vhir-welcome", tmp_path))
    assert r.returncode == 0
    (line,) = _lookups(tmp_path)
    assert line["case"] is None and line["args"] == {"skill": "vhir-welcome"}


def test_each_load_appends_and_a_long_name_is_cut_to_120(tmp_path):
    _case(tmp_path)
    _hook(tmp_path, _skill("finding-skeptic", tmp_path))
    _hook(tmp_path, _skill("x" * 500 + "\n" + "y", tmp_path))
    first, second = _lookups(tmp_path)
    assert first["args"] == {"skill": "finding-skeptic"}
    assert second["args"] == {"skill": "x" * 120}
    mode = (tmp_path / ".vhir" / "logs" / "lookups.jsonl").stat().st_mode & 0o777
    assert mode == 0o600


def test_a_bash_call_is_still_audited_and_logs_no_lookup(tmp_path):
    case = _case(tmp_path)
    p = {"hook_event_name": "PostToolUse", "session_id": "s1", "tool_use_id": "t1",
         "cwd": str(case), "tool_name": "Bash", "tool_input": {"command": "echo hi"},
         "tool_response": {"stdout": "hi"}}  # fmt: skip
    assert _hook(tmp_path, p).returncode == 0
    (entry,) = [
        json.loads(x)
        for x in (case / "audit" / "claude-code.jsonl").read_text().splitlines()
    ]
    assert entry["command"] == "echo hi"
    assert _lookups(tmp_path) == []


@pytest.mark.parametrize("bad", ["", "not json", "[]", '{"tool_name": "Skill"}'])
def test_a_malformed_call_never_blocks(tmp_path, bad):
    _case(tmp_path)
    r = subprocess.run(
        ["/bin/sh", str(HOOK)], input=bad, capture_output=True, text=True,
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}, cwd=tmp_path, timeout=30,
    )  # fmt: skip
    assert r.returncode == 0


def test_an_unwritable_log_never_blocks_a_skill(tmp_path):
    _case(tmp_path)
    (tmp_path / ".vhir" / "logs").write_text("a file, not a folder\n")
    r = _hook(tmp_path, _skill("vhir-playbooks", tmp_path))
    assert r.returncode == 0


def test_the_full_settings_run_the_hook_for_skill_loads():
    settings = json.loads((ROOT / "claude-code" / "full" / "settings.json").read_text())
    skill = [e for e in settings["hooks"]["PostToolUse"] if e["matcher"] == "Skill"]
    assert [h["command"] for e in skill for h in e["hooks"]] == [
        "$CLAUDE_PROJECT_DIR/.claude/hooks/forensic-audit.sh"
    ]
