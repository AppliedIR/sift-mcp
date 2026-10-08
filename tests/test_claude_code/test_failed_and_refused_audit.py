"""Calls that don't run are audited too: a command that failed is recorded
"failed" with its error, a call the permission mode refused "denied" with the
reason (both through the audit hook, registered for those events), and the
case-data guard records its own refusal, with no audit id because nothing
ran. Payloads have the shape Claude Code sends. Values are synthetic."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
HOOKS = ROOT / "claude-code" / "shared" / "hooks"


def _case(tmp_path):
    case = tmp_path / "cases" / "INC-1"
    (case / "audit").mkdir(parents=True)
    (case / "findings.json").write_text("[]\n")
    (tmp_path / ".vhir").mkdir()
    (tmp_path / ".vhir" / "active_case").write_text(str(case))
    return case


def _env(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("VHIR_")}
    env.update(
        HOME=str(tmp_path),
        VHIR_EXAMINER="tester",
        VHIR_CASES_DIR=str(tmp_path / "cases"),
    )
    return env


def _hook(name, payload, tmp_path, cwd):
    return subprocess.run(
        ["bash", str(HOOKS / name)], input=json.dumps(payload), capture_output=True,
        text=True, env=_env(tmp_path), cwd=cwd, timeout=30,
    )  # fmt: skip


def _lines(case):
    return [
        json.loads(x)
        for x in (case / "audit" / "claude-code.jsonl").read_text().splitlines()
    ]


def _payload(event, command, case, **kw):
    return {"hook_event_name": event, "session_id": "s1", "tool_use_id": "t1", "cwd": str(case),
            "tool_name": "Bash", "tool_input": {"command": command}, **kw}  # fmt: skip


def test_a_failed_command_is_recorded_failed_with_its_error(tmp_path):
    case = _case(tmp_path)
    p = _payload(
        "PostToolUseFailure", "false", case, error="Exit code 1", is_interrupt=False
    )
    assert _hook("forensic-audit.sh", p, tmp_path, case).returncode == 0
    (entry,) = _lines(case)
    assert entry["event"] == "failed" and entry["error"] == "Exit code 1"
    assert entry["command"] == "false" and entry["audit_id"].startswith("hook-tester-")


def test_a_denied_call_is_recorded_denied_with_the_reason(tmp_path):
    case = _case(tmp_path)
    why = "Auto mode could not evaluate this action and is blocking it for safety"
    p = _payload("PermissionDenied", "for d in a b; do echo $d; done", case, reason=why)
    assert _hook("forensic-audit.sh", p, tmp_path, case).returncode == 0
    (entry,) = _lines(case)
    assert entry["event"] == "denied" and entry["denial_reason"] == why


def test_a_command_that_ran_carries_no_event(tmp_path):
    case = _case(tmp_path)
    p = _payload("PostToolUse", "echo hi", case, tool_response={"stdout": "hi"})
    _hook("forensic-audit.sh", p, tmp_path, case)
    (entry,) = _lines(case)
    assert (
        "event" not in entry and "error" not in entry and "denial_reason" not in entry
    )


def test_the_guard_records_its_refusal_and_the_record_stays(tmp_path):
    case = _case(tmp_path)
    r = _hook(
        "case-data-guard.sh",
        _payload("PreToolUse", "rm findings.json", case),
        tmp_path,
        case,
    )
    assert r.returncode == 2 and "BLOCKED" in r.stderr
    (entry,) = _lines(case)
    assert entry["event"] == "refused" and entry["command"] == "rm findings.json"
    assert entry["reason"] == "rm on findings.json" and "audit_id" not in entry
    assert (case / "findings.json").read_text() == "[]\n"
    # an audit id the hook mints later doesn't count the refusal
    _hook(
        "forensic-audit.sh",
        _payload("PostToolUse", "ls", case, tool_response="x"),
        tmp_path,
        case,
    )
    assert _lines(case)[-1]["audit_id"].endswith("-001")


def test_an_allowed_command_writes_nothing_from_the_guard(tmp_path):
    case = _case(tmp_path)
    r = _hook("case-data-guard.sh", _payload("PreToolUse", "ls", case), tmp_path, case)
    assert r.returncode == 0 and not (case / "audit" / "claude-code.jsonl").exists()


def test_the_template_registers_the_audit_hook_for_both_events():
    hooks = json.loads((ROOT / "claude-code" / "full" / "settings.json").read_text())[
        "hooks"
    ]
    for event in ("PostToolUseFailure", "PermissionDenied"):
        cmds = [
            h["command"]
            for e in hooks[event]
            if e["matcher"] == "Bash"
            for h in e["hooks"]
        ]
        assert any(c.endswith("/forensic-audit.sh") for c in cmds), event
