"""Codex's calls are audited into the active case: the audit hook, run with
--client codex, marks each entry with the client and what ran (shell or
apply_patch), and as outside the case when the session runs elsewhere; with
no active case nothing is written. The text Codex types into a running shell
(write_stdin) reaches no hook: it's read from the session's transcript at
Stop and after each hooked call, each piece once. Transcript lines have the
shape Codex 0.158 writes; values are synthetic. In code mode (Codex 0.163) the
call is a script the exec tool runs: the whole script is recorded, marked
raw_input; the record taken from a real 0.163 session is kept as written."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
HOOKS = ROOT / "claude-code" / "shared" / "hooks"


def _case(tmp_path, active=True):
    case = tmp_path / "cases" / "INC-1"
    (case / "audit").mkdir(parents=True)
    (tmp_path / ".vhir").mkdir()
    if active:
        (tmp_path / ".vhir" / "active_case").write_text(str(case))
    return case


def _run(script, payload, tmp_path, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("VHIR_")}
    env.update(HOME=str(tmp_path), VHIR_EXAMINER="tester")
    return subprocess.run(
        ["bash", str(HOOKS / script), *args], input=json.dumps(payload),
        capture_output=True, text=True, env=env, timeout=30,
    )  # fmt: skip


def _lines(case):
    p = case / "audit" / "claude-code.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def _call(case, tool="Bash", command="ls", cwd=None, transcript=""):
    return {"hook_event_name": "PostToolUse", "session_id": "s1", "tool_use_id": "t1",
            "cwd": str(cwd or case), "tool_name": tool, "tool_input": {"command": command},
            "tool_response": "ok", "transcript_path": str(transcript)}  # fmt: skip


def _stdin_line(n, chars):
    args = json.dumps({"session_id": "SESSION", "chars": chars, "yield_time_ms": 800})
    return json.dumps({"timestamp": "2026-10-07T07:56:09.075Z", "ordinal": n,
                       "type": "response_item",
                       "payload": {"type": "function_call", "id": f"fc_{n}",
                                   "name": "write_stdin", "arguments": args,
                                   "call_id": f"call_{n}"}})  # fmt: skip


def _transcript(tmp_path, *chars):
    t = tmp_path / "rollout.jsonl"
    other = json.dumps({"type": "response_item", "payload": {"type": "message"}})
    t.write_text(
        "\n".join([other] + [_stdin_line(i, c) for i, c in enumerate(chars)]) + "\n"
    )
    return t


def test_a_codex_shell_call_is_marked_with_its_client(tmp_path):
    case = _case(tmp_path)
    _run("forensic-audit.sh", _call(case), tmp_path, "--client", "codex")
    (e,) = _lines(case)
    assert e["client"] == "codex" and e["event"] == "shell" and "outside_case" not in e


def test_an_apply_patch_is_marked_as_one(tmp_path):
    case = _case(tmp_path)
    patch = "*** Begin Patch\n*** Add File: notes.md\n+x\n*** End Patch"
    _run(
        "forensic-audit.sh",
        _call(case, "apply_patch", patch),
        tmp_path,
        "--client",
        "codex",
    )
    (e,) = _lines(case)
    assert e["event"] == "apply_patch" and e["command"] == patch


def test_a_session_outside_the_case_still_writes_there_marked(tmp_path):
    case = _case(tmp_path)
    elsewhere = tmp_path / "projects" / "notes"
    _run("forensic-audit.sh", _call(case, cwd=elsewhere), tmp_path, "--client", "codex")
    (e,) = _lines(case)
    assert e["outside_case"] is True and e["cwd"] == str(elsewhere)


def test_no_active_case_writes_nothing(tmp_path):
    case = _case(tmp_path, active=False)
    t = _transcript(tmp_path, "echo hi\n")
    _run("forensic-audit.sh", _call(case, transcript=t), tmp_path, "--client", "codex")
    _run("codex-stdin-capture.sh", _call(case, transcript=t), tmp_path)
    assert _lines(case) == []


def test_write_stdin_text_is_captured_once_each(tmp_path):
    case = _case(tmp_path)
    t = _transcript(tmp_path, "echo via-stdin > ./made.txt\n", "exit\n")
    stop = {"hook_event_name": "Stop", "session_id": "s1", "cwd": str(case),
            "transcript_path": str(t)}  # fmt: skip
    _run("codex-stdin-capture.sh", stop, tmp_path)
    _run("codex-stdin-capture.sh", stop, tmp_path)  # nothing new
    got = [e for e in _lines(case) if e["event"] == "write_stdin"]
    assert [e["command"] for e in got] == ["echo via-stdin > ./made.txt\n", "exit\n"]
    assert [e["transcript_line"] for e in got] == [2, 3] and got[0]["client"] == "codex"
    assert got[0]["audit_id"].endswith("-001") and got[1]["audit_id"].endswith("-002")
    with t.open("a") as f:  # the session goes on
        f.write(_stdin_line(9, "touch late\n") + "\n")
    _run("codex-stdin-capture.sh", stop, tmp_path)
    assert [e["command"] for e in _lines(case)][-1] == "touch late\n"
    assert len(_lines(case)) == 3


def test_a_hooked_call_captures_too_so_a_killed_session_loses_nothing(tmp_path):
    case = _case(tmp_path)
    t = _transcript(tmp_path, "rm -rf x\n")
    _run("forensic-audit.sh", _call(case, transcript=t), tmp_path, "--client", "codex")
    events = [e["event"] for e in _lines(case)]
    assert events == ["shell", "write_stdin"]


def test_claude_codes_entries_carry_no_client(tmp_path):
    case = _case(tmp_path)
    _run("forensic-audit.sh", _call(case), tmp_path)
    (e,) = _lines(case)
    assert "client" not in e and "event" not in e


def test_typed_input_from_a_session_outside_the_case_is_marked(tmp_path):
    case = _case(tmp_path)
    t = _transcript(tmp_path, "rm x\n")
    stop = {"hook_event_name": "Stop", "session_id": "s1",
            "cwd": str(tmp_path / "projects" / "notes"), "transcript_path": str(t)}  # fmt: skip
    _run("codex-stdin-capture.sh", stop, tmp_path)
    (e,) = _lines(case)
    assert e["event"] == "write_stdin" and e["outside_case"] is True


def test_input_recorded_in_one_case_isnt_recorded_again_after_a_switch(tmp_path):
    a = _case(tmp_path)
    b = tmp_path / "cases" / "INC-2"
    (b / "audit").mkdir(parents=True)
    t = _transcript(tmp_path, "rm a.txt\n")
    stop = {"hook_event_name": "Stop", "session_id": "s1", "cwd": str(a),
            "transcript_path": str(t)}  # fmt: skip
    _run("codex-stdin-capture.sh", stop, tmp_path)
    (tmp_path / ".vhir" / "active_case").write_text(str(b))  # the examiner switches
    with t.open("a") as f:
        f.write(_stdin_line(9, "rm b.txt\n") + "\n")
    _run("codex-stdin-capture.sh", dict(stop, cwd=str(b)), tmp_path)
    assert [e["command"] for e in _lines(a)] == ["rm a.txt\n"]
    assert [e["command"] for e in _lines(b)] == ["rm b.txt\n"]


def test_long_typed_input_is_marked_cut_with_its_length_and_hash(tmp_path):
    import hashlib

    case = _case(tmp_path)
    typed = " " * 2000 + "rm findings.json\n"
    t = _transcript(tmp_path, typed)
    stop = {"hook_event_name": "Stop", "session_id": "s1", "cwd": str(case),
            "transcript_path": str(t)}  # fmt: skip
    _run("codex-stdin-capture.sh", stop, tmp_path)
    (e,) = _lines(case)
    assert e["command"] == typed[:2000] and e["command_truncated"] is True
    assert e["command_length"] == len(typed)
    assert e["command_sha256"] == hashlib.sha256(typed.encode()).hexdigest()


def test_short_typed_input_carries_no_cut_marker(tmp_path):
    case = _case(tmp_path)
    t = _transcript(tmp_path, "x" * 2000)
    stop = {"hook_event_name": "Stop", "session_id": "s1", "cwd": str(case),
            "transcript_path": str(t)}  # fmt: skip
    _run("codex-stdin-capture.sh", stop, tmp_path)
    (e,) = _lines(case)
    assert e["command"] == "x" * 2000 and "command_truncated" not in e


def test_input_recorded_before_the_cursor_was_kept_isnt_recorded_again(tmp_path):
    """A case holds a session's input from before the per-session cursor (or
    from a run whose cursor write failed): the next run with nothing new keeps
    the cursor, so a switch after it records nothing again."""
    a = _case(tmp_path)
    b = tmp_path / "cases" / "INC-2"
    (b / "audit").mkdir(parents=True)
    t = _transcript(tmp_path, "rm a.txt\n")
    stop = {"hook_event_name": "Stop", "session_id": "s1", "cwd": str(a),
            "transcript_path": str(t)}  # fmt: skip
    _run("codex-stdin-capture.sh", stop, tmp_path)
    for f in (tmp_path / ".vhir" / "codex-stdin").iterdir():
        f.unlink()  # no cursor: as an older version left it
    _run("codex-stdin-capture.sh", stop, tmp_path)  # nothing new in A
    (tmp_path / ".vhir" / "active_case").write_text(str(b))
    _run("codex-stdin-capture.sh", dict(stop, cwd=str(b)), tmp_path)
    assert _lines(b) == [] and len(_lines(a)) == 1


# A real Codex 0.163 code-mode record (line 19 of its session's transcript)
CODE_MODE = json.loads(
    '{"timestamp":"2026-10-16T14:00:46.498Z","ordinal":18,"type":"response_item","payload":{"type":"custom_tool_call","id":"ctc_0d852770ea7e2846016ad22e0de3f48191b6b64562660f4bf6","status":"completed","call_id":"call_a6c33c03aaf4413fb09543738e8aed21","name":"exec","input":"text(await tools.write_stdin({session_id:18929,chars:\\"echo cx07-marker-stdin\\\\n\\",yield_time_ms:1000,max_output_tokens:1000}));\\n","internal_chat_message_metadata_passthrough":{"turn_id":"01a14503-c8b2-7601-9183-3444bef27700","create_time":1792159245.898374}}}'
)


def _code_mode_line(n, script, kind="custom_tool_call"):
    payload = {**CODE_MODE["payload"], "type": kind, "call_id": f"call_{n}",
               "input": script}  # fmt: skip
    return json.dumps({**CODE_MODE, "ordinal": n, "payload": payload})


def _stop(case, *lines):
    t = case.parent.parent / "rollout.jsonl"
    other = json.dumps({"type": "response_item", "payload": {"type": "message"}})
    t.write_text("\n".join([other] * 18 + list(lines)) + "\n")
    return {"hook_event_name": "Stop", "session_id": "s1", "cwd": str(case),
            "transcript_path": str(t)}  # fmt: skip


def test_code_mode_typed_input_is_recorded_once_as_the_script(tmp_path):
    case = _case(tmp_path)
    stop = _stop(case, json.dumps(CODE_MODE))
    _run("codex-stdin-capture.sh", stop, tmp_path)
    _run("codex-stdin-capture.sh", stop, tmp_path)  # nothing new
    (e,) = _lines(case)
    assert e["event"] == "write_stdin" and e["client"] == "codex"
    assert "cx07-marker-stdin" in e["command"]
    assert e["command"] == CODE_MODE["payload"]["input"] and e["raw_input"] is True
    assert e["tool_use_id"] == CODE_MODE["payload"]["call_id"]
    assert e["transcript_line"] == 19 and "command_truncated" not in e


def test_a_code_mode_script_without_write_stdin_records_nothing(tmp_path):
    case = _case(tmp_path)
    script = 'text(await tools.exec_command({cmd:"ls -la",yield_time_ms:1000}));\n'
    _run("codex-stdin-capture.sh", _stop(case, _code_mode_line(1, script)), tmp_path)
    assert _lines(case) == []


def test_write_stdin_named_outside_a_call_records_nothing(tmp_path):
    """Its output, or text that names it, is not a call."""
    case = _case(tmp_path)
    said = json.dumps({"type": "response_item", "payload": {
        "type": "message", "content": "I will use tools.write_stdin next"}})  # fmt: skip
    out = _code_mode_line(
        2, "text(await tools.write_stdin({}))", "custom_tool_call_output"
    )
    _run("codex-stdin-capture.sh", _stop(case, said, out), tmp_path)
    assert _lines(case) == []


def test_a_long_code_mode_script_is_marked_cut_with_its_length_and_hash(tmp_path):
    import hashlib

    case = _case(tmp_path)
    script = (
        "// " + "x" * 2000 + '\ntext(await tools.write_stdin({chars:"rm f\\n"}));\n'
    )
    _run("codex-stdin-capture.sh", _stop(case, _code_mode_line(1, script)), tmp_path)
    (e,) = _lines(case)
    assert e["command"] == script[:2000] and e["command_truncated"] is True
    assert e["command_length"] == len(script) and e["raw_input"] is True
    assert e["command_sha256"] == hashlib.sha256(script.encode()).hexdigest()


def test_both_shapes_in_one_session_are_each_recorded_once(tmp_path):
    case = _case(tmp_path)
    stop = _stop(case, _stdin_line(1, "exit\n"), json.dumps(CODE_MODE))
    _run("codex-stdin-capture.sh", stop, tmp_path)
    _run("codex-stdin-capture.sh", stop, tmp_path)
    old, new = _lines(case)
    assert old["command"] == "exit\n" and "raw_input" not in old
    assert old["tool_use_id"] == "call_1" and old["transcript_line"] == 19
    assert new["raw_input"] is True and new["transcript_line"] == 20
