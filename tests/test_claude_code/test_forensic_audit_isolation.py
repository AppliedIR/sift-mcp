"""The audit hook's Python never imports from the session's directory.

`python3 -c` puts the current directory first on sys.path, and the
PostToolUse hook runs in the session's cwd on every Bash call. A `json.py`
there (in a case directory holding extracted evidence, say) ran as the user,
outside the sandbox; a harmless one made the hook silently write no audit
entry. The hook runs its Python isolated (-I).
"""

import json
import subprocess

from test_claude_code.test_forensic_audit import (
    HOOK_SCRIPT,
    _hook_input,
    _make_active_case,
    _make_env,
)


def _run_in(cwd, env):
    return subprocess.run(
        ["sh", str(HOOK_SCRIPT)],
        input=_hook_input(command="ls -la"),
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        timeout=10,
    )


def _entries(case_dir):
    f = case_dir / "audit" / "claude-code.jsonl"
    return [json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []


def test_a_json_py_in_the_cwd_never_runs(tmp_path):
    case_dir = _make_active_case(tmp_path)
    canary = tmp_path / "CANARY"
    (case_dir / "json.py").write_text(
        f"open({str(canary)!r}, 'w').close()\nfrom json import *\n"
    )
    p = _run_in(case_dir, _make_env(tmp_path))
    assert p.returncode == 0 and not canary.exists()
    assert [e["command"] for e in _entries(case_dir)] == ["ls -la"]


def test_a_harmless_foreign_json_py_does_not_stop_the_audit(tmp_path):
    case_dir = _make_active_case(tmp_path)
    (case_dir / "json.py").write_text(
        "# an extracted file that happens to be named json.py\n"
    )
    _run_in(case_dir, _make_env(tmp_path))
    assert [e["command"] for e in _entries(case_dir)] == ["ls -la"]


def test_every_python_call_in_the_hook_is_isolated():
    text = HOOK_SCRIPT.read_text()
    assert text.count("python3 ") == text.count("python3 -I ") > 0
