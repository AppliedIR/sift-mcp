"""Codex's start-up check is Claude Code's: started outside a case folder it
warns and names the command to start Codex with (`codex -p valhuntir`); at a
case root it says nothing; it never stops the session. The folder is the
payload's cwd when the hook is given one."""

import json
import subprocess
from pathlib import Path

HOOK = (
    Path(__file__).parent.parent.parent
    / "claude-code"
    / "full"
    / "hooks"
    / "case-dir-check.sh"
)


def _run(tmp_path, cwd, *args):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True, exist_ok=True)
    case = tmp_path / "cases" / "INC-1"
    case.mkdir(parents=True, exist_ok=True)
    (case / "CASE.yaml").write_text("case_id: INC-1\n")
    (home / ".vhir" / "active_case").write_text(str(case))
    return subprocess.run(
        ["bash", str(HOOK), *args], input=json.dumps({"cwd": str(cwd)}),
        cwd=tmp_path, env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True,
    )  # fmt: skip


def test_codex_started_outside_a_case_is_warned_with_its_own_command(tmp_path):
    r = _run(tmp_path, tmp_path / "projects", "--client", "codex")
    assert r.returncode == 0 and "WARNING: Not in a case directory" in r.stdout
    assert "codex -p valhuntir" in r.stdout and "\n  claude\n" not in r.stdout


def test_codex_at_a_case_root_hears_nothing(tmp_path):
    r = _run(tmp_path, tmp_path / "cases" / "INC-1", "--client", "codex")
    assert r.returncode == 0 and r.stdout == ""


def test_claude_code_still_gets_its_own_command(tmp_path):
    r = _run(tmp_path, tmp_path / "projects")
    assert "  claude\n" in r.stdout and "codex" not in r.stdout
