"""The SessionStart case-directory warning points at the real cases root.

It named ~/.vhir/cases, which isn't where cases live (VHIR_CASES_DIR, else
~/cases), and it claimed the sandbox restricts commands to the current
directory tree, which it doesn't.
"""

import subprocess
from pathlib import Path

import pytest

HOOK = (
    Path(__file__).parent.parent.parent
    / "claude-code"
    / "full"
    / "hooks"
    / "case-dir-check.sh"
)


def _run(tmp_path, env_extra=None, active_case=None):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True, exist_ok=True)
    if active_case:
        (home / ".vhir" / "active_case").write_text(str(active_case))
    cwd = tmp_path / "elsewhere"
    cwd.mkdir(exist_ok=True)
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin", **(env_extra or {})}
    return subprocess.run(
        ["bash", str(HOOK)],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


@pytest.mark.parametrize("cases_env", [None, "custom"])
def test_no_active_case_points_at_the_cases_root(tmp_path, cases_env):
    env = {"VHIR_CASES_DIR": str(tmp_path / "custom-cases")} if cases_env else {}
    out = _run(tmp_path, env)
    root = (
        str(tmp_path / "custom-cases")
        if cases_env
        else str(tmp_path / "home" / "cases")
    )
    assert out.count(f"cd {root}/<case-id>") == 2
    assert "~/.vhir/cases" not in out and ".vhir/cases" not in out


@pytest.mark.parametrize("active", [False, True])
def test_no_claim_that_the_sandbox_restricts_commands(tmp_path, active):
    case = tmp_path / "cases" / "INC-1"
    case.mkdir(parents=True)
    out = _run(tmp_path, active_case=case if active else None)
    assert "WARNING: Not in a case directory" in out
    assert "sandbox restricts" not in out
    if active:
        assert f"cd {case}" in out


def test_anchor_silent_inside_a_case_dir(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: x\n")
    out = subprocess.run(
        ["bash", str(HOOK)],
        cwd=case,
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert out == ""
