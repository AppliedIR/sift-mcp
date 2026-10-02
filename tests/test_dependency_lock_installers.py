"""Both installers install from the dependency lock, except OpenCTI's client.

Every `uv pip install` of first-party or third-party packages takes the lock
as constraint and build constraint (-c, -b). OpenCTI installs last and
unlocked: pycti pins versions the lock can't hold. uv older than 0.6.0
ignores the lock's hashes, so the installers refuse it. The venv is checked
against the lock after the locked installs (--strict) and again after
OpenCTI's (--final). These run the installers' own text with uv, the venv's
python and every other external command stubbed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SETUP = ROOT / "setup-sift.sh"
LITE = ROOT / "quickstart-lite.sh"


def _slice(text: str, start: str, end: str) -> str:
    i = text.index(start)
    return text[i : text.index(end, i)]


def _run(script: str, tmp_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=60, cwd=tmp_path
    )


STUBS = "\n".join(
    [
        "set -euo pipefail",
        "RED= GREEN= YELLOW= BLUE= BOLD= NC=",
        'info(){ echo "[INFO] $*"; }; ok(){ echo "[OK] $*"; }',
        'warn(){ echo "[WARN] $*"; }; err(){ echo "[ERROR] $*"; }',
        'fail(){ echo "[FAIL] $*"; exit 1; }; header(){ :; }',
        "git(){ return 0; }; docker(){ return 0; }; groups(){ echo x; }; sudo(){ return 0; }",
    ]
)


def _calls(log: Path) -> list[str]:
    return [
        line for line in log.read_text().splitlines() if line.startswith("pip install")
    ]


def _steps(log: Path) -> list[str]:
    """The log as steps: "locked" (-c and -b), "opencti" (its own install,
    neither), "check --strict"/"check --final"; anything else verbatim."""
    out = []
    for line in log.read_text().splitlines():
        if line.startswith("check "):
            out.append("check " + line.split()[2])
        elif line.startswith("pip install"):
            locked = " -c " in line and " -b " in line
            if "packages/opencti" in line:
                out.append(line if " -c " in line or " -b " in line else "opencti")
            else:
                out.append("locked" if locked else line)
    return out


def _held_go_to_the_first_locked_install(log: Path) -> None:
    lines = log.read_text().splitlines()
    first = next(i for i, x in enumerate(lines) if x.startswith("pip install"))
    asked = next(i for i, x in enumerate(lines) if "--installed" in x)
    assert asked < first, lines
    assert " -c " in lines[first] and " setuptools packaging " in lines[first], lines
    assert not any("packaging" in x for x in lines[first + 1 :] if "pip install" in x)


def _python(tmp_path: Path, log: Path) -> Path:
    """The venv's python: records the check-lock.py runs; --installed names
    two packages, as seeds would."""
    py = tmp_path / "venv-python"
    py.write_text(
        f'#!/bin/sh\necho "check $*" >> "{log}"\n'
        '[ "$2" = --installed ] && echo "setuptools packaging"\nexit 0\n'
    )
    py.chmod(0o755)
    return py


@pytest.mark.parametrize(
    "selected,installed", [(True, False), (False, True), (True, True), (False, False)]
)
def test_setup_sift_installs_everything_but_opencti_from_the_lock(
    tmp_path, selected, installed
):
    install_dir = tmp_path / "sift-mcp"
    (install_dir / "deps").mkdir(parents=True)
    lock = install_dir / "deps" / "vhir.lock"
    lock.write_text("# lock\n")
    os_dir = tmp_path / "opensearch-mcp"
    (os_dir / "scripts").mkdir(parents=True)
    (os_dir / "scripts" / "setup-opensearch.sh").write_text("exit 0\n")
    log = tmp_path / "uv.log"
    text = SETUP.read_text()
    script = "\n".join(
        [
            STUBS,
            # `uv pip show opencti-mcp` answers whether it's already installed.
            f'uv(){{ echo "$*" >> "{log}"; [ "$2" != show ] || {str(installed).lower()}; }}',
            f'INSTALL_DIR="{install_dir}"; VHIR_DIR="{tmp_path}/vhir"',
            f'VENV_PYTHON="{_python(tmp_path, log)}"',
            f'HOME="{tmp_path}"; USER=x',
            f"INSTALL_TRIAGE=true; INSTALL_RAG=true; INSTALL_OPENCTI={str(selected).lower()}",
            "INSTALL_OPENSEARCH_FLAG=true",
            _slice(
                text,
                "# Every third-party package is installed",
                "# --- Virtual environment ---",
            ),
            _slice(
                text, "# Helper: install a single package", "# Phase 5: Smoke Tests"
            ),
            _slice(
                text,
                "# --- windows-triage database setup ---",
                "    # Check if databases already exist",
            ),
            "fi",
        ]
    )
    run = _run(script, tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr
    calls = _calls(log)
    locked = f"-c {lock} -b {lock}"
    _held_go_to_the_first_locked_install(log)
    opencti = [c for c in calls if "packages/opencti" in c]
    others = [c for c in calls if "packages/opencti" not in c]
    if not (selected or installed):
        assert not opencti and others and all(locked in c for c in others)
        assert _steps(log).count("check --final") == 1
        return
    # Chosen now, or there already: the locked steps above may have moved
    # what pycti pins, so it's installed again either way.
    assert len(opencti) == 1 and "-c " not in opencti[0] and "-b " not in opencti[0], (
        opencti
    )
    assert others and all(locked in c for c in others), others
    assert any("zstandard" in c for c in others) and any(
        "opensearch-mcp" in c for c in others
    )
    # Last: nothing locked installs after it to move what it moved.
    assert calls[-1] == opencti[0] or all(
        "zstandard" in c for c in calls[calls.index(opencti[0]) + 1 :]
    )
    assert calls.index(opencti[0]) > max(
        i for i, c in enumerate(calls) if "opensearch-mcp" in c
    )
    # Checked after the last locked install, and again after OpenCTI's.
    steps = _steps(log)
    tail = steps[steps.index("check --strict") - 1 :]
    assert tail[:4] == ["locked", "check --strict", "opencti", "check --final"], steps
    assert steps.count("check --strict") == 1 and steps.count("check --final") == 1
    assert all(x == "locked" for x in tail[4:]), steps  # zstandard, already present


@pytest.mark.parametrize("installer", ["setup-sift", "quickstart-lite"])
@pytest.mark.parametrize(
    "version,refused", [("0.5.0", True), ("0.6.0", False), ("0.12.20", False)]
)
def test_uv_older_than_0_6_is_refused(tmp_path, installer, version, refused):
    text = SETUP.read_text() if installer == "setup-sift" else LITE.read_text()
    floor = _slice(text, "# Older uv installs from the lock", "\n\n")
    script = "\n".join(
        [STUBS, f'uv(){{ echo "uv {version} (x)"; }}', floor, 'echo "PASSED"']
    )
    run = _run(script, tmp_path)
    if refused:
        assert run.returncode == 1 and "older than 0.6.0" in run.stdout, run.stdout
    else:
        assert run.returncode == 0 and "PASSED" in run.stdout, run.stdout


def _lite(tmp_path, *args, installed=False, final_rc=0, answers=None):
    """The whole quickstart-lite.sh, with uv a stand-in that records its calls
    and answers `pip show opencti-mcp`; the venv already exists and its python
    records check-lock.py runs (anything else goes to the system python)."""
    home = tmp_path / "home"
    venv_bin = home / ".vhir" / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    (home / "proj").mkdir()
    log = tmp_path / "uv.log"
    log.write_text("")
    py = venv_bin / "python"
    py.write_text(
        "#!/bin/sh\n"
        f'case "$1" in *check-lock.py) echo "check $*" >> "{log}"\n'
        '  [ "$2" = --installed ] && echo "setuptools packaging"\n'
        f'  [ "$2" = --final ] && exit {final_rc}; exit 0;; esac\n'
        'exec python3 "$@"\n'
    )
    py.chmod(0o755)
    stub = tmp_path / "stub"
    stub.mkdir()
    uv = stub / "uv"
    uv.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{log}"\n'
        'if [ "$1" = --version ]; then echo "uv 0.12.20 (x)"; exit 0; fi\n'
        'if [ "$1 $2" = "pip show" ]; then '
        + ("exit 0" if installed else "exit 1")
        + "; fi\nexit 0\n"
    )
    uv.chmod(0o755)
    run = subprocess.run(
        ["bash", str(LITE), *args],
        cwd=home / "proj",
        env={"HOME": str(home), "PATH": f"{stub}:/usr/bin:/bin", "LANG": "C.UTF-8"},
        input=answers or "",
        capture_output=True,
        text=True,
        timeout=120,
    )
    if run.returncode == 0:
        _held_go_to_the_first_locked_install(log)
    return run, _steps(log)


@pytest.mark.parametrize(
    "args,installed,expect_opencti",
    [
        (["--yes", "--venv-only", "--opencti"], False, True),
        (["--yes", "--venv-only"], True, True),  # there already, not chosen again
        (["--yes", "--venv-only"], False, False),
        (["--yes"], True, True),
        (["--yes", "--opencti"], False, True),
    ],
)
def test_lite_reinstalls_opencti_after_the_locked_packages_whenever_it_is_there(
    tmp_path, args, installed, expect_opencti
):
    run, steps = _lite(tmp_path, *args, installed=installed)
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]
    # sift-common, forensic-rag and windows-triage, each from the lock; no
    # other install of any kind.
    assert steps.count("locked") == 3, steps
    assert steps[0] == "check --installed", steps
    allowed = {
        "locked",
        "opencti",
        "check --installed",
        "check --strict",
        "check --final",
    }
    assert set(steps) <= allowed, steps
    # Checked after the strict check whether or not OpenCTI's step runs.
    assert steps.count("check --final") == 1, steps
    if not expect_opencti:
        assert "opencti" not in steps, steps
        assert steps.index("check --final") > steps.index("check --strict"), steps
        return
    assert steps.count("opencti") == 1, steps
    i = steps.index("opencti")
    # After every locked install and the strict check; checked again after it.
    assert "locked" not in steps[i:] and "check --strict" in steps[:i], steps
    assert steps[i + 1] == "check --final", steps


def test_lite_fails_on_conflicts_left_by_a_pycti_without_opencti_mcp(tmp_path):
    """pycti is there, opencti-mcp isn't: --strict leaves `uv pip check` to
    --final, so --final has to run though OpenCTI's step doesn't."""
    run, steps = _lite(tmp_path, "--yes", "--venv-only", installed=False, final_rc=1)
    assert run.returncode != 0
    assert "conflict" in run.stdout + run.stderr
    assert "opencti" not in steps and steps[-1] == "check --final", steps


def test_lite_checks_again_after_opencti_chosen_at_the_prompt(tmp_path):
    """No flags: Continue? y, then "Install OpenCTI MCP?" y; the rest blank."""
    run, steps = _lite(tmp_path, answers="y\ny\n" + "\n" * 12)
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]
    i = steps.index("opencti")
    assert steps[i - 1] == "check --final" and steps[i + 1] == "check --final", steps
    assert steps.count("opencti") == 1 and "locked" not in steps[i:], steps
