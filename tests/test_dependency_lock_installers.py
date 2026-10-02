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
    """The log, each line reduced to: opencti, locked, check --strict/--final."""
    out = []
    for line in log.read_text().splitlines():
        if line.startswith("check "):
            out.append("check " + line.split()[2])
        elif line.startswith("pip install"):
            out.append("opencti" if "packages/opencti" in line else "locked")
    return out


def _python(tmp_path: Path, log: Path) -> Path:
    """The venv's python: records the check-lock.py runs."""
    py = tmp_path / "venv-python"
    py.write_text(f'#!/bin/sh\necho "check $*" >> "{log}"\n')
    py.chmod(0o755)
    return py


def test_setup_sift_installs_everything_but_opencti_from_the_lock(tmp_path):
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
            f'uv(){{ echo "$*" >> "{log}"; }}',
            f'INSTALL_DIR="{install_dir}"; VHIR_DIR="{tmp_path}/vhir"',
            f'VENV_PYTHON="{_python(tmp_path, log)}"',
            f'HOME="{tmp_path}"; USER=x',
            "INSTALL_TRIAGE=true; INSTALL_RAG=true; INSTALL_OPENCTI=true; INSTALL_OPENSEARCH_FLAG=true",
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
    opencti = [c for c in calls if "packages/opencti" in c]
    others = [c for c in calls if "packages/opencti" not in c]
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


def test_quickstart_lite_installs_everything_but_opencti_from_the_lock(tmp_path):
    script_dir = tmp_path / "sift-mcp"
    for p in ("sift-common", "forensic-rag", "windows-triage", "opencti"):
        (script_dir / "packages" / p).mkdir(parents=True)
    (script_dir / "deps").mkdir()
    lock = script_dir / "deps" / "vhir.lock"
    lock.write_text("# lock\n")
    log = tmp_path / "uv.log"
    text = LITE.read_text()
    script = "\n".join(
        [
            STUBS,
            f'uv(){{ if [ "$1" = "--version" ]; then echo "uv 0.12.20"; else echo "$*" >> "{log}"; fi; }}',
            f'SCRIPT_DIR="{script_dir}"; VENV_DIR="{tmp_path}/venv"',
            f'VENV_PYTHON="{_python(tmp_path, log)}"',
            "INSTALL_RAG=true; INSTALL_TRIAGE=true; INSTALL_OPENCTI=true",
            _slice(
                text,
                "# Older uv installs from the lock",
                "# Bridge existing pip mirror config",
            ),
            _slice(
                text,
                "# sift-common always installed",
                'if [[ "${VENV_ONLY:-}" == "true" ]]; then',
            ),
            _slice(
                text,
                'if [[ "$INSTALL_OPENCTI" == "true" ]]; then\n    # Install opencti package',
                '        warn "opencti-mcp not found at $pkg_dir"\n    fi\n',
            ),
            '        warn "opencti-mcp not found at $pkg_dir"\n    fi\nfi',
        ]
    )
    run = _run(script, tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr
    calls = _calls(log)
    locked = f"-c {lock} -b {lock}"
    assert [("packages/opencti" in c, locked in c) for c in calls] == [
        (False, True),
        (False, True),
        (False, True),
        (True, False),
    ], calls
    assert _steps(log) == [
        "locked",
        "locked",
        "locked",
        "check --strict",
        "opencti",
        "check --final",
    ]


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
