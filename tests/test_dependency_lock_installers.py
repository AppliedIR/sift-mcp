"""Both installers install from the dependency lock, except OpenCTI's client.

Every `uv pip install` of first-party or third-party packages takes the lock
as constraint and build constraint (-c, -b). OpenCTI installs last and
unlocked: pycti pins versions the lock can't hold. uv older than 0.6.0
ignores the lock's hashes, so the installers refuse it. These run the
installers' own text with uv and every other external command stubbed.
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
            f'INSTALL_DIR="{install_dir}"; VHIR_DIR="{tmp_path}/vhir"; VENV_PYTHON=python3',
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
            f'SCRIPT_DIR="{script_dir}"; VENV_PYTHON=python3; VENV_DIR="{tmp_path}/venv"',
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
