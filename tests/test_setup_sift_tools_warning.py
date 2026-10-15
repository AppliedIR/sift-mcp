"""The installer's summary says when SIFT's own tools are too old for Valhuntir.

The check itself is vhir's (vhir_cli.sift_tools); the installer prints what it
prints as a warning and carries on: it's never an install error. These run the
installer's own lines with the venv Python stubbed, never the installer.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
_start = SCRIPT.index("# SIFT tools too old for Valhuntir")
CHECK = SCRIPT[_start : SCRIPT.index("# Data Maintenance", _start)]

TEXT = "Some SIFT tools are out of date (`sudo cast install teamdfir/sift`)."


def _summary(tmp_path: Path, stub: str):
    """`stub`: the body of the venv Python's answer to `-m vhir_cli.sift_tools`."""
    py = tmp_path / "venv-python"
    py.write_text(
        "#!/bin/bash\n"
        'if [[ "$*" == "-m vhir_cli.sift_tools" ]]; then\n'
        f"{stub}\n"
        "fi\n"
        "exit 99\n"
    )
    py.chmod(0o755)
    harness = "\n".join(
        [
            "set -euo pipefail",
            'warn(){ echo "[WARN] $*"; }',
            f'VENV_PYTHON="{py}"; INSTALL_ERRORS=0',
            CHECK,
            'echo "errors=$INSTALL_ERRORS"',
        ]
    )
    out = subprocess.run(
        ["bash", "-c", harness],
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    return out.returncode, out.stdout.splitlines()


def test_the_check_runs_after_the_install_errors_and_before_the_data_check():
    assert SCRIPT.index('OPENSEARCH_SNAPSHOTS_FAILED"\n') < _start
    assert _start < SCRIPT.index("# Data Maintenance")
    assert '"$VENV_PYTHON" -m vhir_cli.sift_tools' in CHECK


def test_its_text_is_printed_as_a_warning_not_an_error(tmp_path):
    rc, lines = _summary(tmp_path, f"echo '{TEXT}'; exit 0")
    assert rc == 0 and lines == ["", f"[WARN] {TEXT}", "errors=0"]


def test_nothing_out_of_date_prints_nothing(tmp_path):
    rc, lines = _summary(tmp_path, "exit 0")
    assert rc == 0 and lines == ["errors=0"]


def test_a_check_that_fails_prints_nothing_and_setup_carries_on(tmp_path):
    rc, lines = _summary(tmp_path, "echo 'Traceback' >&2; exit 1")
    assert rc == 0 and lines == ["errors=0"]


def test_a_check_that_hangs_is_cut_off_and_setup_carries_on(tmp_path):
    py = tmp_path / "venv-python"
    harness = "\n".join(
        [
            "set -euo pipefail",
            'warn(){ echo "[WARN] $*"; }',
            "timeout(){ return 124; }",  # what timeout returns when it kills the check
            f'VENV_PYTHON="{py}"; INSTALL_ERRORS=0',
            CHECK,
            'echo "errors=$INSTALL_ERRORS"',
        ]
    )
    out = subprocess.run(
        ["bash", "-c", harness],
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0 and out.stdout.splitlines() == ["errors=0"]
