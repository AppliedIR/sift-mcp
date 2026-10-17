"""setup-sift.sh --remote: Network Configuration's static-IP question is told
whether -y was given (VHIR_ASSUME_DEFAULTS=true or false).

Only the Phase 7b block runs, with a stub Python that records what it was
told; nothing is installed.
"""

import subprocess
from pathlib import Path

import pytest

TEXT = (Path(__file__).resolve().parents[1] / "setup-sift.sh").read_text()
START = 'if $REMOTE_MODE; then\n    header "Network Configuration"'
END = "# =============================================================================\n# Phase 8"


def _run(tmp_path, auto_yes):
    python = tmp_path / "python"
    python.write_text(
        f'#!/bin/bash\necho "${{VHIR_ASSUME_DEFAULTS-unset}}" >> "{tmp_path}/assume"\n'
    )
    python.chmod(0o755)
    script = tmp_path / "block.sh"
    script.write_text(
        "set -euo pipefail\n"
        'header() { echo "== $*"; }; ok() { echo "OK $*"; }; info() { echo "INFO $*"; }\n'
        f'REMOTE_MODE=true; AUTO_YES={auto_yes}; VENV_PYTHON="{python}"\n'
        + TEXT[TEXT.index(START) : TEXT.index(END)]
        + f'echo "${{VHIR_ASSUME_DEFAULTS-unset}}" > "{tmp_path}/after"\n'
    )
    p = subprocess.run(
        ["/bin/bash", str(script)],
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    return p.returncode, p.stdout + p.stderr


@pytest.mark.parametrize("auto_yes", ["true", "false"])
def test_the_static_ip_question_is_told_whether_y_was_given(tmp_path, auto_yes):
    rc, out = _run(tmp_path, auto_yes)
    assert rc == 0 and "Skipped static IP" in out, out
    # one call: _ensure_static_ip (no network.yaml, so no read-back)
    assert (tmp_path / "assume").read_text().splitlines() == [auto_yes]
    # for that call only: the gateway started later must not inherit it
    assert (tmp_path / "after").read_text() == "unset\n"
