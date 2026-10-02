"""setup-sift.sh's ledger directories, with USER unset and after a partial install.

Under `set -u` a missing USER (cron, systemd, cloud-init, docker exec)
aborted the install at the first `chown "$USER:$USER"`, leaving the
directory root-owned, and the rerun's existence check then reported it ok.
These run the installer's own phase text with /var/lib/vhir pointed at a
scratch directory and sudo replaced by a function, never the installer.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "setup-sift.sh"
DIRS = ("verification", "passwords")


def _harness(root: Path, sudo: str = '"$@"', prelude: str = "") -> str:
    text = SCRIPT.read_text()
    user = "\n".join(re.findall(r"^USER=.*$", text, re.M))
    start = text.index("# Phase 1b: Verification Ledger Directory")
    end = text.index(
        "# Phase", text.index("# Phase 1b2: Password Storage Directory") + 10
    )
    block = text[start:end].replace("/var/lib/vhir", str(root))
    return "\n".join(
        [
            "set -euo pipefail",
            prelude,
            f"sudo() {{ {sudo}; }}",
            'info() { echo "INFO $*"; }',
            'ok() { echo "OK $*"; }',
            'warn() { echo "WARN $*"; }',
            'err() { echo "ERR $*"; }',
            user,
            block,
        ]
    )


def _run(tmp_path: Path, env_user: bool, **kw) -> subprocess.CompletedProcess:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    if env_user:
        env["USER"] = subprocess.run(
            ["id", "-un"], capture_output=True, text=True
        ).stdout.strip()
    return subprocess.run(
        ["bash", "-c", _harness(tmp_path / "vhir", **kw)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _writable(path: Path) -> bool:
    return path.is_dir() and os.access(path, os.W_OK)


@pytest.fixture
def unwritable(tmp_path):
    """Both directories left present but not writable, as a partial install
    leaves them root-owned."""
    for name in DIRS:
        (tmp_path / "vhir" / name).mkdir(parents=True)
        (tmp_path / "vhir" / name).chmod(0o555)
    yield tmp_path
    for name in DIRS:
        (tmp_path / "vhir" / name).chmod(0o700)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write a 555 directory")
class TestLedgerDirectories:
    def test_with_user_unset_they_are_created(self, tmp_path):
        run = _run(tmp_path, env_user=False)
        assert run.returncode == 0, run.stderr
        for name in DIRS:
            mode = stat.S_IMODE((tmp_path / "vhir" / name).stat().st_mode)
            assert (_writable(tmp_path / "vhir" / name), mode) == (True, 0o700)

    def test_a_directory_left_unwritable_is_repaired(self, unwritable):
        run = _run(unwritable, env_user=True)
        assert run.returncode == 0, run.stdout + run.stderr
        assert all(_writable(unwritable / "vhir" / name) for name in DIRS)

    def test_a_directory_that_cannot_be_repaired_fails_loudly(self, unwritable):
        run = _run(unwritable, env_user=True, sudo="return 1")
        assert run.returncode == 1
        assert "ERR Could not create" in run.stdout

    def test_a_writable_directory_is_left_alone(self, tmp_path):
        for name in DIRS:
            (tmp_path / "vhir" / name).mkdir(parents=True, mode=0o700)
        run = _run(tmp_path, env_user=True, sudo="exit 9")
        assert run.returncode == 0, run.stdout + run.stderr
        assert run.stdout.count("OK ") == 2

    @pytest.mark.parametrize("name", DIRS)
    @pytest.mark.parametrize("target_mode", [0o555, 0o700])
    def test_a_symlink_fails_loudly_and_its_target_is_untouched(
        self, tmp_path, name, target_mode
    ):
        """A repair through the link would chown and chmod its target."""
        target = tmp_path / "elsewhere"
        target.mkdir(mode=target_mode)
        target.chmod(target_mode)
        for other in DIRS:
            if other != name:
                (tmp_path / "vhir" / other).mkdir(parents=True, mode=0o700)
        (tmp_path / "vhir").mkdir(exist_ok=True)
        (tmp_path / "vhir" / name).symlink_to(target)
        try:
            run = _run(tmp_path, env_user=True)
            mode = stat.S_IMODE(target.stat().st_mode)
        finally:
            target.chmod(0o700)
        assert run.returncode == 1, run.stdout
        assert f"ERR Could not create {tmp_path / 'vhir' / name}/" in run.stdout
        assert mode == target_mode

    def test_a_directory_another_user_owns_is_not_ok(self, tmp_path):
        """World-writable passes -w, but the passwords must be the
        installer's alone. [ -O ] reports another owner: a test that isn't
        root can't create one."""
        for name in DIRS:
            (tmp_path / "vhir" / name).mkdir(parents=True)
            (tmp_path / "vhir" / name).chmod(0o777)
        not_mine = '[() { if [[ $1 == -O ]]; then return 1; fi; builtin [ "$@"; }'
        run = _run(tmp_path, env_user=True, prelude=not_mine)
        assert run.returncode == 0, run.stdout + run.stderr
        assert run.stdout.count("INFO Creating") == 2, run.stdout
        for name in DIRS:
            assert stat.S_IMODE((tmp_path / "vhir" / name).stat().st_mode) == 0o700
