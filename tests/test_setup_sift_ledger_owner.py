"""The installer doesn't take over another examiner's ledger directories.

The ledger repair chowned an existing /var/lib/vhir/verification or
passwords to the installing user even when another, non-root user owned it.
That user could then no longer approve or verify. Now such a directory stops
the install, naming its owner, before any sudo. A root-owned (half-finished)
or missing directory is still repaired, and the installer's own is left as
is. The real Phase 1b block runs with the paths redirected, sudo recorded
(never run), and stat reporting another owner for one path.
"""

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
_start = SCRIPT.find("# The ledger directories may belong to another examiner")
if _start == -1:
    _start = SCRIPT.index("# Phase 1b: Verification Ledger Directory")
_end = SCRIPT.index("# Phase 1c:")
BLOCK = SCRIPT[_start:_end]

ROOT_OWNED = ("/usr/share", "/usr/lib")  # exist and are root's on any Linux box

pytestmark = pytest.mark.skipif(
    os.geteuid() == 0 or not all(os.stat(p).st_uid == 0 for p in ROOT_OWNED),
    reason="needs a non-root user and root-owned /usr/share, /usr/lib",
)


def _run(tmp_path, vdir, pdir, foreign=None):
    """Run the block for the two directories; `foreign` is reported by stat
    as belonging to uid 1234, alice. Returns (rc, sudo calls, output)."""
    stub = tmp_path / "bin"
    stub.mkdir(exist_ok=True)
    (stub / "stat").write_text(
        "#!/bin/bash\n"
        'for a; do last="$a"; done\n'
        'if [ -n "$FOREIGN" ] && [ "$last" = "$FOREIGN" ]; then\n'
        '  case "$*" in *%u*) echo 1234 ;; *%U*) echo alice ;; esac; exit 0\n'
        "fi\n"
        'exec /usr/bin/stat "$@"\n'
    )
    (stub / "stat").chmod(0o755)
    log = tmp_path / "sudo.log"
    log.write_text("")
    block = BLOCK.replace("/var/lib/vhir/verification", str(vdir)).replace(
        "/var/lib/vhir/passwords", str(pdir)
    )
    prologue = (
        "set -euo pipefail\n"
        'info() { echo "INFO $*"; }; ok() { echo "OK $*"; }\n'
        'warn() { echo "WARN $*"; }; err() { echo "ERR $*"; }\n'
        f'sudo() {{ echo "$*" >> "{log}"; }}\n'
    )
    p = subprocess.run(
        ["bash", "-c", prologue + block],
        env={
            "PATH": f"{stub}:/usr/bin:/bin",
            "HOME": str(tmp_path),
            "USER": "steve",
            "FOREIGN": str(foreign or ""),
        },
        capture_output=True,
        text=True,
    )
    return p.returncode, log.read_text().splitlines(), p.stdout + p.stderr


def _mine(tmp_path, name, mode=0o700):
    d = tmp_path / name
    d.mkdir()
    d.chmod(mode)
    return d


@pytest.mark.parametrize("which", ["verification", "passwords"])
def test_1_another_users_directory_stops_the_install_before_any_sudo(tmp_path, which):
    foreign = ROOT_OWNED[0]  # root-owned on disk; stat says it's alice's
    missing = tmp_path / "missing"
    vdir, pdir = (foreign, missing) if which == "verification" else (missing, foreign)
    rc, sudo, out = _run(tmp_path, vdir, pdir, foreign=foreign)
    assert rc == 1 and sudo == []
    assert f"{foreign}/ belongs to alice" in out and "One examiner OS user" in out


def test_5_root_owned_verification_and_foreign_passwords_touch_nothing(tmp_path):
    rc, sudo, out = _run(tmp_path, ROOT_OWNED[1], ROOT_OWNED[0], foreign=ROOT_OWNED[0])
    assert rc == 1 and sudo == [] and "belongs to alice" in out


def test_2_anchor_root_owned_directories_are_repaired(tmp_path):
    rc, sudo, _ = _run(tmp_path, ROOT_OWNED[1], ROOT_OWNED[0])
    assert rc == 0
    assert f"chown steve:steve {ROOT_OWNED[1]}" in sudo
    assert f"chown steve:steve {ROOT_OWNED[0]}" in sudo


def test_3_anchor_the_installers_own_directories_need_no_sudo(tmp_path):
    rc, sudo, _ = _run(tmp_path, _mine(tmp_path, "v"), _mine(tmp_path, "p"))
    assert rc == 0 and sudo == []


def test_4_anchor_the_installers_unwritable_directory_is_repaired(tmp_path):
    v = _mine(tmp_path, "v", 0o500)
    try:
        rc, sudo, _ = _run(tmp_path, v, _mine(tmp_path, "p"))
    finally:
        v.chmod(0o700)
    assert rc == 0 and f"chown steve:steve {v}" in sudo


def test_anchor_missing_directories_are_created(tmp_path):
    rc, sudo, _ = _run(tmp_path, tmp_path / "v", tmp_path / "p")
    assert rc == 0 and f"mkdir -p {tmp_path / 'v'}" in sudo
