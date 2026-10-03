"""Uninstall step [8] never offers to delete what it can't read, and says what
rm -rf removes.

The step counted ledgers as the user, and an unreadable verification/ killed
uninstall at the count (set -euo pipefail): no step [9], no "complete". With
passwords/ unreadable it offered, and ran, `sudo rm -rf /var/lib/vhir`, and the
prompt never named passwords/ or snapshots/. The real step and prompt_yn_strict
run under the installer's own shell options, with the store redirected,
answers from a file and sudo recorded (never run).
"""

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
STEP = SCRIPT[
    SCRIPT.index("    # [8] Verification ledger") : SCRIPT.index("    # [9] AppArmor")
]
_p = SCRIPT.index("prompt_yn_strict() {")
PROMPT = SCRIPT[_p : SCRIPT.index("\n}\n", _p) + 3]

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root reads mode-0 dirs")


def _store(tmp_path, *, verification=True):
    vlv = tmp_path / "var-lib-vhir"
    (vlv / "passwords").mkdir(parents=True)
    (vlv / "snapshots").mkdir()
    (vlv / "passwords" / "alice.json").write_text("{}")
    (vlv / "snapshots" / ".keep").touch()
    if verification:
        (vlv / "verification").mkdir()
        for case in ("CASE-A", "CASE-B"):
            (vlv / "verification" / f"{case}.jsonl").write_text("{}\n")
    return vlv


def _run(tmp_path, vlv, answers, lock=None):
    """Run step [8]; lock = a path to chmod first (restored after)."""
    log = tmp_path / "sudo.log"
    log.write_text("")
    (tmp_path / "answers").write_text(answers)
    prologue = (
        "set -euo pipefail\nBOLD=; NC=; YELLOW=; GREEN=; BLUE=; RED=\n"
        'info() { echo "INFO $*"; }; ok() { echo "OK $*"; }; warn() { echo "WARN $*"; }\n'
        f'READ_FROM="{tmp_path / "answers"}"\n'
        f'sudo() {{ echo "$*" >> "{log}"; }}\n' + PROMPT
    )
    step = STEP.replace("/var/lib/vhir", str(vlv))
    if lock:
        lock[0].chmod(lock[1])
    try:
        p = subprocess.run(
            ["bash", "-c", prologue + step + 'echo "[9] reached"\n'],
            env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        if lock:
            lock[0].chmod(0o755)
    return p.returncode, p.stdout + p.stderr, log.read_text().splitlines()


@pytest.mark.parametrize(
    "which,mode",
    [
        ("verification", 0o000),
        ("", 0o000),  # /var/lib/vhir itself
        ("verification", 0o111),  # search but not list
        ("verification", 0o644),  # list but not search
        ("passwords", 0o000),
    ],
    ids=[
        "verification unreadable",
        "store unreadable",
        "x only",
        "r only",
        "passwords unreadable",
    ],
)
def test_an_unreadable_store_is_left_and_uninstall_goes_on(tmp_path, which, mode):
    vlv = _store(tmp_path)
    locked = vlv / which if which else vlv
    rc, out, sudo = _run(tmp_path, vlv, "y\n", lock=(locked, mode))
    assert rc == 0 and "[9] reached" in out, out  # not killed mid-way
    assert sudo == []  # nothing offered or run, even on a "y"
    assert (
        f"WARN Can't read {locked} (owner: " in out
        and "Run uninstall as that user" in out
    )
    assert "Ledger files: 0" not in out and "(0 ledger files)" not in out


def test_the_prompt_lists_what_rm_removes_and_n_keeps_it(tmp_path):
    vlv = _store(tmp_path)
    rc, out, sudo = _run(tmp_path, vlv, "n\n")
    assert rc == 0 and sudo == [] and "[9] reached" in out
    assert f"Removes {vlv}/ and everything in it (2 ledger files):" in out
    for name in ("verification", "passwords", "snapshots"):
        assert f"      {name}" in out.splitlines(), name
    # read -p shows its prompt only on a terminal: the wording, from the step
    assert 'prompt_yn_strict "    Remove $VERIF_DIR? (requires sudo)"' in STEP


def test_anchor_yes_removes_the_store(tmp_path):
    vlv = _store(tmp_path)
    rc, out, sudo = _run(tmp_path, vlv, "y\n")  # the answer reaches the prompt
    assert rc == 0 and sudo == [f"rm -rf {vlv}"]


def test_an_unreadable_snapshots_dir_is_still_listed(tmp_path):
    vlv = _store(tmp_path)
    rc, out, sudo = _run(tmp_path, vlv, "n\n", lock=(vlv / "snapshots", 0o000))
    assert rc == 0 and "      snapshots" in out.splitlines() and sudo == []


def test_no_verification_dir_lists_the_rest(tmp_path):
    vlv = _store(tmp_path, verification=False)
    rc, out, sudo = _run(tmp_path, vlv, "n\n")
    assert (
        rc == 0 and "(0 ledger files)" in out and "      passwords" in out.splitlines()
    )


def test_anchor_no_store_skips_the_step(tmp_path):
    rc, out, sudo = _run(tmp_path, tmp_path / "absent", "n\n")
    assert rc == 0 and "[8]" not in out and "[9] reached" in out and sudo == []
