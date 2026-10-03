"""The PyTorch build (CPU or GPU) each installer installs, and when it asks.

The rule, the same in setup-sift and Lite: --cpu/--gpu, else the build already
in the venv (+cpu means CPU), else CPU. Interactive runs ask only when the
venv has PyTorch but was never asked (no record), or RAG is being installed
without it; the default answer is CPU. macOS is never asked and uses the PyPI
lock. These run the installers' own text with the venv's python, nvidia-smi
and the answers stubbed.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SETUP = ROOT / "setup-sift.sh"

STUBS = "\n".join(
    [
        "set -euo pipefail",
        "RED= GREEN= YELLOW= BLUE= BOLD= NC=",
        'info(){ echo "[INFO] $*"; }; ok(){ echo "[OK] $*"; }',
        'warn(){ echo "[WARN] $*"; }; err(){ echo "[ERROR] $*"; }',
        'fail(){ echo "[FAIL] $*"; exit 1; }; header(){ :; }',
    ]
)


def _slice(text: str, start: str, end: str) -> str:
    i = text.index(start)
    return text[i : text.index(end, i)]


def _session(terminal: bool):
    """A new session (no controlling terminal), given a pseudo-terminal as
    its terminal when `terminal`: /dev/tty then opens though stdin is a pipe,
    as under `curl | bash`."""
    slave = None
    if terminal:
        master, slave_fd = os.openpty()
        slave = os.ttyname(slave_fd)

    def pre():
        os.setsid()
        if slave:
            os.close(os.open(slave, os.O_RDWR))  # becomes the controlling tty

    return pre


def _setup_decision(
    tmp_path,
    *,
    flag="",
    installed="",
    record=None,
    auto_yes=True,
    rag=True,
    answers=(),
    platform="Linux",
    gpu=False,
    terminal=True,
    rc=0,
):
    """Runs setup-sift's PyTorch-build block, stdin never a terminal; returns
    (variant, record, output, how many times it asked)."""
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    if record is not None:
        (home / ".vhir" / "manifest.json").write_text(
            json.dumps({"torch_variant": record})
        )
    venv = home / ".vhir" / "venv"
    if installed:
        (venv / "bin").mkdir(parents=True)
        py = venv / "bin" / "python"
        py.write_text(f"#!/bin/sh\necho {installed}\n")
        py.chmod(0o755)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if gpu:
        smi = bin_dir / "nvidia-smi"
        smi.write_text("#!/bin/sh\necho 'GPU 0: NVIDIA RTX A4000 (UUID: GPU-x)'\n")
        smi.chmod(0o755)
    replies = tmp_path / "replies"
    replies.write_text("".join(f"{a}\n" for a in answers))
    script = "\n".join(
        [
            STUBS,
            f'export PATH="{bin_dir}:/usr/bin:/bin"',
            f'HOME="{home}"; VENV_DIR="{venv}"; PLATFORM="{platform}"',
            f'TORCH_FLAG="{flag}"; AUTO_YES={str(auto_yes).lower()}; INSTALL_RAG={str(rag).lower()}',
            # A stream, as /dev/tty or /dev/stdin are: each read goes on from the last.
            f'exec 3< <(cat "{replies}"); READ_FROM=/dev/fd/3',
            _slice(
                SETUP.read_text(), "# --- PyTorch build", "# Phase 3: Clone Repository"
            ),
            'echo "VARIANT=$TORCH_VARIANT RECORD=$TORCH_RECORD"',
        ]
    )
    run = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        preexec_fn=_session(terminal),
    )
    assert run.returncode == rc, run.stdout + run.stderr
    asked = 0
    if "PyTorch for knowledge search" in run.stdout:
        asked = 1 + run.stdout.count("Please enter cpu or gpu.")
    if rc:
        return None, None, run.stdout, asked
    last = run.stdout.strip().splitlines()[-1]
    variant, record_out = (x.split("=", 1)[1] for x in last.split())
    return variant, record_out, run.stdout, asked


@pytest.mark.parametrize("flag", ["cpu", "gpu"])
def test_a_flag_wins_without_a_question(tmp_path, flag):
    installed = "2.14.0" if flag == "cpu" else "2.14.0+cpu"  # the other build
    variant, record, _, asked = _setup_decision(
        tmp_path, flag=flag, installed=installed, auto_yes=False
    )
    assert (variant, record, asked) == (flag, flag, 0)


@pytest.mark.parametrize(
    "installed,expect",
    [("2.14.0", "gpu"), ("2.10.0", "gpu"), ("2.14.0+cpu", "cpu"), ("", "cpu")],
)
def test_a_run_that_does_not_ask_keeps_the_installed_build(tmp_path, installed, expect):
    """-y: a GPU install re-run stays GPU; no PyTorch yet means CPU."""
    variant, record, out, asked = _setup_decision(tmp_path, installed=installed)
    assert (variant, asked) == (expect, 0)
    assert record == ""  # not asked: nothing recorded
    assert f"PyTorch build: {expect} (switch with --cpu or --gpu)" in out


def test_the_installed_build_beats_a_stale_record(tmp_path):
    """A run that swapped torch and stopped before the manifest: the venv is
    the truth, the record only says the user was asked."""
    variant, _, _, asked = _setup_decision(
        tmp_path, installed="2.14.0+cpu", record="gpu"
    )
    assert (variant, asked) == ("cpu", 0)


@pytest.mark.parametrize("answer,expect", [("", "cpu"), ("gpu", "gpu"), ("CPU", "cpu")])
def test_an_old_install_never_asked_is_asked_default_cpu(tmp_path, answer, expect):
    variant, record, out, asked = _setup_decision(
        tmp_path, installed="2.10.0", auto_yes=False, answers=[answer]
    )
    assert asked == 1 and (variant, record) == (expect, expect)
    assert "Installed now: the GPU build (torch 2.10.0)" in out
    assert "Choosing the other build replaces it" in out
    assert "0.2 GB download" in out and "3 GB download" in out


def test_a_wrong_answer_is_asked_again(tmp_path):
    variant, _, _, asked = _setup_decision(
        tmp_path, installed="2.10.0", auto_yes=False, answers=["gpus", "gpu"]
    )
    assert (variant, asked) == ("gpu", 2)


def test_an_install_already_asked_is_not_asked_again(tmp_path):
    """Its twin above asks: the record is what stops a re-run asking."""
    variant, record, _, asked = _setup_decision(
        tmp_path, installed="2.14.0", record="gpu", auto_yes=False
    )
    assert (variant, record, asked) == ("gpu", "gpu", 0)


@pytest.mark.parametrize("rag,asks", [(True, True), (False, False)])
def test_a_first_install_asks_only_when_installing_rag(tmp_path, rag, asks):
    variant, _, _, asked = _setup_decision(
        tmp_path, auto_yes=False, answers=[""], rag=rag, record="cpu"
    )
    assert variant == "cpu" and bool(asked) is asks


@pytest.mark.parametrize(
    "gpu,found", [(True, "an NVIDIA GPU was found"), (False, "no NVIDIA GPU was found")]
)
def test_the_question_says_what_nvidia_smi_found(tmp_path, gpu, found):
    _, _, out, _ = _setup_decision(tmp_path, auto_yes=False, gpu=gpu, answers=[""])
    assert found in out


@pytest.mark.parametrize("flag", ["", "cpu", "gpu"])
def test_macos_uses_the_pypi_lock_and_is_never_asked(tmp_path, flag):
    variant, record, out, asked = _setup_decision(
        tmp_path, platform="Darwin", flag=flag, installed="2.14.0", auto_yes=False
    )
    assert (variant, record, asked) == ("pypi", "", 0)
    if flag:
        assert f"--{flag} is not applicable on macOS" in out


@pytest.mark.parametrize("installed,expect", [("2.14.0", "gpu"), ("", "cpu")])
def test_without_a_terminal_a_run_does_not_ask_and_keeps_the_build(
    tmp_path, installed, expect
):
    """Not -y, but nothing to answer with: a re-run over a GPU install stays
    GPU, and nothing is recorded (it was never asked)."""
    variant, record, out, asked = _setup_decision(
        tmp_path, installed=installed, auto_yes=False, terminal=False
    )
    assert (variant, record, asked) == (expect, "", 0)
    assert f"PyTorch build: {expect} (switch with --cpu or --gpu)" in out


def test_piped_stdin_with_a_terminal_still_asks(tmp_path):
    """`curl | bash`: stdin is the pipe, the answer comes from /dev/tty."""
    variant, record, _, asked = _setup_decision(
        tmp_path, installed="2.14.0", auto_yes=False, answers=["gpu"], terminal=True
    )
    assert (variant, record, asked) == ("gpu", "gpu", 1)


def test_no_answer_at_the_question_installs_nothing(tmp_path):
    """End of input mustn't become a silent swap to the default."""
    _, _, out, asked = _setup_decision(
        tmp_path, installed="2.14.0", auto_yes=False, answers=(), rc=1
    )
    assert asked == 1 and "nothing installed" in out and "--cpu or --gpu" in out


# --- The locked installs ------------------------------------------------------


def _lock_slice(tmp_path, variant, installed="", *, fail_core=False, cpu_lock=True):
    install_dir = tmp_path / "sift-mcp"
    (install_dir / "deps").mkdir(parents=True)
    (install_dir / "deps" / "vhir.lock").write_text("# lock\n")
    if cpu_lock:
        (install_dir / "deps" / "vhir-cpu.lock").write_text("# variant cpu\n")
    log = tmp_path / "uv.log"
    py = tmp_path / "venv-python"
    py.write_text('#!/bin/sh\n[ "$2" = --installed ] && echo "setuptools"\nexit 0\n')
    py.chmod(0o755)
    text = SETUP.read_text()
    script = "\n".join(
        [
            STUBS,
            f'uv(){{ echo "$*" >> "{log}"; '
            + ("return 1; }" if fail_core else "return 0; }"),
            f'INSTALL_DIR="{install_dir}"; VHIR_DIR="{tmp_path}/vhir"; VENV_PYTHON="{py}"',
            f'TORCH_VARIANT={variant}; TORCH_INSTALLED="{installed}"',
            "INSTALL_TRIAGE=false; INSTALL_RAG=true",
            _slice(
                text,
                "# Every third-party package is installed",
                "# --- Virtual environment ---",
            ),
            _slice(text, "# Helper: install a single package", "# --- OpenSearch MCP"),
        ]
    )
    run = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=60, cwd=tmp_path
    )
    calls = (
        [x for x in log.read_text().splitlines() if x.startswith("pip install")]
        if log.exists()
        else []
    )
    return run, calls, install_dir / "deps"


def test_the_cpu_variant_installs_from_the_cpu_lock_with_its_index(tmp_path):
    run, calls, deps = _lock_slice(tmp_path, "cpu", installed="2.14.0")
    assert run.returncode == 0, run.stdout + run.stderr
    lock = deps / "vhir-cpu.lock"
    assert len(calls) == 2  # core, then forensic-rag
    for call in calls:
        assert f"-c {lock} -b {lock} --torch-backend cpu" in call, call


@pytest.mark.parametrize(
    "installed,reinstall", [("2.14.0+cpu", True), ("2.14.0", False), ("", False)]
)
def test_the_gpu_variant_installs_from_the_pypi_lock(tmp_path, installed, reinstall):
    """2.14.0+cpu satisfies ==2.14.0: a switch to GPU reinstalls torch."""
    run, calls, deps = _lock_slice(tmp_path, "gpu", installed=installed)
    assert run.returncode == 0, run.stdout + run.stderr
    lock = deps / "vhir.lock"
    for call in calls:
        assert f"-c {lock} -b {lock}" in call and "--torch-backend" not in call, call
        assert ("--reinstall-package torch" in call) is reinstall, call


def test_macos_installs_from_the_pypi_lock(tmp_path):
    run, calls, deps = _lock_slice(tmp_path, "pypi", installed="2.14.0")
    assert run.returncode == 0 and calls
    assert all(
        f"-c {deps / 'vhir.lock'}" in c and "--torch-backend" not in c for c in calls
    )


def test_a_missing_cpu_lock_is_named(tmp_path):
    run, calls, deps = _lock_slice(tmp_path, "cpu", cpu_lock=False)
    assert run.returncode == 1 and not calls
    assert f"Dependency lock not found: {deps / 'vhir-cpu.lock'}" in run.stdout


@pytest.mark.parametrize("variant,hint", [("cpu", True), ("gpu", False)])
def test_a_failed_install_on_the_cpu_lock_names_the_pytorch_index(
    tmp_path, variant, hint
):
    run, _, _ = _lock_slice(tmp_path, variant, fail_core=True)
    assert run.returncode == 1
    assert ("download.pytorch.org" in run.stdout and "--gpu" in run.stdout) is hint


# --- The record ---------------------------------------------------------------


@pytest.mark.parametrize("record", ["cpu", "gpu", ""])
def test_the_manifest_carries_the_record(tmp_path, record):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    script = "\n".join(
        [
            STUBS,
            f'HOME="{home}"; VENV_PYTHON=python3; VENV_DIR=x; INSTALL_DIR="{tmp_path}"',
            "GATEWAY_PORT=4508; MODE=recommended; INSTALL_TRIAGE=false; INSTALL_RAG=false",
            f'INSTALL_OPENCTI=false; TORCH_RECORD="{record}"',
            _slice(
                SETUP.read_text(),
                'MANIFEST="$HOME/.vhir/manifest.json"',
                'chmod 600 "$MANIFEST"',
            ),
        ]
    )
    run = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=60
    )
    assert run.returncode == 0, run.stdout + run.stderr
    manifest = json.loads((home / ".vhir" / "manifest.json").read_text())
    assert manifest.get("torch_variant", "") == record
