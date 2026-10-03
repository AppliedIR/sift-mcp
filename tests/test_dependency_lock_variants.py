"""The two dependency locks: GPU PyTorch (vhir.lock, PyPI) and CPU PyTorch
(vhir-cpu.lock, uv --torch-backend cpu), the same pins otherwise.

regen-lock.sh --check runs for real against throwaway git repos, with a uv
stand-in whose `pip compile` answers with the CPU lock's pins when given
--torch-backend cpu and the GPU lock's otherwise.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

DEPS = Path(__file__).parent.parent / "deps"
GPU = DEPS / "vhir.lock"
CPU = DEPS / "vhir-cpu.lock"
FAMILY = re.compile(r"^(nvidia-|cuda-|triton==)")


def _pins(lock: Path) -> list[str]:
    return [
        x for x in lock.read_text().splitlines() if re.match(r"^[A-Za-z0-9._-]+==", x)
    ]


def test_the_cpu_lock_pins_cpu_torch_and_no_cuda_family():
    pins = _pins(CPU)
    torch = [x for x in pins if x.startswith("torch==")]
    assert "torch==2.14.0+cpu ; sys_platform != 'darwin' \\" in torch
    assert not [x for x in pins if FAMILY.match(x)]
    assert [x for x in _pins(GPU) if FAMILY.match(x)]  # the GPU lock's twin has them
    assert "# variant         cpu" in CPU.read_text()


def test_every_cpu_pin_is_hashed():
    lines = CPU.read_text().splitlines()
    for i, line in enumerate(lines):
        if re.match(r"^[A-Za-z0-9._-]+==", line):
            assert "--hash=sha256:" in lines[i + 1], line


def test_the_locks_share_every_pin_but_torch_and_cuda():
    """colorama's marker is rewritten in a form equal for every real platform."""
    rest = lambda lock: {  # noqa: E731
        x.split(" ")[0]
        for x in _pins(lock)
        if not FAMILY.match(x) and not x.startswith("torch==")
    }
    assert rest(GPU) == rest(CPU)
    gpu_head = GPU.read_text().split("\n#\n")[1]
    assert gpu_head == CPU.read_text().split("\n#\n")[1]  # same commits, date, holds


def _regen_check(tmp_path: Path, cpu_lock: str) -> subprocess.CompletedProcess:
    repos = {}
    for name in ("sift-mcp", "vhir", "opensearch-mcp"):
        r = tmp_path / name
        (r / "deps").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(r)], check=True)
        repos[name] = r
    sift = repos["sift-mcp"]
    shutil.copy(DEPS / "regen-lock.sh", sift / "deps")
    shutil.copy(GPU, sift / "deps")
    (sift / "deps" / "vhir-cpu.lock").write_text(cpu_lock)
    for r in repos.values():
        git = ["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t"]
        subprocess.run([*git, "add", "-A"], check=True)
        subprocess.run([*git, "commit", "-qm", "x", "--allow-empty"], check=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    uv.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "uv 0.12.20"; exit 0; fi\n'
        'out=""; cpu=no; prev=""\n'
        'for a in "$@"; do [ "$prev" = "-o" ] && out=$a; [ "$a" = "--torch-backend" ] && cpu=yes;'
        " prev=$a; done\n"
        f'if [ $cpu = yes ]; then grep -E "^[A-Za-z0-9._-]+==" "{CPU}" > "$out";'
        f' else grep -E "^[A-Za-z0-9._-]+==" "{GPU}" > "$out"; fi\n'
    )
    uv.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "VHIR_REPO": str(repos["vhir"]),
        "OPENSEARCH_REPO": str(repos["opensearch-mcp"]),
    }
    return subprocess.run(
        ["bash", str(sift / "deps" / "regen-lock.sh"), "--check"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def test_check_covers_both_locks(tmp_path):
    ok = _regen_check(tmp_path / "ok", CPU.read_text())
    assert ok.returncode == 0, ok.stderr
    wrong = _regen_check(
        tmp_path / "wrong", GPU.read_text()
    )  # the GPU lock as the CPU one
    assert wrong.returncode == 1
    assert "vhir-cpu.lock" in wrong.stderr and "torch==2.14.0+cpu" in wrong.stderr
