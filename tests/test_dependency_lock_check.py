"""deps/check-lock.py: a venv against the dependency lock.

The venv is a directory of .dist-info records and uv a stand-in on PATH whose
`pip check` result each row chooses, so every row runs the real script.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

CHECK = Path(__file__).parent.parent / "deps" / "check-lock.py"
OLD = sys.version_info < (3, 11)

LOCK = """\
# header
starlette==1.7.0 \\
    --hash=sha256:aaaa
uvicorn==0.54.0 \\
    --hash=sha256:bbbb
setuptools==84.0.0 \\
    --hash=sha256:cccc
numpy==2.2.6 ; python_full_version < '3.11' \\
    --hash=sha256:dddd
numpy==2.4.0 ; python_full_version >= '3.11' \\
    --hash=sha256:eeee
scipy==1.16.0 ; python_full_version >= '3.11' \\
    --hash=sha256:ffff
scipy==1.15.3 ; python_full_version < '3.11' \\
    --hash=sha256:9999
pywin32==311 ; sys_platform == 'win32' \\
    --hash=sha256:8888
"""
# Each listed once per Python range, in opposite orders: neither "first entry
# wins" nor "last entry wins" can stand in for evaluating the marker.
NUMPY = "2.2.6" if OLD else "2.4.0"
NUMPY_OTHER = "2.4.0" if OLD else "2.2.6"
SCIPY = "1.15.3" if OLD else "1.16.0"
SCIPY_OTHER = "1.16.0" if OLD else "1.15.3"
CLEAN = {"starlette": "1.7.0", "uvicorn": "0.54.0", "numpy": NUMPY, "scipy": SCIPY}


def _venv(
    tmp_path: Path, dists: dict, editable: dict | None = None, requires=None
) -> Path:
    site = tmp_path / "site"
    for name, version in {**dists, **(editable or {})}.items():
        info = site / f"{name}-{version}.dist-info"
        info.mkdir(parents=True)
        reqs = "".join(f"Requires-Dist: {r}\n" for r in (requires or {}).get(name, []))
        (info / "METADATA").write_text(f"Name: {name}\nVersion: {version}\n{reqs}")
        if editable and name in editable:
            url = {"url": "file:///src", "dir_info": {"editable": True}}
            (info / "direct_url.json").write_text(json.dumps(url))
    return site


def _run(
    tmp_path,
    mode,
    dists,
    *,
    pip_check_ok=True,
    editable=None,
    requires=None,
    conflict="",
    lock_text=LOCK,
    sizes=None,
):
    """conflict: what `uv pip check` reports (exit 1) until an uninstall,
    which removes the named packages' records. sizes: bytes a package's
    RECORD lists."""
    lock = tmp_path / "vhir.lock"
    lock.write_text(lock_text)
    site = _venv(tmp_path, dists, editable, requires)
    for name, size in (sizes or {}).items():
        info = next(site.glob(f"{name}-*.dist-info"))
        (info / "RECORD").write_text(f"{name}/lib.so,sha256=x,{size}\n")
        (site / name).mkdir()  # 3.12 lists only files that exist; its size is RECORD's
        (site / name / "lib.so").touch()
    (tmp_path / "conflict.txt").write_text(conflict)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    check = (
        "exit 0\n"
        if pip_check_ok
        else 'echo "x 1 requires y<2, but 2 is installed"; exit 1\n'
    )
    uv.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "uv 0.12.20"; exit 0; fi\n'
        f'echo "uv $*" >> "{tmp_path}/uv.log"\n'
        'if [ "$2" = uninstall ]; then shift 4\n'
        f'  for n in "$@"; do rm -rf "{site}/$n"-*.dist-info; done\n'
        f'  touch "{tmp_path}/removed"; exit 0; fi\n'
        f'if [ -s "{tmp_path}/conflict.txt" ] && [ ! -e "{tmp_path}/removed" ]; then\n'
        f'  cat "{tmp_path}/conflict.txt"; exit 1; fi\n' + check
    )
    uv.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    run = subprocess.run(
        [sys.executable, str(CHECK), mode, "--lock", str(lock), "--site", str(site)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    log = tmp_path / "uv.log"
    lines = log.read_text().splitlines() if log.exists() else []
    run.pip_checked = any("pip check" in x for x in lines)
    # Each uninstall's package names (after "uv pip uninstall --python PY").
    run.removed = [x.split()[5:] for x in lines if x.startswith("uv pip uninstall")]
    return run


def test_a_clean_venv_passes(tmp_path):
    run = _run(tmp_path, "--strict", CLEAN)
    assert run.returncode == 0, run.stderr
    assert "Dependencies match the lock: 4 packages" in run.stdout
    assert "uv 0.12.20" in run.stdout and run.pip_checked


def test_drift_is_a_loud_failure_naming_the_package_and_the_repair(tmp_path):
    run = _run(tmp_path, "--strict", {**CLEAN, "starlette": "0.50.0"})
    assert run.returncode == 1
    assert "starlette installed 0.50.0, lock 1.7.0" in run.stderr
    repair = [x for x in run.stderr.splitlines() if "uv pip install" in x]
    assert len(repair) == 1 and "starlette==1.7.0" in repair[0]
    assert "-c " in repair[0] and "-b " in repair[0]
    assert "uvicorn" not in run.stderr


def test_the_lock_entry_for_this_python_is_the_one_compared(tmp_path):
    assert _run(tmp_path, "--strict", CLEAN).returncode == 0
    for name, other in (("numpy", NUMPY_OTHER), ("scipy", SCIPY_OTHER)):
        d = tmp_path / name
        d.mkdir()
        run = _run(d, "--strict", {**CLEAN, name: other})
        assert run.returncode == 1 and f"{name} installed {other}" in run.stderr


def test_editables_are_skipped_and_unlocked_packages_listed(tmp_path):
    run = _run(
        tmp_path,
        "--strict",
        {**CLEAN, "leftover": "1.0"},
        editable={"sift-mcp": "0.6.1"},
    )
    assert run.returncode == 0, run.stderr
    assert "not in the lock" in run.stdout and "leftover" in run.stdout
    assert "sift-mcp" not in run.stdout


def test_unmet_requirements_fail(tmp_path):
    run = _run(tmp_path, "--strict", CLEAN, pip_check_ok=False)
    assert run.returncode == 1 and "requires y<2" in run.stderr


def test_strict_leaves_requirements_to_final_while_pycti_is_installed(tmp_path):
    run = _run(tmp_path, "--strict", {**CLEAN, "pycti": "6.9.29"}, pip_check_ok=False)
    assert run.returncode == 0, run.stderr
    assert "conflict" not in run.stderr and not run.removed


def test_final_lists_what_pycti_6_holds_and_why_it_matters(tmp_path):
    held = {"starlette": "0.50.0", "uvicorn": "0.35.0", "setuptools": "80.9.0"}
    run = _run(tmp_path, "--final", {**CLEAN, **held, "pycti": "6.9.29"})
    assert run.returncode == 0, run.stderr
    assert "pycti 6.9.29" in run.stdout
    for line in ("starlette 0.50.0 (lock 1.7.0)", "uvicorn 0.35.0 (lock 0.54.0)"):
        assert line in run.stdout
    note = [x for x in run.stdout.splitlines() if "pycti 6 holds" in x]
    assert len(note) == 1
    assert "starlette" in note[0] and "security advisories" in note[0]
    assert "7.x" in note[0]


def test_final_with_pycti_7_has_no_pycti_6_note(tmp_path):
    run = _run(
        tmp_path, "--final", {**CLEAN, "setuptools": "82.0.1", "pycti": "7.261002.0"}
    )
    assert run.returncode == 0, run.stderr
    assert "setuptools 82.0.1 (lock 84.0.0)" in run.stdout
    assert "pycti 6 holds" not in run.stdout


@pytest.mark.parametrize("mode", ["--final"])
def test_final_still_fails_on_conflicts_and_on_drift_without_pycti(tmp_path, mode):
    run = _run(tmp_path, mode, {**CLEAN, "pycti": "6.9.29"}, pip_check_ok=False)
    assert run.returncode == 1 and run.pip_checked
    other = tmp_path / "other"
    other.mkdir()
    run = _run(other, mode, {**CLEAN, "starlette": "0.50.0"})
    assert run.returncode == 1 and "starlette installed 0.50.0" in run.stderr


def test_installed_names_what_the_lock_pins_for_this_venv(tmp_path):
    run = _run(
        tmp_path,
        "--installed",
        {**CLEAN, "leftover": "1.0", "pywin32": "311"},
        editable={"sift-mcp": "0.6.1"},
    )
    assert run.returncode == 0, run.stderr
    # Only the names, on one line, for the first locked install to take.
    assert run.stdout == "numpy scipy starlette uvicorn\n"
    assert not run.pip_checked


OTLP = "opentelemetry-exporter-otlp-common"
OTLP_CONFLICT = f"The package `{OTLP}` requires `opentelemetry-sdk~=1.45`, but `1.35.0` is installed"


def test_strict_removes_a_conflicting_leftover_nothing_requires(tmp_path):
    """A no-OpenCTI 0.6.1 venv: otel moved to the lock, the old exporter
    plugin stays behind, outside the lock, and conflicts."""
    run = _run(tmp_path, "--strict", {**CLEAN, OTLP: "0.66b0"}, conflict=OTLP_CONFLICT)
    assert run.returncode == 0, run.stderr
    assert run.removed == [[OTLP]]
    # Named with its version, and how to put it back if it was the user's own.
    note = [x for x in run.stdout.splitlines() if f"{OTLP}==0.66b0" in x]
    assert len(note) == 1, run.stdout
    assert "nothing installed needs it" in note[0]
    assert f"uv pip install --python {sys.executable} {OTLP}==0.66b0" in note[0]
    assert "if you added it yourself" in note[0]


def test_strict_keeps_what_an_installed_package_requires(tmp_path):
    """Between the locked step and OpenCTI's: pycti conflicts, but opencti-mcp
    requires it, and it requires the exporter (under an extra)."""
    run = _run(
        tmp_path,
        "--strict",
        {**CLEAN, "pycti": "6.9.29", OTLP: "0.66b0"},
        editable={"opencti-mcp": "0.6.1"},
        requires={"opencti-mcp": ["pycti>=6"], "pycti": [f"{OTLP}; extra == 'otel'"]},
        conflict="The package `pycti` requires `starlette<0.51`, but `1.7.0` is installed\n"
        + OTLP_CONFLICT,
    )
    assert run.returncode == 0, run.stderr
    assert not run.removed


def test_strict_keeps_locked_editable_and_quiet_leftovers(tmp_path):
    run = _run(
        tmp_path,
        "--strict",
        {**CLEAN, "leftover": "1.0"},
        editable={"sift-gateway": "0.6.1"},
        conflict="The package `starlette` requires `anyio<5`, but `5.0` is installed\n"
        "The package `sift-gateway` requires `starlette>=2`, but `1.7.0` is installed",
    )
    assert not run.removed
    assert run.returncode == 1  # the conflict stands, so --strict fails


def test_final_removes_nothing(tmp_path):
    run = _run(tmp_path, "--final", {**CLEAN, OTLP: "0.66b0"}, conflict=OTLP_CONFLICT)
    assert run.returncode == 1 and not run.removed


def test_strict_reports_but_keeps_a_package_only_missing_its_own_dependency(tmp_path):
    missing = "The package `flask` requires `werkzeug>=3.1.0`, but it's not installed"
    run = _run(tmp_path, "--strict", {**CLEAN, "flask": "3.1.3"}, conflict=missing)
    assert not run.removed
    assert run.returncode == 1 and missing in run.stderr


# --- The CPU-PyTorch lock and what GPU PyTorch leaves behind ----------------

CPU_LOCK = """\
# vhir dependency lock: generated by deps/regen-lock.sh; don't edit by hand.
# variant         cpu: torch from the PyTorch CPU index; install with --torch-backend cpu
torch==2.14.0+cpu ; sys_platform != 'darwin' \\
    --hash=sha256:aaaa
starlette==1.7.0 \\
    --hash=sha256:bbbb
"""
GPU_LOCK = """\
# vhir dependency lock: generated by deps/regen-lock.sh; don't edit by hand.
torch==2.14.0 \\
    --hash=sha256:aaaa
nvidia-cublas==13.1.0.3 ; sys_platform == 'linux' \\
    --hash=sha256:cccc
starlette==1.7.0 \\
    --hash=sha256:bbbb
"""


def test_repairing_to_the_cpu_lock_names_its_index_and_replaces_torch(tmp_path):
    """Without --torch-backend cpu the +cpu pin can't be found."""
    run = _run(
        tmp_path,
        "--strict",
        {"torch": "2.14.0", "starlette": "1.7.0"},
        lock_text=CPU_LOCK,
    )
    (repair,) = [x for x in run.stderr.splitlines() if "uv pip install" in x]
    assert "'torch==2.14.0+cpu'" in repair or "torch==2.14.0+cpu" in repair
    assert "--torch-backend cpu" in repair and "--reinstall-package torch" in repair


def test_repairing_to_the_gpu_lock_replaces_the_cpu_build(tmp_path):
    """2.14.0+cpu satisfies ==2.14.0: only --reinstall-package replaces it."""
    run = _run(
        tmp_path,
        "--strict",
        {"torch": "2.14.0+cpu", "starlette": "1.7.0"},
        lock_text=GPU_LOCK,
    )
    (repair,) = [x for x in run.stderr.splitlines() if "uv pip install" in x]
    assert "--reinstall-package torch" in repair and "--torch-backend" not in repair


CUDA_VENV = {
    "torch": "2.14.0+cpu",
    "starlette": "1.7.0",
    "nvidia-cudnn-cu12": "9.10.2.21",
    "nvidia-cublas-cu12": "12.8.4.1",
    "triton": "3.6.0",
    "nvidia-curand-cu12": "10.3.9.90",
    "cupy-cuda12x": "13.6.0",
}
CUDA_REQUIRES = {
    "nvidia-cudnn-cu12": ["nvidia-cublas-cu12"],  # in the family: still removable
    "cupy-cuda12x": ["nvidia-curand-cu12"],  # the user's own package needs it
}


def test_cuda_leftovers_are_the_closure_requirers_first(tmp_path):
    run = _run(
        tmp_path,
        "--cuda-leftovers",
        CUDA_VENV,
        requires=CUDA_REQUIRES,
        lock_text=CPU_LOCK,
        sizes={"nvidia-cudnn-cu12": 1_054_000_000},
    )
    assert run.returncode == 0, run.stderr
    rows = [x.split() for x in run.stdout.splitlines()]
    names = [n for n, _ in rows]
    assert dict(rows)["nvidia-cudnn-cu12"] == "1054000000"  # name, then bytes
    assert sorted(names) == ["nvidia-cublas-cu12", "nvidia-cudnn-cu12", "triton"]
    assert names.index("nvidia-cudnn-cu12") < names.index("nvidia-cublas-cu12")


def test_a_family_package_the_lock_pins_is_not_a_leftover(tmp_path):
    venv = {
        "torch": "2.14.0",
        "starlette": "1.7.0",
        "nvidia-cublas": "13.1.0.3",
        "triton": "3.6.0",
    }
    run = _run(tmp_path, "--cuda-leftovers", venv, lock_text=GPU_LOCK)
    assert run.stdout.split() == ["triton", "0"]


def test_final_prints_the_leftovers_size_and_commands_and_removes_nothing(tmp_path):
    run = _run(
        tmp_path,
        "--final",
        CUDA_VENV,
        requires=CUDA_REQUIRES,
        lock_text=CPU_LOCK,
        sizes={"nvidia-cudnn-cu12": 1_000_000_000, "triton": 500_000_000},
    )
    out = run.stdout
    assert (
        "CUDA-family packages this lock doesn't install (check none are yours)" in out
    )
    assert "(1.5 GB in the venv" in out
    (uninstall,) = [x for x in out.splitlines() if "uv pip uninstall" in x]
    (clean,) = [x for x in out.splitlines() if "uv cache clean" in x]
    for name in ("nvidia-cudnn-cu12", "nvidia-cublas-cu12", "triton"):
        assert name in uninstall and name in clean
    assert "nvidia-curand-cu12" not in uninstall
    # Only what it uninstalls: cleaning torch's cache breaks a venv that links
    # its CPU torch there (uv --link-mode symlink).
    assert clean.split()[3:] == ["nvidia-cudnn-cu12", "triton", "nvidia-cublas-cu12"]
    assert run.removed == []


def test_final_on_the_gpu_lock_cleans_only_the_leftovers(tmp_path):
    venv = {
        "torch": "2.14.0",
        "starlette": "1.7.0",
        "nvidia-cublas": "13.1.0.3",
        "triton": "3.6.0",
    }
    out = _run(tmp_path, "--final", venv, lock_text=GPU_LOCK).stdout
    (clean,) = [x for x in out.splitlines() if "uv cache clean" in x]
    assert clean.split()[3:] == ["triton"]


def test_final_without_leftovers_prints_no_hint(tmp_path):
    out = _run(
        tmp_path,
        "--final",
        {"torch": "2.14.0+cpu", "starlette": "1.7.0"},
        lock_text=CPU_LOCK,
    ).stdout
    assert "CUDA packages" not in out
