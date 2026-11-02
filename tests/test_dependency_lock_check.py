"""deps/check-lock.py: a venv against the dependency lock.

The venv is a directory of .dist-info records and uv a stand-in on PATH whose
`pip check` result each row chooses, so every row runs the real script.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
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
    """conflict: what `uv pip check` reports (exit 1), each "The package `X`
    requires" line while X is still installed; an uninstall removes the named
    packages' records. sizes: bytes a package's RECORD lists."""
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
        # name-<version>: stix2's records aren't stix2-patterns'
        f'  for n in "$@"; do rm -rf "{site}/$n"-[0-9]*.dist-info; done; exit 0; fi\n'
        "rc=0\n"
        'while IFS= read -r line || [ -n "$line" ]; do\n'
        "  n=${line#The package \\`}; n=${n%%\\`*}\n"
        f'  if [ "$n" = "$line" ] || [ -n "$(ls -d "{site}/$n"-[0-9]*.dist-info 2>/dev/null)" ]; then\n'
        '    echo "$line"; rc=1; fi\n'
        f'done < "{tmp_path}/conflict.txt"\n'
        '[ "$rc" = 0 ] || exit 1\n' + check
    )
    uv.chmod(0o755)
    return _check(tmp_path, mode)


def _check(tmp_path, mode):
    """Run the script again on the venv _run made, as it now is; pip_checked
    and removed are this run's."""
    lock, site, bin_dir = tmp_path / "vhir.lock", tmp_path / "site", tmp_path / "bin"
    log = tmp_path / "uv.log"
    log.unlink(missing_ok=True)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    run = subprocess.run(
        [sys.executable, str(CHECK), mode, "--lock", str(lock), "--site", str(site)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
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


PYCTI_CONFLICT = (
    "The package `pycti` requires `starlette<0.51`, but `1.7.0` is installed"
)


@pytest.mark.parametrize("mode", ["--strict", "--final"])
def test_a_leftover_pycti_s_own_conflicts_fail_neither_check(tmp_path, mode):
    """An install from before keeps pycti, which nothing uses any more: its
    own unmet requirements don't fail the check, and it isn't removed."""
    run = _run(tmp_path, mode, {**CLEAN, "pycti": "6.9.29"}, conflict=PYCTI_CONFLICT)
    assert run.returncode == 0, run.stderr
    assert not run.removed
    assert "conflict" not in run.stderr


FASTAPI_CONFLICT = (
    "The package `fastapi` requires `starlette>=0.40.0,<0.51.0`, but `1.7.0` is"
    " installed"
)


@pytest.mark.parametrize("mode", ["--strict", "--final"])
def test_what_pycti_brought_in_doesn_t_fail_the_check_either(tmp_path, mode):
    """A 0.6.3 OpenCTI install also left pycti's fastapi, whose starlette pin
    the lock's starlette doesn't meet: still only leftovers, so it passes."""
    run = _run(tmp_path, mode, {**CLEAN, "pycti": "6.9.29", "fastapi": "0.115.0"},
               requires={"pycti": ["fastapi"]},  # as pycti 6 declares it
               conflict=PYCTI_CONFLICT + "\n" + FASTAPI_CONFLICT)  # fmt: skip
    assert run.returncode == 0, run.stderr
    assert not run.removed and "conflict" not in run.stderr
    if mode == "--final":
        assert _commands(run) == [["pycti", "fastapi"]]


def test_what_pycti_brought_in_is_never_advised_away_when_something_else_uses_it(
    tmp_path,
):
    """fastapi also required by a package installed by hand: still tolerated,
    but left out of the uninstall line and named with what requires it."""
    run = _run(tmp_path, "--final",
               {**CLEAN, "pycti": "6.9.29", "fastapi": "0.115.0", "my-api": "1.0",
                "transformers": "5.19.0"},
               requires={"pycti": ["fastapi"], "my-api": ["fastapi>=0.100"],
                         "transformers": ["fastapi ; extra == 'serving'"]},
               conflict=PYCTI_CONFLICT + "\n" + FASTAPI_CONFLICT)  # fmt: skip
    assert run.returncode == 0, run.stderr
    assert not run.removed
    lines = run.stdout.splitlines()
    assert (
        "  fastapi: also required by my-api; its own requirements aren't met" in lines
    )
    assert not [x for x in lines if "uninstall" in x and "fastapi" in x]


def test_a_package_asking_for_fastapi_only_with_an_extra_doesn_t_count_as_using_it(
    tmp_path,
):
    """As on a real 0.6.3+OpenCTI venv: chromadb, huggingface_hub, sse-starlette
    and transformers name fastapi only under extras, so it's pycti's alone and
    the command removes it with pycti."""
    extras = {"chromadb": "dev", "huggingface-hub": "oauth",
              "sse-starlette": "examples", "transformers": "serving"}  # fmt: skip
    run = _run(tmp_path, "--final",
               {**CLEAN, "pycti": "6.9.29", "fastapi": "0.124.4",
                **{n: "1.0" for n in extras}},
               requires={"pycti": ["fastapi<0.125.0,>=0.124.0"],
                         **{n: [f"fastapi>=0.115 ; extra == '{e}'"] for n, e in extras.items()}},
               conflict=PYCTI_CONFLICT + "\n" + FASTAPI_CONFLICT)  # fmt: skip
    assert run.returncode == 0, run.stderr
    assert _commands(run) == [["pycti", "fastapi"]]
    assert "also required by" not in run.stdout


def test_a_conflict_in_a_locked_package_still_fails_beside_leftovers(tmp_path):
    locked = next(iter(CLEAN))
    run = _run(tmp_path, "--final", {**CLEAN, "pycti": "6.9.29", "fastapi": "0.115.0"},
               requires={"pycti": ["fastapi"]}, conflict=PYCTI_CONFLICT + "\n" + FASTAPI_CONFLICT + "\n"
               f"The package `{locked}` requires `y<2`, but `2.0` is installed")  # fmt: skip
    assert run.returncode == 1 and "installed packages conflict" in run.stderr


def test_final_names_a_leftover_pycti_6_and_how_to_remove_it(tmp_path):
    run = _run(
        tmp_path, "--final", {**CLEAN, "pycti": "6.9.29"}, conflict=PYCTI_CONFLICT
    )
    note = [x for x in run.stdout.splitlines() if "no longer needed" in x]
    assert len(note) == 1, run.stdout
    assert "pycti 6.9.29 is installed but no longer needed" in note[0]
    assert "pycti 6 requires starlette and uvicorn below the lock's versions" in note[0]
    assert note[0].endswith(f"uv pip uninstall --python {sys.executable} pycti")


def test_final_names_a_leftover_pycti_7_without_the_pycti_6_hold(tmp_path):
    run = _run(tmp_path, "--final", {**CLEAN, "pycti": "7.261002.0"})
    assert run.returncode == 0, run.stderr
    (note,) = [x for x in run.stdout.splitlines() if "no longer needed" in x]
    assert "pycti 7.261002.0 is installed but no longer needed" in note
    assert "below the lock" not in note


def test_strict_says_nothing_about_a_leftover_pycti(tmp_path):
    run = _run(tmp_path, "--strict", {**CLEAN, "pycti": "6.9.29"})
    assert run.returncode == 0, run.stderr
    assert "no longer needed" not in run.stdout


@pytest.mark.parametrize("mode", ["--strict", "--final"])
def test_another_conflict_beside_a_leftover_pycti_still_fails(tmp_path, mode):
    run = _run(
        tmp_path,
        mode,
        {**CLEAN, "pycti": "6.9.29", OTLP: "0.66b0"},
        requires={"pycti": [f"{OTLP}; extra == 'otel'"]},
        conflict=PYCTI_CONFLICT + "\n" + OTLP_CONFLICT,
    )
    assert run.returncode == 1 and OTLP in run.stderr
    assert not run.removed


@pytest.mark.parametrize("mode", ["--strict", "--final"])
def test_a_check_that_fails_unreadably_still_fails_with_pycti(tmp_path, mode):
    run = _run(tmp_path, mode, {**CLEAN, "pycti": "6.9.29"}, pip_check_ok=False)
    assert run.returncode == 1 and run.pip_checked


@pytest.mark.parametrize("mode", ["--strict", "--final"])
def test_drift_still_fails_with_a_leftover_pycti(tmp_path, mode):
    run = _run(tmp_path, mode, {**CLEAN, "starlette": "0.50.0", "pycti": "6.9.29"})
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
    # A loud block on stderr: named with its version, and how to put it back
    # if it was the user's own, and that the next run takes it out again.
    assert f"{OTLP}==0.66b0" not in run.stdout
    rule = "  " + "=" * 66
    lines = run.stderr.splitlines()
    block = lines[lines.index(rule) + 1 : len(lines) - lines[::-1].index(rule) - 1]
    assert (
        block[0]
        == f"  REMOVED {OTLP}==0.66b0: it conflicted with the dependency lock and nothing installed needs it."
    )
    assert "the next install or update removes it again" in block[1]
    assert block[2] == f"    uv pip install --python {sys.executable} {OTLP}==0.66b0"


def test_strict_keeps_what_an_installed_package_requires(tmp_path):
    """A conflicting package something installed requires is kept."""
    run = _run(
        tmp_path,
        "--strict",
        {**CLEAN, "needs-it": "1.0", OTLP: "0.66b0"},
        requires={"needs-it": [OTLP]},
        conflict=OTLP_CONFLICT,
    )
    assert run.returncode == 1
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


# --- What update offers to remove: pycti and what only it uses ---------------


def _leftovers(tmp_path, dists, requires):
    run = _run(tmp_path, "--opencti-leftovers", dists, requires=requires)
    assert run.returncode == 0, run.stderr
    return run.stdout.split()


def test_the_opencti_leftovers_are_pycti_and_what_only_it_brought_in(tmp_path):
    """As on a real 0.6.3+OpenCTI venv: what only pycti brought in, at any
    depth (outside an extra), is listed: stix2-patterns too, which only stix2
    requires. The lock's packages, a package something else needs, and one
    asked for only under an extra elsewhere are handled each as they are."""
    dists = {**CLEAN, "pycti": "6.9.29", "fastapi": "0.124.4", "stix2": "3.0.1",
             "stix2-patterns": "2.0.0", "pika": "1.3.2", "my-api": "1.0",
             "transformers": "5.19.0", "otel-extra": "1.0"}  # fmt: skip
    requires = {
        "pycti": ["fastapi<0.125.0,>=0.124.0", "stix2>=3", "pika", "starlette<0.51",
                  "otel-extra ; extra == 'otel'"],
        "stix2": ["stix2-patterns"],  # one leftover needing another
        "my-api": ["pika"],  # something else uses pika: never listed
        "transformers": ["fastapi ; extra == 'serving'"],  # only an extra: not a use
    }  # fmt: skip
    assert _leftovers(tmp_path, dists, requires) == [
        "pycti", "fastapi", "stix2", "stix2-patterns"]  # fmt: skip


def test_no_pycti_no_opencti_leftovers(tmp_path):
    assert _leftovers(tmp_path, {**CLEAN, "fastapi": "0.124.4"}, {}) == []


def test_one_kept_for_something_else_keeps_what_it_requires_too(tmp_path):
    """pycti brought a and b; a hand-installed service needs a, and a needs b:
    removing b would break a, so neither is offered."""
    dists = {**CLEAN, "pycti": "6.9.29", "a": "1.0", "b": "1.0", "c": "1.0",
             "service": "1.0"}  # fmt: skip
    requires = {"pycti": ["a", "b", "c"], "service": ["a"], "a": ["b"]}
    assert _leftovers(tmp_path, dists, requires) == ["pycti", "c"]


def test_pycti_isn_t_offered_when_something_else_requires_it(tmp_path):
    dists = {**CLEAN, "pycti": "6.9.29", "fastapi": "0.124.4", "my-intel": "1.0"}
    requires = {"pycti": ["fastapi"], "my-intel": ["pycti>=6"]}
    assert _leftovers(tmp_path, dists, requires) == []


# --- pycti's whole tree: what it brought in, at any depth --------------------

# A 0.6.3+OpenCTI box updated to 0.6.6 (a test bed's venv, pycti 7): pycti
# brought boto3, boto3 brought botocore, and botocore needs python-dateutil
# below the lock's. The conflicts are the ones that stopped its update.
U063 = {
    "requests": "2.34.2",
    "setuptools": "84.2.1",
    "opentelemetry-api": "1.45.1",
    "opentelemetry-sdk": "1.45.1",
    "python-dateutil": "3.0.0",
    "urllib3": "2.8.0",
    "pycti": "7.261002.0",
    "boto3": "1.43.109",
    "botocore": "1.43.109",
    "s3transfer": "0.19.2",
    "jmespath": "1.1.0",
}
# The lock pins the first six; pycti's tree outside the lock is the rest.
U063_LOCK = "# header\n" + "".join(
    f"{n}=={v} \\\n    --hash=sha256:aaaa\n" for n, v in list(U063.items())[:6]
)
U063_REQUIRES = {
    "pycti": ["boto3<1.44,>=1.38.27", "requests<2.34.0,>=2.32.0",
              "setuptools~=82.0.0", "opentelemetry-api~=1.35.0",
              "opentelemetry-sdk~=1.35.0"],
    "boto3": ["botocore<1.44.0,>=1.43.109", "jmespath<2.0.0,>=0.7.1",
              "s3transfer<0.20.0,>=0.19.0"],
    "botocore": ["jmespath<2.0.0,>=0.7.1", "python-dateutil<3.0.0,>=2.1",
                 "urllib3!=2.2.0,<3,>=1.25.4 ; python_version >= '3.10'",
                 "awscrt==0.31.2 ; extra == 'crt'"],
    "s3transfer": ["botocore<2.0a.0,>=1.37.4",
                   "botocore[crt]<2.0a.0,>=1.37.4 ; extra == 'crt'"],
}  # fmt: skip
# Verbatim from the bed's update.log.
U063_CONFLICT = """\
The package `pycti` requires `requests>=2.32.0,<2.34.0`, but `2.34.2` is installed
The package `pycti` requires `setuptools~=82.0.0`, but `84.2.1` is installed
The package `pycti` requires `opentelemetry-api~=1.35.0`, but `1.45.1` is installed
The package `pycti` requires `opentelemetry-sdk~=1.35.0`, but `1.45.1` is installed
The package `botocore` requires `python-dateutil>=2.1,<3.0.0`, but `3.0.0` is installed
"""


def _u063(tmp_path, mode, dists=U063, requires=U063_REQUIRES, conflict=U063_CONFLICT):
    return _run(tmp_path, mode, dists, requires=requires, conflict=conflict,
                lock_text=U063_LOCK)  # fmt: skip


@pytest.mark.parametrize("mode", ["--strict", "--final"])
def test_a_conflict_two_levels_under_pycti_fails_neither_check(tmp_path, mode):
    """pycti -> boto3 -> botocore: botocore's conflict is a leftover's too."""
    run = _u063(tmp_path, mode)
    assert run.returncode == 0, run.stderr
    assert not run.removed and "conflict" not in run.stderr


DEEP_CONFLICT = "The package `c` requires `starlette<1`, but `1.7.0` is installed"


@pytest.mark.parametrize("mode", ["--strict", "--final"])
def test_a_conflict_three_levels_under_pycti_fails_neither_check(tmp_path, mode):
    """pycti -> a -> b -> c: any depth, not pycti's requirements and theirs."""
    run = _run(tmp_path, mode,
               {**CLEAN, "pycti": "7.261002.0", "a": "1.0", "b": "1.0", "c": "1.0"},
               requires={"pycti": ["a"], "a": ["b"], "b": ["c"], "c": ["starlette<1"]},
               conflict=DEEP_CONFLICT)  # fmt: skip
    assert run.returncode == 0, run.stderr
    assert not run.removed and "conflict" not in run.stderr


@pytest.mark.parametrize("mode", ["--strict", "--final"])
def test_a_cycle_under_pycti_ends_and_reaches_past_it(tmp_path, mode):
    """a and b require each other; c is reached only through them."""
    run = _run(tmp_path, mode,
               {**CLEAN, "pycti": "7.261002.0", "a": "1.0", "b": "1.0", "c": "1.0"},
               requires={"pycti": ["a"], "a": ["b"], "b": ["a", "c"]},
               conflict=DEEP_CONFLICT)  # fmt: skip
    assert run.returncode == 0, run.stderr


@pytest.mark.parametrize("mode", ["--strict", "--final"])
def test_what_comes_only_through_a_locked_package_is_not_pycti_s(tmp_path, mode):
    """pycti -> starlette (the lock's) -> x: x is the lock's dependency's, so
    its conflict fails as any other."""
    run = _run(tmp_path, mode, {**CLEAN, "pycti": "7.261002.0", "x": "1.0"},
               requires={"pycti": ["starlette"], "starlette": ["x"]},
               conflict="The package `x` requires `uvicorn<0.50`, but `0.54.0` is installed")  # fmt: skip
    assert run.returncode == 1 and "installed packages conflict" in run.stderr


@pytest.mark.parametrize("mode", ["--strict", "--final"])
def test_a_locked_package_s_conflict_in_pycti_s_tree_still_fails(tmp_path, mode):
    """urllib3 is botocore's, but the lock's: its conflict is never a leftover's."""
    conflict = U063_CONFLICT + (
        "The package `urllib3` requires `brotli>=1.2`, but `1.0` is installed\n"
    )
    run = _u063(tmp_path, mode, conflict=conflict)
    assert run.returncode == 1 and "`urllib3` requires" in run.stderr


@pytest.mark.parametrize("mode", ["--strict", "--final"])
def test_the_user_s_own_conflict_still_fails_beside_pycti_s_tree(tmp_path, mode):
    """my-app requires my-tool, so --strict doesn't remove it either."""
    conflict = U063_CONFLICT + (
        "The package `my-tool` requires `urllib3<2`, but `2.8.0` is installed\n"
    )
    run = _u063(tmp_path, mode, {**U063, "my-tool": "1.0", "my-app": "1.0"},
                {**U063_REQUIRES, "my-tool": ["urllib3<2"], "my-app": ["my-tool"]},
                conflict)  # fmt: skip
    assert run.returncode == 1 and "`my-tool` requires" in run.stderr


def _commands(run):
    """The uninstall commands --final prints that name pycti, as name lists."""
    return [x.split("uv pip uninstall --python ", 1)[1].split()[1:]
            for x in run.stdout.splitlines()
            if "uv pip uninstall" in x and "pycti" in x.split()]  # fmt: skip


def test_final_prints_one_command_for_pycti_s_whole_tree(tmp_path):
    """The same list update offers, conflicting or not (boto3 conflicts with
    nothing); the CUDA command is separate."""
    run = _u063(tmp_path, "--final")
    leftovers = _check(tmp_path, "--opencti-leftovers").stdout.split()
    assert _commands(run) == [leftovers]
    assert leftovers == ["pycti", "boto3", "botocore", "jmespath", "s3transfer"]


def test_final_leaves_out_of_the_command_what_something_else_requires(tmp_path):
    run = _u063(tmp_path, "--final", {**U063, "my-s3": "1.0"},
                {**U063_REQUIRES, "my-s3": ["s3transfer"]})  # fmt: skip
    assert _commands(run) == [["pycti", "boto3"]]
    lines = run.stdout.splitlines()
    assert "  s3transfer: also required by my-s3" in lines
    # Kept for what is kept, and botocore's own requirement isn't met.
    assert (
        "  botocore: also required by s3transfer; its own requirements aren't met"
        in lines
    )
    assert "  jmespath: also required by botocore" in lines


def test_final_offers_nothing_for_a_pycti_something_else_requires(tmp_path):
    run = _u063(tmp_path, "--final", {**U063, "my-intel": "1.0"},
                {**U063_REQUIRES, "my-intel": ["pycti>=7"]})  # fmt: skip
    assert run.returncode == 0, run.stderr
    assert _commands(run) == []
    (note,) = [x for x in run.stdout.splitlines() if "pycti 7.261002.0" in x]
    assert note.endswith(
        "also required by my-intel, so nothing is offered for removal."
    )


@pytest.mark.parametrize(
    "dists, requires, conflict, lock",
    [
        (U063, U063_REQUIRES, U063_CONFLICT, U063_LOCK),
        ({**CLEAN, "pycti": "6.9.29", "fastapi": "0.115.0"}, {"pycti": ["fastapi"]},
         PYCTI_CONFLICT + "\n" + FASTAPI_CONFLICT, LOCK),
    ],
    ids=["pycti-7", "pycti-6"],
)  # fmt: skip
def test_running_the_printed_command_leaves_the_next_check_passing(
    tmp_path, dists, requires, conflict, lock
):
    """What a user does with the advice: the command, then the next update,
    which has nothing left to remove."""
    run = _run(tmp_path, "--final", dists, requires=requires, conflict=conflict,
               lock_text=lock)  # fmt: skip
    (command,) = _commands(run)
    uv = [str(tmp_path / "bin" / "uv"), "pip", "uninstall", "--python", sys.executable]
    subprocess.run([*uv, *command], check=True)
    run = _check(tmp_path, "--strict")
    assert run.returncode == 0, run.stderr
    assert not run.removed, run.removed
    assert not list((tmp_path / "site").glob("pycti-*"))


# --- The shipped lock --------------------------------------------------------

DEPS = Path(__file__).parent.parent / "deps"


# Each lock as 0.6.6's refresh made it (sha256), and the one change since: the
# hold, which brings back 2.9.0.post0 and drops tzdata (only 3.0.0 needs it).
REFRESHED = {
    "vhir.lock": "35dd09328e2dfc603f517930232913e37602516ede3bf382b290d734e9a5b224",
    "vhir-cpu.lock": "b6d3441913c17e9cf9267ed2daf156e65677b78b6dadfe2630214cd8d0f15425",
}
HELD = "# held            python-dateutil<3\n"
DATEUTIL = """\
python-dateutil=={} \\
    --hash=sha256:{}
    --hash=sha256:{}
    # via
{}    #   kubernetes
"""
DATEUTIL_HELD = DATEUTIL.format(
    "2.9.0.post0",
    "37dd54208da7e1cd875388217d5e00ebd4179249f90fb72437e91a35459a0ad3 \\",
    "a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427",
    "    #   -c holds.txt\n",
)
DATEUTIL_3 = DATEUTIL.format(
    "3.0.0",
    "3c79630202e4152c6add678446984236efe4f57e84d8e892aab0637bab82e9fd \\",
    "7ebcb3c29a92f3ceafe79a7a48a5c45677e9e004bbeec5742ac0bbb00560b7a2",
    "",
)
TZDATA = """\
tzdata==2026.5 \\
    --hash=sha256:8cc73c0a0bfca7dbfa59235d60b2eff82231dee33f53d206db1acd9173cfc0a7 \\
    --hash=sha256:b683bd1b6659ddcd810ff02ad09ba821d4bf1065072805063eb35c49617905ac
    # via python-dateutil
"""


@pytest.mark.parametrize("lock", ["vhir.lock", "vhir-cpu.lock"])
def test_the_shipped_lock_holds_python_dateutil_below_3(lock):
    """Every release before 0.6.6 shipped 2.9.0.post0. A box that removed pycti
    alone (0.6.4's advice) or took 0.6.4's offer keeps botocore, which needs
    <3, and nothing can tell it was pycti's any more. Lift the hold only once
    such leftovers are handled. Undoing the hold must give back the refreshed
    lock exactly: a regen that moves anything else fails here."""
    text = (DEPS / lock).read_text()
    assert text.count(HELD) == 1 and text.count(DATEUTIL_HELD) == 1
    assert "\ntzdata==" not in text
    undone = text.replace(HELD, "").replace(DATEUTIL_HELD, DATEUTIL_3)
    undone = undone.replace("unicodecsv==", TZDATA + "unicodecsv==", 1)
    assert hashlib.sha256(undone.encode()).hexdigest() == REFRESHED[lock]
    holds = re.search(r"^HOLDS=\((.*)\)$", (DEPS / "regen-lock.sh").read_text(), re.M)
    assert holds and '"python-dateutil<3"' in holds.group(1).split()
