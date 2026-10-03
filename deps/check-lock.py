"""Check a Valhuntir venv against the dependency lock.

Run it with the venv's own python, so the lock's markers are evaluated for
that interpreter:

    <venv>/bin/python deps/check-lock.py --installed  before the first locked install
    <venv>/bin/python deps/check-lock.py --strict     after the locked installs
    <venv>/bin/python deps/check-lock.py --final      after OpenCTI's client
    <venv>/bin/python deps/check-lock.py --cuda-leftovers

--cuda-leftovers prints the CUDA-family packages (nvidia-*, cuda-*, triton)
the lock doesn't pin and nothing outside them requires, one "name bytes" line
each, requirers first: what a switch to CPU PyTorch leaves behind. --final
prints them with their size and the commands that remove them; nothing here
deletes them (`vhir update` offers to, asking first).

--installed prints the installed packages the lock names (pip's seeds, what
an earlier OpenCTI install pulled in). The first locked install takes them
as requirements, so -c moves them to the lock along with everything it
installs; nothing else would touch them.

The contract for every caller (setup-sift.sh, quickstart-lite.sh, `vhir
update`): --strict passes immediately before the unlocked OpenCTI step, and
--final runs right after it.

--strict first removes leftovers: packages `uv pip check` names that are
installed, not editable, not in the lock, and required by no installed
package (under any marker). An earlier install's plugin for a version the
lock moved away from is one; each removed is named. Then it fails when any
installed package is at a version other than the lock's, naming each one
and the command that repairs it. --final runs after
the unlocked OpenCTI step, and what pycti moved is listed for information;
without pycti, any difference from the lock still fails. Both run `uv pip
check`, which must pass, except --strict while pycti is installed: between
the locked step and the OpenCTI step its requirements may be unmet. Both list
installed packages the lock doesn't name, for information.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import re
import shlex
import subprocess
import sys
import sysconfig
from pathlib import Path

try:
    from packaging.markers import Marker
except ImportError:  # not every venv has packaging; pip's copy is the same code
    from pip._vendor.packaging.markers import Marker

PIN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)\s*(?:;\s*([^\\]+?))?\s*\\?$"
)
# pycti 6 requires these below the lock's versions.
PYCTI6_HOLDS = ("starlette", "uvicorn", "setuptools")
# What GPU PyTorch brings; the CPU build needs none of it.
CUDA_FAMILY = re.compile(r"^(nvidia-.+|cuda-.+|triton)$")


def _name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def locked_versions(lock: Path) -> dict[str, str]:
    """The lock's version of each package, for this interpreter."""
    pins = {}
    for line in lock.read_text().splitlines():
        m = PIN.match(line)
        if m and (m.group(3) is None or Marker(m.group(3)).evaluate()):
            pins[_name(m.group(1))] = m.group(2)
    return pins


def _editable(dist: importlib.metadata.Distribution) -> bool:
    try:
        url = json.loads(dist.read_text("direct_url.json") or "{}")
    except ValueError:
        return False
    return bool(url.get("dir_info", {}).get("editable"))


def installed_versions(site: list[str]) -> dict[str, str]:
    """Every non-editable package in the venv (the first-party ones are editable)."""
    found = {}
    for dist in importlib.metadata.distributions(path=site):
        name = dist.metadata["Name"]
        if name and not _editable(dist):
            found.setdefault(_name(name), dist.version)
    return found


def _required_names(site: list[str]) -> set[str]:
    """Every name any installed package requires, under any marker or extra."""
    names = set()
    for dist in importlib.metadata.distributions(path=site):
        for req in dist.requires or []:
            m = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", req)
            if m:
                names.add(_name(m.group(0)))
    return names


def _cpu_lock(lock: Path) -> bool:
    """The CPU-PyTorch variant (regen-lock.sh marks it in the header)."""
    return any(
        x.startswith("# variant") and " cpu" in x for x in lock.read_text().splitlines()
    )


def cuda_leftovers(site: list[str], pins: dict[str, str], have: dict) -> list[str]:
    """CUDA-family packages the lock doesn't pin and that no installed package
    outside the set requires (repeated until stable), requirers first, so
    stopping a single uninstall partway still leaves consistent requirements."""
    reqs: dict[str, set[str]] = {}
    for dist in importlib.metadata.distributions(path=site):
        if dist.metadata["Name"]:
            names = reqs.setdefault(_name(dist.metadata["Name"]), set())
            for req in dist.requires or []:
                m = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", req)
                if m:
                    names.add(_name(m.group(0)))
    left = {n for n in have if CUDA_FAMILY.match(n) and n not in pins}
    while True:
        needed = {r for n, rs in reqs.items() if n not in left for r in rs}
        if not left & needed:
            break
        left -= needed
    order = []
    while left:
        inner = {r for n in left for r in reqs.get(n, ())}
        step = sorted(left - inner) or sorted(left)  # a cycle: any order
        order += step
        left -= set(step)
    return order


def _size(site: list[str], names: list[str]) -> int:
    """Bytes the named packages' RECORDs list."""
    total = 0
    for dist in importlib.metadata.distributions(path=site):
        if dist.metadata["Name"] and _name(dist.metadata["Name"]) in names:
            total += sum(f.size or 0 for f in dist.files or [])
    return total


def remove_leftovers(site: list[str], pins: dict[str, str], have: dict) -> list[str]:
    """Uninstall what conflicts, isn't the lock's and nothing needs."""
    check = subprocess.run(
        ["uv", "pip", "check", "--python", sys.executable],
        capture_output=True,
        text=True,
    )
    named = {
        _name(n)
        for n in re.findall(
            r"The package `([^`]+)` requires `[^`]+`, but `[^`]+` is installed",
            check.stdout + check.stderr,
        )
    }
    stale = sorted((named & set(have)) - set(pins) - _required_names(site))
    if stale:
        subprocess.run(
            ["uv", "pip", "uninstall", "--python", sys.executable, *stale], check=True
        )
        # It may be the user's own package: say how to put it back.
        specs = [f"{n}=={have[n]}" for n in stale]
        rule = "=" * 66
        print(
            f"\n  {rule}\n  REMOVED {', '.join(specs)}: it conflicted with the"
            " dependency lock and nothing installed needs it.\n  If you added it"
            " yourself, reinstall it (this moves locked packages off the lock, and"
            " the next install or update removes it again):\n"
            f"    uv pip install --python {shlex.quote(sys.executable)}"
            f" {' '.join(shlex.quote(x) for x in specs)}\n  {rule}",
            file=sys.stderr,
            flush=True,
        )
    return stale


def _uv_version() -> str:
    try:
        out = subprocess.run(
            ["uv", "--version"], capture_output=True, text=True, timeout=30
        )
        return out.stdout.split()[1] if out.returncode == 0 else "unknown"
    except (OSError, IndexError, subprocess.SubprocessError):
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--strict", action="store_true")
    mode.add_argument("--final", action="store_true")
    mode.add_argument("--installed", action="store_true")
    mode.add_argument("--cuda-leftovers", action="store_true")
    parser.add_argument(
        "--lock", type=Path, default=Path(__file__).with_name("vhir.lock")
    )
    # The site-packages to read; the running interpreter's by default.
    parser.add_argument("--site", action="append")
    args = parser.parse_args(argv)

    lock = args.lock.resolve()
    site = args.site or sorted(
        {sysconfig.get_paths()["purelib"], sysconfig.get_paths()["platlib"]}
    )
    pins = locked_versions(lock)
    have = installed_versions(site)
    if args.installed:
        print(" ".join(sorted(n for n in have if n in pins)))
        return 0
    if args.cuda_leftovers:
        for n in cuda_leftovers(site, pins, have):
            print(n, _size(site, [n]))
        return 0
    print(f"  Dependency check against {lock} (uv {_uv_version()})", flush=True)
    if args.strict and remove_leftovers(site, pins, have):
        have = installed_versions(site)
    differ = {
        n: (v, pins[n]) for n, v in sorted(have.items()) if n in pins and pins[n] != v
    }
    extra = sorted(n for n in have if n not in pins)
    py = sys.executable

    failed = False
    pycti = have.get("pycti")
    if args.final or not pycti:
        check = subprocess.run(
            ["uv", "pip", "check", "--python", py], capture_output=True, text=True
        )
        if check.returncode != 0:
            print(
                "  DEPENDENCY CHECK FAILED: installed packages conflict:",
                file=sys.stderr,
            )
            print((check.stdout + check.stderr).rstrip(), file=sys.stderr)
            failed = True

    if differ and args.final and pycti:
        print(
            f"  Held at other versions by OpenCTI's client (pycti {pycti}), outside the lock:"
        )
        for n, (v, want) in differ.items():
            print(f"    {n} {v} (lock {want})")
        held = [n for n in PYCTI6_HOLDS if n in differ]
        if pycti.split(".")[0] == "6" and held:
            risk = (
                ", and the starlette versions it allows have known security advisories"
                if "starlette" in held
                else ""
            )
            print(
                f"  pycti 6 holds {', '.join(held)} below the lock{risk}."
                " Upgrading OpenCTI (server and pycti) to 7.x removes the hold."
            )
    elif differ:
        print(
            f"  DEPENDENCY CHECK FAILED: {len(differ)} package(s) differ from the lock:",
            file=sys.stderr,
        )
        for n, (v, want) in differ.items():
            print(f"    {n} installed {v}, lock {want}", file=sys.stderr)
        repair = " ".join(
            shlex.quote(f"{n}=={want}") for n, (_, want) in differ.items()
        )
        # 2.14.0+cpu satisfies ==2.14.0, and the CPU lock's torch is on the
        # PyTorch index: without these the line repairs nothing.
        repair += "".join(f" --reinstall-package {shlex.quote(n)}" for n in differ)
        if _cpu_lock(lock):
            repair += " --torch-backend cpu"
        print("  Repair:", file=sys.stderr)
        print(
            f"    uv pip install --python {shlex.quote(py)} -c {shlex.quote(str(lock))}"
            f" -b {shlex.quote(str(lock))} {repair}",
            file=sys.stderr,
        )
        failed = True

    if extra:
        print(
            f"  Installed but not in the lock (earlier installs or added by hand): {', '.join(extra)}"
        )
    leftovers = cuda_leftovers(site, pins, have) if args.final else []
    if leftovers:
        names = " ".join(shlex.quote(n) for n in leftovers)
        # The venv's files are links into uv's cache: the disk comes back
        # only once the cache copies go too. Only these names: cleaning
        # torch's would break a venv that links its CPU torch into the cache.
        print(
            "  CUDA-family packages this lock doesn't install (check none are"
            f" yours): {', '.join(leftovers)}"
            f" ({_size(site, leftovers) / 1e9:.1f} GB in the venv, freed on disk only"
            " after the cache clean). Nothing removed them; to remove them:\n"
            f"    uv pip uninstall --python {shlex.quote(py)} {names}\n"
            f"    uv cache clean {names}"
        )
    if not failed:
        print(
            f"  Dependencies match the lock: {len(have) - len(extra) - len(differ)} packages"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
