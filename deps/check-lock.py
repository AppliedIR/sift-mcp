"""Check a Valhuntir venv against the dependency lock.

Run it with the venv's own python, so the lock's markers are evaluated for
that interpreter:

    <venv>/bin/python deps/check-lock.py --strict   after the locked installs
    <venv>/bin/python deps/check-lock.py --final    after OpenCTI's client

--strict fails when any installed package is at a version other than the
lock's, naming each one and the command that repairs it. --final runs after
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
    differ = {
        n: (v, pins[n]) for n, v in sorted(have.items()) if n in pins and pins[n] != v
    }
    extra = sorted(n for n in have if n not in pins)
    py = sys.executable
    print(f"  Dependency check against {lock} (uv {_uv_version()})", flush=True)

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
    if not failed:
        print(
            f"  Dependencies match the lock: {len(have) - len(extra) - len(differ)} packages"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
