"""The installer installs the Eric Zimmerman's tools sift-mcp calls that SIFT lacks.

Only what is missing is installed, in SIFT's layout, and nothing already there is
replaced. These run the installer's own lines with /opt/zimmermantools and
/usr/local/bin moved into a temp folder and curl, sudo, apt-get and dotnet stubbed,
never the installer.
"""

from __future__ import annotations

import hashlib
import subprocess
import zipfile
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
_start = SCRIPT.index("# Phase 5c: Eric Zimmerman's Tools")
PHASE = SCRIPT[_start : SCRIPT.index("# Phase 6: Examiner Identity", _start)]
_sum = SCRIPT.index('if [[ -n "$EZ_FAILED" ]]; then')
SUMMARY = SCRIPT[_sum : SCRIPT.index("\nfi\n", _sum) + 4]

URL = "https://download.ericzimmermanstools.com/net"
TOOLS = [
    "AmcacheParser",
    "PECmd",
    "AppCompatCacheParser",
    "RECmd",
    "MFTECmd",
    "EvtxECmd",
    "JLECmd",
    "LECmd",
    "SBECmd",
    "RBCmd",
    "SQLECmd",
    "bstrings",
]
# the three the vendor ships in a folder, under the folder's name
FOLDER = {"RECmd": "RECmd", "EvtxECmd": "EvtxeCmd", "SQLECmd": "SQLECmd"}
WRAPPER = '#!/bin/bash\nexec dotnet {} "$@"\n'

STUBS = {
    "curl": """#!/bin/bash
echo "curl $*" >> "$STATE/calls"
out=""; prev=""
for a in "$@"; do [[ "$prev" == -o ]] && out=$a; prev=$a; done
url=${!#}; src="$EZ_FIX/${url##*/}"
[[ -f "$src" ]] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
cp "$src" "$out"
""",
    "sudo": """#!/bin/bash
echo "sudo $*" >> "$STATE/calls"
exec "$@"
""",
    "apt-get": """#!/bin/bash
echo "apt-get $*" >> "$STATE/calls"
[[ -e "$STATE/apt-ok" ]] || { echo "E: Unable to locate package dotnet-runtime-10.0"; exit 100; }
touch "$STATE/net10"
""",
    "dotnet": """#!/bin/bash
if [[ "$1" == --list-runtimes ]]; then
    echo "Microsoft.NETCore.App 9.0.23 [/usr/lib/dotnet/shared/Microsoft.NETCore.App]"
    [[ -e "$STATE/net10" ]] && echo "Microsoft.NETCore.App 10.0.15 [/usr/lib/dotnet/x]"
    exit 0
fi
printf '%s\\n' "$@" > "$STATE/dotnet-args"
if [[ "$2" == --help ]]; then
    [[ -e "$STATE/help-fails" ]] && { echo "Unhandled exception. Bad image"; exit 134; }
    n=${1##*/}; echo "${n%.dll} version 1.2.3.0"
fi
""",
}


def _zip(path: Path, names: list[str]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for n in names:
            z.writestr(n, f"bytes of {n}\n")
    return path


def _tool_zip(fix: Path, tool: str) -> Path:
    d = f"{FOLDER[tool]}/" if tool in FOLDER else ""
    return _zip(fix / f"{tool}.zip", [f"{d}{tool}.dll", f"{d}{tool}.deps.json"])


def _dll(opt: Path, tool: str) -> Path:
    if tool in FOLDER:
        return opt / FOLDER[tool] / f"{tool}.dll"
    return opt / f"{tool}.dll"


def _tree(*roots: Path) -> dict:
    return {
        str(p): (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
        for r in roots
        for p in sorted(r.rglob("*"))
        if p.is_file()
    }


class Box:
    """A temp /opt/zimmermantools, /usr/local/bin and the stubs' state."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.opt = tmp / "opt"
        self.bin = tmp / "bin"
        self.fix = tmp / "fix"
        self.state = tmp / "state"
        self.stubs = tmp / "stubs"
        for d in (self.opt, self.bin, self.fix, self.state, self.stubs, tmp / "tmp"):
            d.mkdir()
        for name, body in STUBS.items():
            (self.stubs / name).write_text(body)
            (self.stubs / name).chmod(0o755)
        (self.state / "net10").touch()
        for t in TOOLS:
            _tool_zip(self.fix, t)

    def place_sift(self, tools=TOOLS, dlls=True):
        """SIFT's own layout: its dll and its two `${*}` wrappers per tool."""
        for t in tools:
            dll = _dll(self.opt, t)
            if dlls:
                dll.parent.mkdir(parents=True, exist_ok=True)
                dll.write_text(f"SIFT's {t}.dll\n")
            for w in (t, t.lower()):
                (self.bin / w).write_text(f"#!/bin/bash\ndotnet {dll} ${{*}}\n")
                (self.bin / w).chmod(0o755)

    def calls(self) -> list[str]:
        f = self.state / "calls"
        return f.read_text().splitlines() if f.exists() else []

    def run(self, install=True, answer="y", platform="Linux"):
        phase = PHASE.replace("EZ_DIR=/opt/zimmermantools", f"EZ_DIR={self.opt}")
        phase = phase.replace("EZ_BIN=/usr/local/bin", f"EZ_BIN={self.bin}")
        assert str(self.opt) in phase and str(self.bin) in phase
        harness = "\n".join(
            [
                "set -euo pipefail",
                'info(){ echo "[INFO] $*"; }; ok(){ echo "[OK] $*"; }',
                'err(){ echo "[ERROR] $*"; }; warn(){ echo "[WARN] $*"; }',
                'header(){ echo "=== $* ==="; }',
                f'prompt_yn(){{ echo "[ASK] $1"; [[ {answer} == y ]]; }}',
                f"PLATFORM={platform}; INSTALL_EZ={str(install).lower()}",
                "INSTALL_ERRORS=0",
                phase,
                SUMMARY,
                'echo "failed=$EZ_FAILED"; echo "errors=$INSTALL_ERRORS"',
            ]
        )
        out = subprocess.run(
            ["bash", "-c", harness],
            env={
                "PATH": f"{self.stubs}:{self.bin}:/usr/bin:/bin",
                "HOME": str(self.tmp),
                "TMPDIR": str(self.tmp / "tmp"),
                "STATE": str(self.state),
                "EZ_FIX": str(self.fix),
            },
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert out.returncode == 0, out.stdout + out.stderr
        return out.stdout.splitlines()


@pytest.fixture
def box(tmp_path):
    return Box(tmp_path)


def test_the_phase_comes_before_the_examiner_and_failures_reach_the_summary():
    assert _start < SCRIPT.index("# Phase 6: Examiner Identity") < _sum
    assert SCRIPT.index("INSTALL_EZ=true") < _start
    assert "INSTALL_ERRORS=$((INSTALL_ERRORS + 1))" in SUMMARY
    assert "        --no-ez-tools)     INSTALL_EZ=false ;;" in SCRIPT


def test_what_is_missing_is_installed_in_sifts_layout(box):
    lines = box.run()
    assert lines[-2:] == ["failed=", "errors=0"]
    assert sum(ln.startswith("[OK] ") for ln in lines) == len(TOOLS)
    manifest = (box.opt / "valhuntir-manifest.tsv").read_text().splitlines()
    assert len(manifest) == len(TOOLS)
    for t, row in zip(TOOLS, manifest, strict=True):
        dll = _dll(box.opt, t)
        assert dll.read_text() == f"bytes of {dll.relative_to(box.opt)}\n"
        for w in (t, t.lower()):
            assert (box.bin / w).read_text() == WRAPPER.format(dll)
            assert (box.bin / w).stat().st_mode & 0o777 == 0o755
        z = (box.fix / f"{t}.zip").read_bytes()
        sha = hashlib.sha256(z).hexdigest()
        assert row.split("\t")[1:] == [t, f"{URL}/{t}.zip", str(len(z)), sha]
        assert f"[OK] {t}: {dll} (sha256 {sha})" in lines
    assert not [c for c in box.calls() if c.startswith("apt-get")]


def test_srumecmd_is_never_installed_it_runs_only_on_windows(box):
    # SrumECmd exits 1 on any platform but Windows: not fetched even when the
    # vendor serves it, and its absence leaves a SIFT that has the rest alone
    _tool_zip(box.fix, "SrumECmd")
    box.run()
    assert not [c for c in box.calls() if "SrumECmd" in c]
    assert not list(box.opt.rglob("SrumECmd*"))
    assert not list(box.bin.glob("[Ss]rum[Ee][Cc]md"))
    (box.tmp / "fresh").mkdir()
    fresh = Box(box.tmp / "fresh")
    fresh.place_sift()
    _tool_zip(fresh.fix, "SrumECmd")
    assert fresh.run() == ["failed=", "errors=0"]
    assert fresh.calls() == []


def test_a_sift_that_has_them_all_is_left_alone(box):
    box.place_sift()
    before = _tree(box.opt, box.bin)
    assert box.run() == ["failed=", "errors=0"]
    assert _tree(box.opt, box.bin) == before
    assert box.calls() == []


def test_sifts_wrappers_without_their_dlls_get_the_dlls_and_keep_the_wrappers(box):
    # SIFT's release writes its wrappers even when its download fails, and it never
    # installs PECmd
    box.place_sift([t for t in TOOLS if t != "PECmd"], dlls=False)
    wrappers = _tree(box.bin)
    lines = box.run()
    assert lines[-2:] == ["failed=", "errors=0"]
    assert {k: v for k, v in _tree(box.bin).items() if k in wrappers} == wrappers
    for t in TOOLS:
        assert _dll(box.opt, t).is_file()
    assert (box.bin / "PECmd").read_text() == WRAPPER.format(box.opt / "PECmd.dll")


def test_a_file_already_in_the_tools_folder_is_never_replaced(box):
    keep = box.opt / "PECmd.deps.json"
    keep.write_text("the one already there\n")
    lines = box.run()
    assert lines[-2:] == ["failed=", "errors=0"]
    assert keep.read_text() == "the one already there\n"
    assert (box.opt / "PECmd.dll").read_text() == "bytes of PECmd.dll\n"


def test_a_dll_without_its_wrapper_gets_the_wrapper_only(box):
    box.place_sift()
    for w in ("RECmd", "recmd"):
        (box.bin / w).unlink()
    opt = _tree(box.opt)
    assert box.run() == ["=== Eric Zimmerman's Tools ===", *_ask_ok("RECmd", box)]
    assert _tree(box.opt) == opt
    assert not [c for c in box.calls() if c.startswith("curl")]
    dll = box.opt / "RECmd" / "RECmd.dll"
    assert (box.bin / "recmd").read_text() == WRAPPER.format(dll)


def _ask_ok(tool, box):
    return [
        f"[ASK] Install Eric Zimmerman's tools that are missing: {tool}"
        " (up to 45 MB, and .NET 10; requires sudo)?",
        f"[OK] {tool}: {_dll(box.opt, tool)}",
        "failed=",
        "errors=0",
    ]


def test_the_folder_is_found_whatever_its_case(box):
    box.place_sift(["EvtxECmd"], dlls=False)
    (box.opt / "evtxecmd").mkdir()
    (box.opt / "evtxecmd" / "EvtxECmd.dll").write_text("SIFT's\n")
    box.run()
    assert not (box.opt / "EvtxeCmd").exists()
    assert not [c for c in box.calls() if "EvtxECmd.zip" in c]


def test_a_second_run_changes_nothing(box):
    box.run()
    before = _tree(box.opt, box.bin)
    calls = len(box.calls())
    assert box.run() == ["failed=", "errors=0"]
    assert _tree(box.opt, box.bin) == before
    assert len(box.calls()) == calls


def test_the_wrapper_keeps_an_argument_with_a_space_whole(box):
    box.run()
    subprocess.run(
        [str(box.bin / "pecmd"), "-f", "/cases/a b/CMD.EXE-1.pf"],
        env={"PATH": f"{box.stubs}:/usr/bin:/bin", "STATE": str(box.state)},
        check=True,
    )
    assert (box.state / "dotnet-args").read_text().splitlines() == [
        f"{box.opt}/PECmd.dll",
        "-f",
        "/cases/a b/CMD.EXE-1.pf",
    ]


def test_a_download_that_fails_is_an_install_error(box):
    (box.fix / "PECmd.zip").unlink()
    lines = box.run()
    assert (
        f"[ERROR] PECmd: download failed ({URL}/PECmd.zip): "
        "curl: (22) The requested URL returned error: 404"
    ) in lines
    assert lines[-2:] == ["failed= PECmd", "errors=1"]
    assert (
        "[ERROR] Eric Zimmerman's tools not installed: PECmd (the errors above say"
        " why), so sift-mcp can't run them. Re-run setup-sift.sh to install them."
    ) in lines
    assert not (box.bin / "PECmd").exists()
    assert not (box.opt / "PECmd.dll").exists()
    assert (box.opt / "bstrings.dll").is_file()


def test_something_that_isnt_a_zip_is_refused(box):
    (box.fix / "PECmd.zip").write_text("<html>Service Unavailable</html>\n")
    lines = box.run()
    assert f"[ERROR] PECmd: {URL}/PECmd.zip isn't a valid zip" in lines
    assert lines[-2:] == ["failed= PECmd", "errors=1"]
    assert not list(box.opt.glob("PECmd*"))
    assert not (box.bin / "PECmd").exists()


@pytest.mark.parametrize(
    "bad", ["../evil.sh", "/tmp/evil.sh", "RECmd/../../evil.sh", "a\\..\\evil.sh"]
)
def test_a_zip_with_a_path_outside_the_folder_is_refused(box, bad):
    _zip(box.fix / "PECmd.zip", ["PECmd.dll", bad])
    lines = box.run()
    refused = f"refused: {URL}/PECmd.zip has a path outside {box.opt}"
    assert f"[ERROR] PECmd: {refused}" in lines
    assert lines[-2:] == ["failed= PECmd", "errors=1"]
    assert not (box.opt / "PECmd.dll").exists()
    assert not [p for p in box.tmp.rglob("*evil*") if p.parent != box.fix]


def test_a_zip_without_the_tools_dll_is_refused(box):
    _zip(box.fix / "PECmd.zip", ["Other.dll"])
    lines = box.run()
    assert f"[ERROR] PECmd: {URL}/PECmd.zip has no PECmd.dll" in lines
    assert not (box.opt / "Other.dll").exists()


def test_a_tool_that_doesnt_run_is_an_install_error(box):
    (box.state / "help-fails").touch()
    lines = box.run()
    dll = box.opt / "PECmd.dll"
    said = f"'dotnet {dll} --help' doesn't run: Unhandled exception. Bad image"
    assert f"[ERROR] PECmd: {said}" in lines
    assert lines[-1] == "errors=1"


def test_without_dotnet_10_the_runtime_is_installed_from_apt(box):
    (box.state / "net10").unlink()
    (box.state / "apt-ok").touch()
    lines = box.run()
    assert "apt-get install -y dotnet-runtime-10.0" in box.calls()
    assert lines[-2:] == ["failed=", "errors=0"]


def test_when_dotnet_10_wont_install_nothing_is_downloaded(box):
    (box.state / "net10").unlink()
    lines = box.run()
    assert "E: Unable to locate package dotnet-runtime-10.0" in lines
    errs = [ln for ln in lines if "dotnet-runtime-10.0 didn't install" in ln]
    assert len(errs) == 1 and errs[0].startswith("[ERROR] ")
    assert lines[-2:] == ["failed= " + " ".join(TOOLS), "errors=1"]
    assert not [c for c in box.calls() if c.startswith("curl")]
    assert _tree(box.opt, box.bin) == {}


@pytest.mark.parametrize(
    "kw, said",
    [
        ({"install": False}, "[INFO] Not installed (--no-ez-tools)."),
        ({"answer": "n"}, "[INFO] Skipped."),
    ],
)
def test_no_ez_tools_or_a_no_installs_nothing(box, kw, said):
    lines = box.run(**kw)
    said += " sift-mcp can't run: AmcacheParser PECmd "
    assert [ln for ln in lines if ln.startswith(said)]
    assert lines[-2:] == ["failed=", "errors=0"]
    assert box.calls() == []
    assert _tree(box.opt, box.bin) == {}


def test_nothing_is_done_on_macos(box):
    assert box.run(platform="Darwin") == ["failed=", "errors=0"]
    assert box.calls() == []
