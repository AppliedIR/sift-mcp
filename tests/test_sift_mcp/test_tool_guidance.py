"""Tool guidance comes from the installed tool.

- Every call to a catalog tool's help, check or run probes the tool that
  actually runs and reports its version and path (`installed_version` /
  `tool_version`, `resolved_path`). A probe that fails says "unknown" and
  what the tool printed; it is never an error. Nothing is cached, so an
  update shows on the next call.
- get_tool_help returns the installed tool's own help (capped inline), the
  catalog's recipes for that version, and says which recipes were tested on
  other versions only. Help is judged on what the tool printed, never on its
  exit code: usage after an error about the way of asking is help (TSK's
  --help, exit 1); an error naming the subcommand asked for is not.
- A tool is found under its binary or a name another version installs it
  under (plaso's log2timeline.py, or log2timeline from pip), and a run's
  version is asked of the binary the command names.
- A run reports what it did: the raw exit code, and `stopped` only when the
  server stopped it (a timeout or the output limit). `success` means the run
  completed; a non-zero exit doesn't make it false, and no exit code is
  translated into a meaning.

The tools are stand-ins on PATH, shaped like the real ones' version and help
behaviour; the server runs in-process on a scratch case under a scratch HOME.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from pathlib import Path

import pytest
from sift_mcp.server import create_server

TSK_HELP = (
    "usage: fls [-adDFlhpruvV] [-f fstype] [-i imgtype] [-b dev_sector_size] "
    "[-m dir/] [-o imgoffset] [-z ZONE] [-s seconds] image [images] [inode]\n"
    "\t-r: Recurse on directory entries\n\t-p: Display full path for each file\n"
)
HAYABUSA_TOP = "Hayabusa v3.9.0 - SecTwo Release\nUsage:\n  hayabusa.exe <COMMAND>\n"
HAYABUSA_CSV_HELP = (
    "Usage: csv-timeline <INPUT> [OPTIONS]\n"
    "  -d, --directory <DIR>  Directory of multiple .evtx files\n"
    "  -o, --output <FILE>    Save the timeline in CSV format\n"
    "  -w, --no-wizard        Do not ask questions\n"
)


def _tool(folder: Path, name: str, body: str) -> Path:
    """A stand-in executable `name` running the shell `body` ($@ its args)."""
    p = folder / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return p


@pytest.fixture
def tools(tmp_path, monkeypatch):
    """Stand-ins first on PATH. fls answers -V only (its --version is an
    error), as TSK does; hayabusa names its version in `help`; vol in
    --version. Each one's version is read from a file, so a test can update
    the tool between two calls."""
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    ver = tmp_path / "versions"
    ver.mkdir()
    (ver / "fls").write_text("4.11.1")
    (ver / "hayabusa").write_text("3.9.0")
    (ver / "vol").write_text("2.26.0")
    _tool(
        bin_,
        "fls",
        f"""case "$1" in
  -V) echo "The Sleuth Kit ver $(cat {ver}/fls)";;
  --version|--help) printf '%s' '{TSK_HELP}' >&2; exit 1;;
  *) echo "r/r 5-128-1: a.txt"; exit "${{FLS_RC:-0}}";;
esac""",
    )
    _tool(
        bin_,
        "hayabusa",
        f"""case "$1 $2" in
  "help "*) echo "Hayabusa v$(cat {ver}/hayabusa) - SecTwo Release"; printf '%s' 'Usage:
  hayabusa.exe <COMMAND>
';;
  "csv-timeline --help") printf '%s' '{HAYABUSA_CSV_HELP}';;
  *) echo "unknown"; exit 2;;
esac""",
    )
    _tool(
        bin_,
        "vol",
        f"""case "$1" in
  --version) echo "Volatility 3 Framework $(cat {ver}/vol)";;
  *) echo "ok";;
esac""",
    )
    monkeypatch.setenv("PATH", f"{bin_}{os.pathsep}{os.environ.get('PATH', '')}")
    return {"bin": bin_, "versions": ver}


@pytest.fixture
def case(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "examiner1")
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    d = tmp_path / "cases" / "case-a"
    (d / "evidence").mkdir(parents=True)
    (d / "extractions").mkdir()
    (d / "CASE.yaml").write_text("case_id: case-a\nstatus: open\n")
    (home / ".vhir" / "active_case").write_text(str(d))
    return d


def _call(tool: str, **args) -> dict:
    r = asyncio.run(create_server().call_tool(tool, args))
    r = r[0] if isinstance(r, tuple) else r
    return json.loads(r[0].text)


def _entries(case: Path, tool: str) -> list[dict]:
    log = case / "audit" / "sift-mcp.jsonl"
    lines = log.read_text().splitlines() if log.exists() else []
    return [e for e in (json.loads(x) for x in lines if x.strip()) if e["tool"] == tool]


# --- the installed version, from what actually runs ------------------


def test_help_names_the_installed_version_and_path(case, tools):
    r = _call("get_tool_help", tool_name="fls")
    assert r["installed_version"] == "4.11.1"  # from -V, after --version failed
    assert r["resolved_path"] == str(tools["bin"] / "fls")


def test_a_tools_own_probe_is_used(case, tools):
    assert _call("get_tool_help", tool_name="hayabusa")["installed_version"] == "3.9.0"
    assert _call("get_tool_help", tool_name="vol3")["installed_version"] == "2.26.0"


def test_check_tools_names_each_version_and_path(case, tools):
    r = _call("check_tools", tool_names=["fls", "vol3"])
    assert r["fls"]["installed_version"] == "4.11.1"
    assert r["fls"]["resolved_path"] == str(tools["bin"] / "fls")
    assert r["vol3"]["installed_version"] == "2.26.0"


def test_a_run_records_the_version_and_path_in_its_reply_and_entry(case, tools):
    r = _call("run_command", command=["fls", str(case / "evidence")], purpose="t")
    assert r["tool_version"] == "4.11.1"
    assert r["resolved_path"] == str(tools["bin"] / "fls")
    (e,) = _entries(case, "run_command")
    assert e["result_summary"]["tool_version"] == "4.11.1"
    assert e["result_summary"]["resolved_path"] == str(tools["bin"] / "fls")


def test_a_large_output_reply_keeps_the_version(case, tools, monkeypatch):
    """The parsed-preview shape replaces the raw result: the keys stay."""
    monkeypatch.setenv("SIFT_RESPONSE_BUDGET", "10")
    r = _call("run_command", command=["fls", str(case / "evidence")], purpose="t")
    assert r["output_format"].startswith("parsed")
    assert r["tool_version"] == "4.11.1"


def test_check_tools_flags_a_version_outside_every_recipes_range(case, tools):
    """hayabusa 9.0 has no recipe (3.x and 4.x do); fls 4.11.1 has one; vol3
    2.26.0 is in its recipes' range."""
    (tools["versions"] / "hayabusa").write_text("9.0.0")
    r = _call("check_tools", tool_names=["hayabusa", "fls", "vol3"])
    assert r["hayabusa"]["outside_tested_ranges"] is True
    assert r["hayabusa"]["tested_ranges"] == [">=3.0,<4", ">=4.0,<5"]
    assert "outside_tested_ranges" not in r["fls"]
    assert "outside_tested_ranges" not in r["vol3"]


def test_an_update_shows_on_the_next_call(case, tools):
    assert _call("get_tool_help", tool_name="fls")["installed_version"] == "4.11.1"
    (tools["versions"] / "fls").write_text("4.12.0")
    assert _call("get_tool_help", tool_name="fls")["installed_version"] == "4.12.0"


def test_a_probe_that_fails_says_unknown_and_what_it_printed(case, tools):
    _tool(tools["bin"], "vol", 'echo "vol: cannot import framework" >&2; exit 3')
    r = _call("get_tool_help", tool_name="vol3")
    assert r["installed_version"] == "unknown"
    assert r["version_output"] == "vol: cannot import framework"
    assert "error" not in r


def test_the_version_is_the_first_one_printed_not_a_usage_number(case, tools):
    """As ewfacquire answers --version: an error, its name and date-stamped
    version, then a usage text holding other numbers (1.4 GiB)."""
    _tool(
        tools["bin"],
        "ewfacquire",
        """printf '%s\\n' "ewfacquire: invalid option -- '-'" \\
  "ewfacquire 20140816" "" "Use ewfacquire to acquire data." \\
  "	-S: segment file size in bytes (default is 1.4 GiB)" >&2; exit 1""",
    )
    assert (
        _call("get_tool_help", tool_name="ewfacquire")["installed_version"]
        == "20140816"
    )


def test_a_command_not_in_the_catalog_has_no_version(case, tools):
    r = _call("run_command", command=["true"], purpose="t")
    assert "tool_version" not in r


def test_probes_write_nothing_to_the_case(case, tools):
    _call("get_tool_help", tool_name="fls")
    _call("check_tools", tool_names=["fls"])
    assert list((case / "extractions").iterdir()) == []
    assert {e["tool"] for e in _entries(case, "get_tool_help")} == {"get_tool_help"}
    log = (case / "audit" / "sift-mcp.jsonl").read_text()
    assert len([x for x in log.splitlines() if x.strip()]) == 1  # help only


# --- the tool's own help -----------------------------------------------


def test_help_is_the_installed_tools_own(case, tools):
    r = _call("get_tool_help", tool_name="fls")
    assert "-r: Recurse on directory entries" in r["help"]  # stderr, rc 1: still help
    assert "common_flags" not in r


def test_long_help_is_cut_and_says_so(case, tools):
    _tool(
        tools["bin"],
        "fls",
        """case "$1" in
  -V) echo "The Sleuth Kit ver 4.11.1";;
  *) i=0; while [ $i -lt 2000 ]; do echo "  -x$i: an option line"; i=$((i+1)); done;;
esac""",
    )
    r = _call("get_tool_help", tool_name="fls")
    assert len(r["help"].encode()) <= 8192
    assert r["help_cut"] is True and "help" in r["help_note"]


def test_the_audit_keeps_no_help_text(case, tools):
    _call("get_tool_help", tool_name="fls")
    (e,) = _entries(case, "get_tool_help")
    text = json.dumps(e)
    assert "Recurse on directory entries" not in text
    assert e["result_summary"]["installed_version"] == "4.11.1"


def test_a_subcommands_help(case, tools):
    r = _call("get_tool_help", tool_name="hayabusa", subcommand="csv-timeline")
    assert "--no-wizard" in r["help"]


@pytest.mark.parametrize("bad", ["--output=/x", "-o", "csv timeline", "../x"])
def test_a_subcommand_that_isnt_a_name_is_refused(case, tools, bad):
    r = _call("get_tool_help", tool_name="hayabusa", subcommand=bad)
    assert "error" in r and "subcommand" in r["error"]
    assert "help" not in r


# --- recipes for the installed version ------------------------------


def test_the_catalog_has_recipes_not_switch_lists():
    from sift_mcp.catalog import load_catalog

    cat = load_catalog()
    assert not any(getattr(td, "common_flags", None) for td in cat.values())
    from packaging.specifiers import SpecifierSet

    for td in cat.values():
        for recipe in td.recipes:
            assert recipe["task"] and isinstance(recipe["argv"], list)
            assert recipe["versions"].strip()  # blank is invalid, not "any"
            SpecifierSet(recipe["versions"])  # a valid range


def test_help_gives_the_recipes_for_the_installed_version(case, tools):
    from packaging.specifiers import SpecifierSet

    r = _call("get_tool_help", tool_name="hayabusa")
    assert r["recipes"], r
    assert all("3.9.0" in SpecifierSet(x["versions"]) for x in r["recipes"])
    others = r.get("other_recipes", [])
    assert all("tested on" in x["note"] for x in others)


def test_a_version_with_no_recipe_says_so(case, tools):
    (tools["versions"] / "hayabusa").write_text("9.0.0")
    r = _call("get_tool_help", tool_name="hayabusa")
    assert r["recipes"] == []
    assert "no recipe for 9.0.0" in r["recipe_note"] and "tested on" in r["recipe_note"]


# --- what a run did, not what its exit code means ----------------


def test_a_non_zero_exit_is_a_completed_run_with_no_meaning(case, tools, monkeypatch):
    monkeypatch.setenv("FLS_RC", "1")
    r = _call("run_command", command=["fls", str(case / "evidence")], purpose="t")
    assert r["success"] is True
    assert r["metadata"]["exit_code"] == 1
    assert "exit_code_meaning" not in json.dumps(r)
    assert "stopped" not in r


def test_the_output_limit_stop_is_named(case, tools, monkeypatch):
    monkeypatch.setenv("SIFT_MAX_OUTPUT", "200000")
    _tool(tools["bin"], "yes_forever", "while :; do echo xxxxxxxxxxxxxxxx; done")
    r = _call("run_command", command=["yes_forever"], purpose="t")
    assert r["success"] is False
    assert r["stopped"] == "output limit"
    assert "stopped by sift-mcp at its output limit (200000 bytes)" in r["error"]
    (e,) = _entries(case, "run_command")
    assert e["result_summary"]["stopped"] == "output limit"


def test_a_run_that_ended_on_its_own_with_its_output_cut_completed(
    case, tools, monkeypatch
):
    monkeypatch.setenv("SIFT_MAX_OUTPUT", "200000")
    _tool(tools["bin"], "burst", "head -c 230000 /dev/zero | tr '\\\\0' x")
    r = _call("run_command", command=["burst"], purpose="t")
    assert r["success"] is True and "stopped" not in r
    assert r["metadata"]["exit_code"] == 0


def test_the_timeout_stop_is_named(case, tools):
    _tool(tools["bin"], "slow", "sleep 30")
    r = _call("run_command", command=["slow"], purpose="t", timeout=1)
    assert r["success"] is False and r["stopped"] == "timeout"
    (e,) = _entries(case, "run_command")
    assert e["result_summary"]["stopped"] == "timeout"


def test_a_mount_record_still_needs_exit_0(case, tools, monkeypatch):
    """An internal consumer keeps its own check: no mount record for a mount
    tool that failed, though the run completed."""
    _tool(tools["bin"], "ewfmount", "exit 1")
    img = case / "evidence" / "a.E01"
    img.write_bytes(b"EVF")
    mnt = case / "mnt"
    mnt.mkdir()
    r = _call("run_command", command=["ewfmount", str(img), str(mnt)], purpose="t")
    assert r["success"] is True
    (e,) = _entries(case, "run_command")
    assert "mount" not in e


# --- the dead installer goes -----------------------------


def test_the_pinned_hayabusa_installer_is_gone():
    """It downloaded Hayabusa 2.18.0 and nothing called it."""
    import importlib.util

    assert importlib.util.find_spec("sift_mcp.installer") is None


# --- help as the real tools reply: both streams and the exit code, unjudged ---

REPLIES = Path(__file__).resolve().parents[1] / "fixtures" / "tool_replies"


def _replaying(bin_: Path, name: str, version: str, answers: dict[str, str]) -> None:
    """A stand-in `name` answering each argv in `answers` with a captured
    reply (its stdout, stderr and exit code), and anything else with
    `version`."""
    cases = "".join(
        f"""  "{argv}") cat '{REPLIES}/{stem}.stdout' 2>/dev/null
    cat '{REPLIES}/{stem}.stderr' >&2 2>/dev/null
    exit {_exit(stem)};;
"""
        for argv, stem in answers.items()
    )
    _tool(bin_, name, f'case "$*" in\n{cases}  *) echo "{version}";;\nesac')


def _exit(stem: str) -> int:
    return int((REPLIES / f"{stem}.exit").read_text())


def _shown(stem: str) -> str:
    """The reply as get_tool_help shows it: stdout, then stderr under its label."""
    out = (REPLIES / f"{stem}.stdout").read_text()
    err = (REPLIES / f"{stem}.stderr").read_text()
    return f"{out}\n# --- stderr ---\n{err}\n"


@pytest.mark.parametrize(
    "tool, version, argv, stem",
    [
        ("fls", "The Sleuth Kit ver 4.11.1", "--help", "fls-4.11.1-help"),
        ("fls", "The Sleuth Kit ver 4.15.0", "--help", "fls-4.15.0-help"),
        ("mactime", "The Sleuth Kit ver 4.11.1", "--help", "mactime-4.11.1-help"),
        ("bulk_extractor", "bulk_extractor 1.6.1", "-h", "bulk_extractor-1.6.1-h"),
        ("bulk_extractor", "bulk_extractor 2.2.0", "-h", "bulk_extractor-2.2.0-h"),
        ("ewfmount", "ewfmount 20140816", "--help", "ewfmount-20140816-help"),
        ("dc3dd", "dc3dd 7.2.646", "--help", "dc3dd-7.2.646-help"),
    ],
)
def test_help_is_both_streams_as_printed_with_the_exit_code(
    case, tools, tool, version, argv, stem
):
    """As captured: TSK answers --help with "invalid option" or "Unknown
    option" and its usage on stderr, exit 1; bulk_extractor 2.2.0's -h exits
    1 where 1.6.1's exits 0; ewfmount puts an error on stderr and its usage
    on stdout; dc3dd prints one line on stdout and its usage on stderr."""
    _replaying(tools["bin"], tool, version, {argv: stem})
    shown = _shown(stem)
    r = _call("get_tool_help", tool_name=tool)
    if len(shown.encode()) > 8192:  # bulk_extractor 2.2.0's: cut inline
        assert r["help_cut"] is True and shown.startswith(r["help"])
    else:
        assert r["help"] == shown
    assert r["help_exit_code"] == _exit(stem)


@pytest.mark.parametrize(
    "tool, version, stem",
    [
        ("ssdeep", "ssdeep version 2.14.1", "ssdeep-2.14.1"),
        ("hashdeep", "hashdeep version 4.4", "hashdeep-4.4"),
    ],
)
def test_a_tool_whose_help_flag_is_only_an_error_is_asked_its_own_way(
    case, tools, tool, version, stem
):
    """ssdeep and hashdeep answer --help with "invalid option -- '-'" and
    "Try ... -h"; the catalog asks them with -h, which prints their help."""
    _replaying(
        tools["bin"],
        tool,
        version,
        {"--help": f"{stem}-help", "-h": f"{stem}-h"},
    )
    r = _call("get_tool_help", tool_name=tool)
    assert r["help"] == _shown(f"{stem}-h")
    assert "invalid option" not in r["help"] and r["help_exit_code"] == 0


@pytest.mark.parametrize(
    "version, subcommand, stem",
    [
        ("3.9.0", "dfir-timeline", "hayabusa-3.9.0-dfir-timeline-help"),
        ("4.2.0", "json-timeline", "hayabusa-4.2.0-json-timeline-help"),
        ("4.2.0", "csv-timeline", "hayabusa-4.2.0-csv-timeline-help"),
    ],
)
def test_a_subcommand_this_version_lacks_shows_the_tools_own_error(
    case, tools, version, subcommand, stem
):
    """Hayabusa 3.9.0 has no dfir-timeline; 4.2.0 removed json-timeline and
    csv-timeline. Asked for their help, each says so on stderr and exits 2,
    and that is what the AI is shown."""
    _replaying(
        tools["bin"],
        "hayabusa",
        f"Hayabusa v{version} - Release",
        {f"{subcommand} --help": stem},
    )
    r = _call("get_tool_help", tool_name="hayabusa", subcommand=subcommand)
    assert r["help"] == _shown(stem) and r["help_exit_code"] == 2
    stderr = r["help"].split("# --- stderr ---\n", 1)[1]
    assert f"unrecognized subcommand '{subcommand}'" in stderr
    assert r["installed_version"] == version


def test_a_subcommand_for_a_tool_without_subcommands_is_refused_unrun(case, tools):
    """Only a tool the catalog gives a subcommand_help takes a subcommand;
    fls would otherwise print its own help as the help of "nosuch"."""
    ran = tools["bin"].parent / "ran"
    _tool(tools["bin"], "fls", f'echo "$*" >> {ran}; echo "The Sleuth Kit ver 4.11.1"')
    r = _call("get_tool_help", tool_name="fls", subcommand="nosuch")
    assert "help" not in r and "has no subcommands" in r["error"]
    assert not ran.exists()


def test_a_huge_help_is_read_only_up_to_a_cap(case, tools):
    """A help run that prints 10 MB and keeps running: a capped read, the
    child stopped, the reply cut, all well inside the run's time limit."""
    import time

    _tool(
        tools["bin"],
        "fls",
        f"""case "$1" in
  -V) echo "The Sleuth Kit ver 4.11.1";;
  *) exec {sys.executable} -c "import sys, time
sys.stdout.write('  -x: an option line' * 500000)
sys.stdout.flush()
time.sleep(30)";;
esac""",
    )
    start = time.monotonic()
    r = _call("get_tool_help", tool_name="fls")
    assert time.monotonic() - start < 5
    assert r["help_cut"] is True and len(r["help"].encode()) <= 8192


# --- a tool found under another version's name, and a run's own binary -------


def test_a_tool_installed_under_another_versions_name_is_found(
    case, tools, monkeypatch
):
    """pip installs plaso 20260720 as log2timeline, without .py."""
    import shutil

    import sift_mcp.tool_version as tv
    import sift_mcp.tools.discovery as discovery

    def only_stand_ins(name, extra_paths=None):
        return shutil.which(name, path=str(tools["bin"]))

    monkeypatch.setattr(tv, "find_binary", only_stand_ins)
    monkeypatch.setattr(discovery, "find_binary", only_stand_ins)
    _tool(tools["bin"], "log2timeline", 'echo "plaso - log2timeline version 20260720"')
    r = _call("get_tool_help", tool_name="log2timeline")
    assert r["installed_version"] == "20260720"
    assert r["resolved_path"] == str(tools["bin"] / "log2timeline")
    assert [x["argv"][0] for x in r["recipes"]] == ["log2timeline"]
    c = _call("check_tools", tool_names=["log2timeline"])["log2timeline"]
    assert c["binary_path"] == str(tools["bin"] / "log2timeline")
    listed = _call("list_available_tools", category="timeline")
    listed = listed.get("tools", listed) if isinstance(listed, dict) else listed
    (entry,) = [t for t in listed if t["name"] == "log2timeline"]
    assert entry["available"] is True


def test_a_runs_version_is_asked_of_the_binary_it_names(case, tools):
    """Both plaso installs on PATH: the run names log2timeline, so its
    version is that one's, not log2timeline.py's; the help shows both."""
    _tool(
        tools["bin"], "log2timeline.py", 'echo "plaso - log2timeline version 20240308"'
    )
    _tool(
        tools["bin"],
        "log2timeline",
        'case "$1" in --version) echo "plaso - log2timeline version 20260720";; '
        "*) echo ok;; esac",
    )
    r = _call(
        "run_command", command=["log2timeline", "--status_view", "none"], purpose="t"
    )
    assert r["tool_version"] == "20260720"
    assert r["resolved_path"] == str(tools["bin"] / "log2timeline")
    h = _call("get_tool_help", tool_name="log2timeline")
    assert (h["installed_version"], h["recipes"][0]["argv"][0]) == (
        "20240308",
        "log2timeline.py",
    )
    (other,) = h["other_installs"]
    assert (other["binary"], other["installed_version"]) == ("log2timeline", "20260720")
    assert other["resolved_path"] == str(tools["bin"] / "log2timeline")
    assert [x["argv"][0] for x in other["recipes"]] == ["log2timeline"]


def test_a_blank_recipe_range_matches_no_version():
    from types import SimpleNamespace

    from sift_mcp.tools.discovery import _recipes

    td = SimpleNamespace(recipes=[{"task": "t", "versions": " ", "argv": ["x"]}])
    out = _recipes(td, "1.0")
    assert out["recipes"] == [] and "no recipe for 1.0" in out["recipe_note"]


def test_one_command_records_a_versions_help(case, tools, tmp_path):
    """scripts/capture_tool_help.py: the fixtures the recipe test reads."""
    import importlib.util

    script = Path(__file__).resolve().parents[2] / "scripts" / "capture_tool_help.py"
    spec = importlib.util.spec_from_file_location("capture_tool_help", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = tmp_path / "tool_help"
    written = mod.capture("hayabusa", ["csv-timeline"], out)
    assert [(p.relative_to(out).as_posix(), code) for p, code in written] == [
        ("hayabusa/3.9.0/hayabusa-3.9.0-help.txt", 0),
        ("hayabusa/3.9.0/hayabusa-3.9.0-csv-timeline-help.txt", 0),
    ]
    # both streams, as the fixtures are written
    assert written[1][0].read_text().endswith("\n# --- stderr ---\n\n")
    assert "--no-wizard" in written[1][0].read_text()
