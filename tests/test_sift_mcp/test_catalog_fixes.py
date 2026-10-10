"""SIFT tools run as forensic work needs them.

`-e` stays refused where it runs code (perl, ruby, node; pwsh's -enc and
-EncodedCommand in any case) and is allowed where it only selects or extracts
(grep -E, sed -e, strings -e l, tshark -e, ...). `-o` is no output where it
is a switch (grep -o, strings -o); a tool's own output flags (tshark -w,
unzip -d, the EZ tools' --body, ...) are outputs; AmcacheParser's -w stays an
input. Acquisition and mount tools take a /dev source. The hayabusa entry
names its subcommand and -w. An EZ tool runs as `dotnet <Tool>.dll`, so a path
with a space is one argument.
"""

from __future__ import annotations

import os
import stat
from unittest.mock import patch

import pytest
from sift_mcp import command_files
from sift_mcp.catalog import clear_catalog_cache, get_tool_def
from sift_mcp.security import get_output_flags, sanitize_extra_args
from sift_mcp.tools import generic


@pytest.fixture(autouse=True)
def clear_cache():
    clear_catalog_cache()
    yield
    clear_catalog_cache()


# -- -e: allowed where it selects, refused where it runs code


@pytest.mark.parametrize(
    "tool, args",
    [
        ("grep", ["-E", "a|b", "f.txt"]),
        ("grep", ["-e", "pattern", "f.txt"]),
        ("zgrep", ["-E", "x", "f.gz"]),
        ("sed", ["-e", "s/a/b/", "f.txt"]),
        ("sed", ["-E", "s/(a)/b/", "f.txt"]),
        ("strings", ["-e", "l", "mem.raw"]),
        ("tshark", ["-r", "c.pcap", "-T", "fields", "-e", "ip.src", "-E", "header=y"]),
        ("bulk_extractor", ["-e", "net", "-x", "zip", "img.raw"]),
        ("binwalk", ["-e", "fw.bin"]),
        ("ewfacquire", ["-e", "steve", "-E", "INC-1", "/dev/sdb"]),
    ],
)
def test_e_that_only_selects_or_extracts_is_allowed(tool, args):
    assert sanitize_extra_args(args, tool_name=tool) == args


@pytest.mark.parametrize(
    "tool, args",
    [
        ("perl", ["-e", "system('id')"]),
        ("ruby", ["-e", "`id`"]),
        ("node", ["-e", "require('child_process')"]),
        ("pwsh", ["-EncodedCommand", "aQBkAA=="]),
        ("pwsh", ["-ENC", "aQBkAA=="]),
        ("python3", ["--command", "x"]),
    ],
)
def test_e_that_runs_code_is_still_refused(tool, args):
    with pytest.raises(ValueError, match="dangerous flag"):
        sanitize_extra_args(args, tool_name=tool)


# -- -o where it's a switch; a tool's own output flags


@pytest.mark.parametrize("tool", ["strings", "grep", "zgrep", "ls", "hexdump", "tar"])
def test_o_is_no_output_where_it_is_a_switch(tool):
    reads, writes = command_files.named(
        [tool, "-o", "/cases/c1/evidence/disk.raw"], get_output_flags(tool)
    )
    assert writes == [] and "/cases/c1/evidence/disk.raw" in reads


@pytest.mark.parametrize(
    "command, written",
    [
        (["tshark", "-r", "c.pcap", "-w", "/out/x.pcap"], "/out/x.pcap"),
        (["unzip", "a.zip", "-d", "/out/a"], "/out/a"),
        (["ewfacquire", "/dev/sdb", "-t", "/out/disk"], "/out/disk"),
        (["hashdeep", "-r", "/ev", "-W", "/out/h.txt"], "/out/h.txt"),
        (["psort.py", "-w", "/out/t.csv", "s.plaso"], "/out/t.csv"),
        (["log2timeline.py", "--storage-file", "/out/s.plaso", "/ev"], "/out/s.plaso"),
        (
            ["vol", "--output-dir", "/out/v", "-f", "m.raw", "windows.dumpfiles"],
            "/out/v",
        ),
        (["MFTECmd", "-f", "$MFT", "--body", "/out/b"], "/out/b"),
        (["EvtxECmd", "-d", "/ev", "--xml", "/out/x"], "/out/x"),
    ],
)
def test_a_tools_own_output_flag_is_an_output(command, written):
    _, writes = command_files.named(command, get_output_flags(command[0]))
    assert written in writes


def test_amcacheparsers_w_stays_an_input():
    reads, writes = command_files.named(
        ["AmcacheParser", "-f", "/ev/Amcache.hve", "-w", "/ev/whitelist.txt"],
        get_output_flags("AmcacheParser"),
    )
    assert "/ev/whitelist.txt" in reads and "/ev/whitelist.txt" not in writes


# -- /dev sources for acquisition and mount tools


@pytest.mark.parametrize(
    "command",
    [["ewfacquire", "-u", "-t", "/tmp/disk", "/dev/sdb"], ["ewfmount", "/dev/sdb1", "/mnt/e"],
     ["vshadowinfo", "/dev/sdb2"], ["dc3dd", "if=/dev/sdb", "of=/tmp/disk.dd"]],
)  # fmt: skip
def test_an_acquisition_or_mount_tool_takes_a_dev_source(command):
    ran = {}

    def execute(cmd, **k):
        ran["cmd"] = cmd
        return {"exit_code": 0, "stdout": "", "stderr": "", "command": cmd}

    with (
        patch.object(generic, "find_binary", return_value=f"/usr/bin/{command[0]}"),
        patch.object(generic, "execute", side_effect=execute),
        patch.object(generic, "validate_output_path"),
    ):
        generic.run_command(command)
    assert ran["cmd"][1:] == command[1:]


# -- hayabusa


def test_the_hayabusa_entry_names_its_subcommand_and_no_wizard():
    td = get_tool_def("hayabusa")
    flags = [f["flag"] for f in td.common_flags]
    assert "json-timeline" in flags and "-w" in flags
    assert "json-timeline -d" in td.description


# -- EZ tools: dotnet <Tool>.dll, each argument whole


def test_an_ez_tools_path_with_a_space_is_one_argument(tmp_path, monkeypatch):
    ez = tmp_path / "zimmermantools"
    ez.mkdir()
    (ez / "MFTECmd.dll").write_bytes(b"")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    out = tmp_path / "argv.txt"
    for name, body in (
        # SIFT's wrapper: arguments expanded unquoted
        ("MFTECmd", f'#!/bin/sh\nexec "{bindir}/dotnet" {ez}/MFTECmd.dll ${{*}}\n'),
        # dotnet: writes each argument it was given on its own line
        ("dotnet", f'#!/bin/sh\nfor a in "$@"; do echo "$a"; done > "{out}"\n'),
    ):
        f = bindir / name
        f.write_text(body)
        f.chmod(f.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(generic, "_EZ_TOOLS_DIR", ez, raising=False)
    evidence = tmp_path / "Evidence Drive" / "$MFT"
    evidence.parent.mkdir()
    evidence.write_bytes(b"x")
    generic.run_command(["MFTECmd", "-f", str(evidence)], cwd=str(tmp_path))
    assert out.read_text().splitlines()[-2:] == ["-f", str(evidence)]
