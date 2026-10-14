"""How to read a windows-triage verdict is served in the verdicts the tools
return: check_file gives EXPECTED, EXPECTED_LOLBIN, SUSPICIOUS or UNKNOWN, and
check_process_tree gives EXPECTED, SUSPICIOUS or UNKNOWN. The guidance named
RENAMED and UNEXPECTED, which no tool returns, and nothing the AI reads names
them now. The texts are the approved ones, served as written, and each
check_process_tree text describes an answer the tool gives."""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest
from forensic_mcp.server import create_server
from test_windows_triage.test_process_tree_checks import answer, srv  # noqa: F401
from windows_triage.analysis.verdicts import Verdict
from windows_triage.server import MACHINE_ACCOUNT_NOT_JUDGED

ROOT = Path(__file__).resolve().parents[2]

CHECK_FILE = {
    "EXPECTED": "The path, or a known directory for this filename, matches the "
    "Windows baseline. Without a hash this is a name-and-path match only; pass the "
    "hash to compare it with the baseline builds of that path. Default does not "
    "mean benign.",
    "EXPECTED_LOLBIN": "As EXPECTED, and the file is a known LOLBin that can be "
    "abused. Check how it was used.",
    "SUSPICIOUS": "A specific anomaly: a critical filename trick (Unicode or double "
    "extension), a known attack-tool name, a system binary's name in an unexpected "
    "directory (masquerading), a hash that matches no baseline build of that path, "
    "or another high-severity filename issue. The reply's reasons say which. "
    "Investigate further.",
    "UNKNOWN": "File NOT in baseline database. This is NEUTRAL — it means "
    "not-in-database, not suspicious. Custom software, user files, and enterprise "
    "tools will all be UNKNOWN. A filename without a folder is not checked: pass "
    "the full path.",
}
CHECK_PROCESS_TREE = {
    "EXPECTED": "The process is known, and the checks that ran match its "
    "expectations. The parent is always checked. The path and user are checked only "
    "when they were given. The reasons do not list which checks ran. A user that "
    "could not be judged gets its own reason.",
    "SUSPICIOUS": "Unexpected parent, executable path or user context for a known "
    "process, or a filename anomaly; the reasons say which. May indicate process "
    "injection, living-off-the-land, or unusual execution.",
    "UNKNOWN": "Not enough data to judge. Either the process is not in the "
    "expectations database, or it has no list of expected parents. This is neutral. "
    "The reasons say which.",
}


async def _served(tool: str, mode: str = "tools") -> dict:
    """As the AI reads it: the get_tool_guidance tool, or the resource."""
    if mode == "tools":
        server = create_server(reference_mode="tools")
        result = await server.call_tool("get_tool_guidance", {"tool_name": tool})
        raw = result[0].text
    else:
        server = create_server()
        result = await server.read_resource(f"forensic-mcp://tool-guidance/{tool}")
        raw = result[0].content if hasattr(result[0], "content") else result[0].text
    return json.loads(raw)["score_interpretation"]


def _served_now(tool: str) -> dict:
    return asyncio.run(_served(tool))


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["tools", "resources"])
@pytest.mark.parametrize(
    "tool, texts",
    [("check_file", CHECK_FILE), ("check_process_tree", CHECK_PROCESS_TREE)],
)
async def test_the_verdict_guidance_is_served_as_approved(tool, texts, mode):
    assert await _served(tool, mode) == texts


@pytest.mark.asyncio
async def test_the_guidance_names_only_verdicts_the_tools_return():
    returned = {v.value for v in Verdict}
    assert set(await _served("check_file")) == returned
    assert set(await _served("check_process_tree")) <= returned


def test_nothing_the_ai_reads_names_a_verdict_no_tool_returns():
    """The served knowledge, instructions, skills and client texts."""
    places = [
        ROOT / "packages",
        ROOT / "skills",
        ROOT / "agents",
        ROOT / "codex",
        ROOT / "claude-code",
        ROOT / "AGENTS.md",
    ]
    old = re.compile(r"\b(RENAMED|UNEXPECTED)\b")
    named = [
        f"{path.relative_to(ROOT)}:{n}"
        for place in places
        for path in ([place] if place.is_file() else sorted(place.rglob("*")))
        if path.is_file()
        and path.suffix in {".yaml", ".yml", ".md", ".py", ".toml"}
        and "/tests/" not in str(path)
        for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1)
        if old.search(line)
    ]
    assert named == []


SVCHOST = {"process_name": "svchost.exe", "parent_name": "services.exe"}
SVCHOST_PATH = r"C:\Windows\System32\svchost.exe"


@pytest.mark.parametrize(
    "given",
    [
        {},
        {"path": SVCHOST_PATH},
        {"path": SVCHOST_PATH, "user": "NT AUTHORITY\\SYSTEM"},
    ],
    ids=["parent", "parent+path", "parent+path+user"],
)
def test_expected_gives_the_same_one_reason_whichever_checks_ran(srv, given):
    """EXPECTED: the parent is always checked, the path and user only when given,
    and the reasons don't say which of them ran."""
    got = answer(srv, "check_process_tree", {**SVCHOST, **given})
    assert (got["verdict"], got["reasons"], got["finding_types"]) == (
        "EXPECTED",
        ["Process relationship matches expectations"],
        [],
    )
    served = _served_now("check_process_tree")["EXPECTED"]
    assert "The parent is always checked" in served
    assert "The reasons do not list which checks ran" in served


def test_a_user_that_could_not_be_judged_adds_its_own_reason(srv):
    """lsass.exe runs as SYSTEM, and a machine account can be SYSTEM or not."""
    got = answer(
        srv,
        "check_process_tree",
        {
            "process_name": "lsass.exe",
            "parent_name": "wininit.exe",
            "user": "CONTOSO\\WKS01$",
        },
    )
    assert (got["verdict"], got["reasons"], got["user_valid"]) == (
        "EXPECTED",
        ["Process relationship matches expectations", MACHINE_ACCOUNT_NOT_JUDGED],
        None,
    )
    assert (
        "A user that could not be judged gets its own reason"
        in _served_now("check_process_tree")["EXPECTED"]
    )


def test_unknown_for_a_known_process_with_no_parent_list(srv):
    """UNKNOWN: a process the database knows, with no list of expected parents
    (cmd.exe has only a known-bad list), and the reason says so."""
    got = answer(
        srv,
        "check_process_tree",
        {"process_name": "cmd.exe", "parent_name": "explorer.exe"},
    )
    assert got["verdict"] == "UNKNOWN"
    assert got["reasons"] == [
        "No list of expected parents for this process; parent is not on its "
        "known-bad list"
    ]
    assert (
        "it has no list of expected parents"
        in _served_now("check_process_tree")["UNKNOWN"]
    )


def test_unknown_for_a_process_not_in_the_database(srv):
    got = answer(
        srv,
        "check_process_tree",
        {"process_name": "acmeagent.exe", "parent_name": "services.exe"},
    )
    assert (got["verdict"], got["reasons"]) == (
        "UNKNOWN",
        ["Process not in expectations database (neutral)"],
    )
    assert (
        "not in the expectations database"
        in _served_now("check_process_tree")["UNKNOWN"]
    )
