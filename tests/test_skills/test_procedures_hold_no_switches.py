"""The procedures (skills and the tool reference) hold no command-line switches:
a tool's syntax comes from get_tool_help (get_windows_tool_help) for the
installed version, as the knowledge base's own lint requires. Every MCP tool
they name exists, so a step that sends the AI to a tool sends it somewhere.

What keeps a switch is listed below, each with why."""

from __future__ import annotations

import re
from pathlib import Path

from test_forensic_knowledge import test_schemas
from test_forensic_knowledge.test_fk_holds_no_switches import FLAG

from .test_skeptic_agents import SOURCES, _served

ROOT = Path(__file__).resolve().parents[2]

# (file, text the line starts with): why it keeps a switch
ALLOWED = {
    # an attacker's switch, as the evidence shows it (generated from the
    # knowledge base, where the same lines are allowed)
    (
        "skills/vhir-playbooks/references/powershell_anomaly.md",
        "- Encoded command parameter (-enc",
    ): "evidence",
    (
        "skills/vhir-playbooks/references/powershell_anomaly.md",
        "1. If encoded command detected (-enc)",
    ): "evidence",
    # Valhuntir's own commands and the client checks, not a forensic tool's
    ("skills/vhir-welcome/SKILL.md", "vhir config --setup-password"): "own CLI",
    ("skills/vhir-welcome/SKILL.md", "vhir config --reset-password"): "own CLI",
    ("skills/vhir-welcome/SKILL.md", "6. Sign: `vhir approve --review`"): "own CLI",
    ("skills/vhir-welcome/SKILL.md", "Tip: claude --continue"): "client",
    ("skills/vhir-welcome/SKILL.md", "claude --resume"): "client",
    ("skills/vhir-welcome/SKILL.md", "bwrap --ro-bind / / --unshare-net"): "check",
    ("skills/vhir-welcome/SKILL.md", "Valhuntir MCP servers (it was started"): "client",
    ("skills/vhir-welcome/SKILL.md", 'If not: "Start Codex with'): "client",
    ("skills/vhir-welcome/SKILL.md", '"Start Codex in the case folder'): "client",
    ("skills/vhir-welcome/SKILL.md", "--client=codex`."): "own CLI",
    ("skills/vhir-welcome/SKILL.md", "Run `test -r /var/lib/vhir/passwords`"): "check",
    ("claude-code/lite/TOOL_REFERENCE.md", "| threatintel-mcp | No | `--opencti`"): (
        "installer option"
    ),
}

# The names the procedures give a server, mapped to the one it serves as
SERVER = {
    "forensic-rag": "forensic-rag-mcp",
    "windows-triage": "windows-triage-mcp",
    "remnux": "remnux-mcp",
    "opencti": "opencti-mcp",
}
_NAME = r"[a-z][a-z-]*-mcp|forensic-rag|windows-triage|remnux|opencti"
REFS = (
    # "server tool(", "server tool (", "server `tool`", "server tool ->"
    re.compile(rf"\b(?P<s>{_NAME})[: ] ?`?(?P<t>[a-z][a-z_]*)(?=`|[ \t]?\(|[ \t]*->)"),
    # "server some_tool" at a line's end (a plain word there is prose)
    re.compile(rf"\b(?P<s>{_NAME})[: ] ?(?P<t>[a-z]+_[a-z_]+)[ \t]*$", re.M),
    # "Call `tool` on server"
    re.compile(rf"`(?P<t>[a-z][a-z_]*)` on (?P<s>{_NAME})\b"),
    # a backend table row: "| server | ... | MCP tool `tool` |"
    re.compile(rf"^\| (?P<s>{_NAME}) \|.*MCP tool `(?P<t>[a-z_]+)`", re.M),
)


def _files() -> list[Path]:
    return sorted(ROOT.glob("skills/**/*.md")) + sorted(
        ROOT.glob("claude-code/*/TOOL_REFERENCE.md")
    )


def _lines():
    for p in _files():
        rel = p.relative_to(ROOT).as_posix()
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            yield rel, n, line.strip()


def _allowed(rel: str, line: str) -> bool:
    return any(f == rel and line.startswith(start) for f, start in ALLOWED)


# wintools-mcp runs on the Windows host, so its tools are named here
WINTOOLS = {
    "batch_scan",
    "check_windows_tools",
    "get_share_info",
    "get_windows_tool_help",
    "list_kape_targets",
    "list_missing_windows_tools",
    "list_windows_tools",
    "run_windows_command",
    "scan_tools",
    "suggest_windows_tools",
}


def _tools() -> dict[str, set[str]]:
    tools = {name: _served(ROOT / path) for name, path in SOURCES.items()}
    other = test_schemas.TestCrossMcpChecks.VALID_TOOLS
    tools["remnux-mcp"] = other["remnux"]
    tools["opensearch-mcp"] = other["opensearch-mcp"]
    tools["wintools-mcp"] = WINTOOLS
    return tools


def test_no_procedure_carries_a_command_line_switch():
    found = [
        f"{rel}:{n} {FLAG.findall(line)} {line[:80]}"
        for rel, n, line in _lines()
        if FLAG.search(line) and not _allowed(rel, line)
    ]
    assert found == []


def test_every_allowed_switch_line_still_exists():
    """An allowance outlives its line only by mistake."""
    lines = {(rel, line) for rel, _n, line in _lines()}
    stale = [
        k
        for k in ALLOWED
        if not any(f == k[0] and t.startswith(k[1]) for f, t in lines)
    ]
    assert stale == []


def test_every_mcp_tool_the_procedures_name_exists():
    tools = _tools()
    unknown = []
    for p in _files():
        text = p.read_text(encoding="utf-8")
        for ref in REFS:
            for m in ref.finditer(text):
                server = SERVER.get(m["s"], m["s"])
                if server in tools and m["t"] not in tools[server]:
                    line = text.count("\n", 0, m.start()) + 1
                    unknown.append(f"{p.relative_to(ROOT)}:{line} {server}: {m['t']}")
    assert unknown == []


def test_the_resolver_reads_each_form():
    """Each form is read, so an empty result means the names resolved."""
    text = (
        "1. `forensic-rag search(query=x)`\n"
        "3. forensic-rag search (sigma context)  -+\n"
        "| Rules | forensic-rag `search` (sigma) |\n"
        "6. forensic-rag search -> macro rules\n"
        "Call `get_stats` on forensic-rag and\n"
        "| forensic-rag | Yes | — | MCP tool `get_stats` |\n"
        "5. Per IOC: threatintel-mcp lookup_iocs\n"
        "the reply on forensic-rag and\n"
    )
    found = [(m["s"], m["t"]) for ref in REFS for m in ref.finditer(text)]
    assert sorted(found) == sorted(
        [("forensic-rag", "search")] * 4
        + [("forensic-rag", "get_stats")] * 2
        + [("threatintel-mcp", "lookup_iocs")]
    )


def test_no_procedure_sends_the_ai_to_a_live_scan_or_acquisition_tool():
    """wintools analyses what is in the case: HollowsHunter and Moneta scan
    live processes and DumpIt acquires memory, so none is offered."""
    named = [
        f"{rel}:{n} {line[:80]}"
        for rel, n, line in _lines()
        if re.search(r"(?i)\b(hollows_?hunter|moneta|dumpit)\b", line)
    ]
    assert named == []
