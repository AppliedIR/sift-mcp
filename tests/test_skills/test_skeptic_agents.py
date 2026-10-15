"""The finding skeptic's agent files, one per client.

`agents/finding-skeptic/claude.md` is a Claude Code subagent: its `tools` line
is an allowlist of read and query tools, plus `run_command` and the Windows
tool runner. Every tool a backend in this repo serves is either on it or
named below as left off, so a new tool can't reach the skeptic unreviewed.

`agents/finding-skeptic/codex.toml` is a Codex custom agent. Codex 0.158
honours its `[features] shell_tool = false`, but not `mcp_servers` keys in an
agent file (the agent keeps the parent's MCP tools), and a server entry
without its transport makes Codex drop the whole file. So it has none: the
managed hook `codex-skeptic-tools.sh` holds the skeptic to claude.md's list.

Both carry the skeptic's part of `skills/finding-skeptic/SKILL.md` as it is.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "agents" / "finding-skeptic"
PART_HEADING = "## The skeptic's part"

# Each backend in this repo, by the name clients give its MCP server.
SOURCES = {
    "forensic-mcp": "packages/forensic-mcp/src/forensic_mcp/server.py",
    "case-mcp": "packages/case-mcp/src/case_mcp/server.py",
    "report-mcp": "packages/report-mcp/src/report_mcp/server.py",
    "sift-mcp": "packages/sift-mcp/src/sift_mcp/server.py",
    "forensic-rag-mcp": "packages/forensic-rag/src/rag_mcp/server.py",
    "windows-triage-mcp": "packages/windows-triage/src/windows_triage/server.py",
    "opencti-mcp": "packages/opencti/src/opencti_mcp/server.py",
    "threatintel-mcp": "packages/opencti/src/opencti_mcp/server.py",
}

# Left off the allowlist: tools that write case state, run outside the
# runners the skeptic is given, or aren't needed to re-run a cited query.
LEFT_OFF = {
    "forensic-mcp": {
        "record_finding", "record_timeline_event",
        "add_todo", "update_todo", "complete_todo",
        "get_procedure",  # the skeptic's client loads skills
    },
    "case-mcp": {
        "case_init", "case_activate", "case_list", "case_status",
        "evidence_register", "evidence_list", "evidence_verify",
        "export_bundle", "import_bundle", "backup_case", "audit_summary",
        "record_action", "log_reasoning", "log_external_action",
        "open_case_dashboard",
    },
    "report-mcp": {"generate_report", "set_case_metadata", "save_report"},
}  # fmt: skip

FORBIDDEN = re.compile(
    r"^(record_|add_todo|update_todo|complete_todo|case_init|case_activate"
    r"|evidence_|backup|import_|export_|log_|save_|set_|upload|download"
    r"|extract_archive|batch_scan|case_host_fix|idx_install|idx_enrich"
    r"|idx_ingest(?!_status$))"
)


def _part() -> str:
    skill = (ROOT / "skills" / "finding-skeptic" / "SKILL.md").read_text()
    return skill[skill.index(PART_HEADING) :]


def _claude() -> tuple[dict, str]:
    text = (AGENT / "claude.md").read_text()
    _, head, body = text.split("---\n", 2)
    return yaml.safe_load(head), body


def _allowed() -> dict[str, set[str]]:
    front, _ = _claude()
    out: dict[str, set[str]] = {}
    for name in front["tools"].split(", "):
        _, server, tool = name.split("__")
        out.setdefault(server, set()).add(tool)
    return out


def _served(path: Path) -> set[str]:
    """The tool names a server module registers: functions under a
    `.tool()` decorator, and `Tool(name=...)` declarations."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                f = d.func if isinstance(d, ast.Call) else d
                if isinstance(f, ast.Attribute) and f.attr == "tool":
                    names.add(node.name)
        elif isinstance(node, ast.Call):
            f = node.func
            called = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
            for k in node.keywords if called == "Tool" else ():
                if k.arg == "name" and isinstance(k.value, ast.Constant):
                    names.add(k.value.value)
    return names


def test_the_claude_agent_is_the_skeptic_s_part_with_no_model_pin():
    front, body = _claude()
    assert body == "\n" + _part()
    assert front["name"] == "finding-skeptic"
    assert set(front) == {"name", "description", "tools"}  # no model, no denylist


def test_the_claude_allowlist_names_only_mcp_tools_and_no_case_state_tool():
    tools = _claude()[0]["tools"].split(", ")
    assert len(tools) == len(set(tools))
    assert all(re.fullmatch(r"mcp__[a-z-]+__[a-z_]+", t) for t in tools), tools
    assert [t for t in tools if FORBIDDEN.search(t.split("__")[2])] == []
    assert "mcp__sift-mcp__run_command" in tools
    assert "mcp__wintools-mcp__run_windows_command" in tools
    # a long Windows run is fetched by its id
    assert "mcp__wintools-mcp__get_windows_run" in tools


@pytest.mark.parametrize("server", sorted(SOURCES))
def test_every_tool_a_backend_serves_is_allowed_or_left_off_by_name(server):
    served = _served(ROOT / SOURCES[server])
    assert served, f"no tools found in {SOURCES[server]}"
    allowed = _allowed().get(server, set())
    left_off = LEFT_OFF.get(server, set())
    assert served - allowed - left_off == set(), "classify the new tools"
    assert allowed - served == set(), "allowed, but the backend serves no such tool"
    assert allowed & left_off == set()


def test_the_two_threat_intel_names_allow_the_same_tools():
    allowed = _allowed()
    assert allowed["threatintel-mcp"] == allowed["opencti-mcp"]


def _toml(text: str) -> dict:
    try:
        import tomllib
    except ImportError:  # Python 3.10
        tomllib = pytest.importorskip("tomli")
    return tomllib.loads(text)


def test_the_codex_agent_is_the_skeptic_s_part_without_a_shell():
    agent = _toml((AGENT / "codex.toml").read_text())
    assert agent == {
        "name": "finding-skeptic",
        "description": _claude()[0]["description"],
        "sandbox_mode": "read-only",
        "developer_instructions": _part(),
        "features": {"shell_tool": False},
    }
