"""The knowledge base holds no command lines: a tool's syntax comes from
get_tool_help (get_windows_tool_help) for the installed version, never from
text written against another version. It names only MCP tools that exist, so
a step that sends the AI to a tool sends it somewhere.

What stays is listed below, each with why: text that describes evidence (an
attacker's switch), and lines whose rewording isn't approved yet."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from . import test_schemas

DATA = Path(__file__).resolve().parents[2] / "packages" / "forensic-knowledge" / "data"
FLAG = re.compile(r"(?<![\w\-/\\.:=<>'\"*])(--?[A-Za-z][A-Za-z0-9_\-]*)")
# a Windows switch ("dir /r"); a path's first part has the same shape, so a
# filesystem root's name is read as a path
SLASH = re.compile(r"(?<![\w\-/\\.:=<>'\"*\]])/([A-Za-z?][A-Za-z0-9?:]*)(?![\w/.\-])")
PATH_ROOTS = frozenset(
    [
        "bin",
        "boot",
        "dev",
        "etc",
        "home",
        "lib",
        "lib64",
        "media",
        "mnt",
        "opt",
        "private",
        "proc",
        "root",
        "run",
        "sbin",
        "srv",
        "sys",
        "tmp",
        "usr",
        "var",
        "Applications",
        "Library",
        "System",
        "Users",
        "Volumes",
    ]
)


def switches(text: str) -> list[str]:
    """The command-line switches in a text, dash and slash forms."""
    slash = [f"/{s}" for s in SLASH.findall(text) if s not in PATH_ROOTS]
    return FLAG.findall(text) + slash


# (file, text the scalar starts with): why it keeps a switch
ALLOWED = {
    # an attacker's switch, as it appears in the evidence
    (
        "artifacts/linux/bash_history.yaml",
        "History can be cleared (history -c)",
    ): "evidence",
    (
        "artifacts/windows/event_logs_powershell.yaml",
        "ScriptBlock logging (EID 4104)",
    ): "evidence",
    (
        "artifacts/windows/event_logs_services.yaml",
        "PsExec creates a service",
    ): "evidence",
    (
        "discipline/playbooks/powershell_anomaly.yaml",
        "Encoded command parameter (-enc",
    ): "evidence",
    (
        "discipline/playbooks/powershell_anomaly.yaml",
        "If encoded command detected (-enc)",
    ): "evidence",
    (
        "artifacts/windows/volume_shadow_copies.yaml",
        "VSS has limited allocated storage.",
    ): "evidence",
    (
        "discipline/playbooks/credential_access.yaml",
        "Check for pass-the-hash logon patterns",
    ): "evidence",
    (
        "artifacts/windows/registry_run_keys.yaml",
        "ValueData:(*powershell* OR",
    ): "evidence",
    # commands outside the approved before/after: a 0.6.5 follow-on sweep
    ("artifacts/linux/wtmp_utmp.yaml", "wtmp is a BINARY file."): "follow-on",
    (
        "artifacts/windows/wmi_persistence.yaml",
        "WMI subscriptions do not appear",
    ): "follow-on",
    # wording not approved yet
    (
        "tools/memory/winpmem.yaml",
        "winpmem_mini writes raw images only",
    ): "pending text",
    (
        "artifacts/windows/alternate_data_streams.yaml",
        "Standard dir commands and Windows Explorer",
    ): "pending text",
}
# macOS artifacts carry live-response commands, many of them warnings about
# what not to run against evidence; kept, and swept as a 0.6.5 follow-on
ALLOWED_FOLDERS = ("artifacts/macos/",)
# "(server: tool)" in text, and a corroboration check's "server: tool ..."
MCP_REF = re.compile(r"\(([a-z][a-z-]+): ([a-z_]+)\)|^([a-z][a-z-]+): ([a-z_]+)\b")
ALIASES = {
    "forensic-rag-mcp": "forensic-rag",
    "opencti-mcp": "opencti",
    "wintools": "wintools-mcp",
}


def _scalars(path: Path):
    """(line, keypath, text) of every scalar in a yaml file."""
    node = yaml.compose(path.read_text(encoding="utf-8"))

    def walk(n, kp):
        if isinstance(n, yaml.MappingNode):
            for k, v in n.value:
                yield from walk(v, (*kp, str(k.value)))
        elif isinstance(n, yaml.SequenceNode):
            for i, v in enumerate(n.value):
                yield from walk(v, (*kp, i))
        elif isinstance(n, yaml.ScalarNode):
            yield n.start_mark.line + 1, kp, str(n.value)

    if node is not None:
        yield from walk(node, ())


def _files():
    return sorted(DATA.rglob("*.yaml"))


def _allowed(rel: str, text: str) -> str | None:
    if rel.startswith(ALLOWED_FOLDERS):
        return "macOS follow-on"
    return next(
        (
            why
            for (f, start), why in ALLOWED.items()
            if f == rel and text.startswith(start)
        ),
        None,
    )


def test_no_knowledge_text_carries_a_command_line_switch():
    found = [
        f"{p.relative_to(DATA)}:{line} {switches(text)} {text[:80]}"
        for p in _files()
        for line, _kp, text in _scalars(p)
        if switches(text) and not _allowed(p.relative_to(DATA).as_posix(), text)
    ]
    assert found == []


def test_switches_reads_slash_switches_and_not_paths():
    text = (
        "Use 'dir /r' or `vssadmin delete shadows /all /quiet` (runas /netonly)."
        " Copy to /tmp or /Users/x, scan /proc/[pid]/mem, read C:/Windows, and/or"
        " a 1/2 split; a URL https://x.org/a"
    )
    assert switches(text) == ["/r", "/all", "/quiet", "/netonly"]


def test_every_allowed_switch_line_still_exists():
    """An allowance outlives its line only by mistake."""
    texts = {
        (p.relative_to(DATA).as_posix(), text)
        for p in _files()
        for _line, _kp, text in _scalars(p)
    }
    stale = [
        k
        for k in ALLOWED
        if not any(f == k[0] and t.startswith(k[1]) for f, t in texts)
    ]
    assert stale == []


@pytest.mark.parametrize("key", ["quick_start", "exit_code_hints"])
def test_no_tool_entry_has_a_command_or_exit_code_key(key):
    """A quick start is one version's command, and exit codes differ by tool
    and version: get_tool_help gives the syntax, the output gives the result."""
    have = [
        p.relative_to(DATA).as_posix()
        for p in sorted((DATA / "tools").rglob("*.yaml"))
        if key in (yaml.safe_load(p.read_text(encoding="utf-8")) or {})
    ]
    assert have == []


def test_every_mcp_tool_the_knowledge_names_exists():
    valid = test_schemas.TestCrossMcpChecks.VALID_TOOLS
    unknown = []
    for p in _files():
        for line, _kp, text in _scalars(p):
            for m in MCP_REF.finditer(text):
                server, tool = (
                    (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
                )
                server = ALIASES.get(server, server)
                if server in valid and tool not in valid[server]:
                    unknown.append(f"{p.relative_to(DATA)}:{line} {server}: {tool}")
    assert unknown == []
