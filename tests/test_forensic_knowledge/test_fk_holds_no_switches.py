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
    **{
        ("tools/persistence/autorunsc.yaml", start): "pending text"
        for start in (
            "Use -a * for comprehensive",
            "Use -c for CSV output suitable",
            "Use -h to show file hashes",
            "Use -s to verify digital signatures — unsigned",
            "Use -m to hide Microsoft-signed",
            "Use -c for CSV output and -h",
            "Use -s to verify digital signatures for trust",
            "Use -m to hide Microsoft entries only",
        )
    },
    # the wintools-scope edits (the next change)
    **{
        (f, start): "wintools-scope"
        for f, start in (
            ("tools/persistence/autorunsc.yaml", "Offline scanning (-z flag)"),
            ("tools/persistence/autorunsc.yaml", "Live system analysis covers"),
            ("tools/persistence/autorunsc.yaml", "Use -v to check VirusTotal"),
            ("tools/persistence/autorunsc.yaml", "Run autorunsc with -a *"),
            ("tools/persistence/autorunsc.yaml", "Use -z for offline analysis"),
            (
                "tools/persistence/autorunsc.yaml",
                "Windows forensic workstation available",
            ),
            ("tools/malware/sigcheck.yaml", "Certificate chain validation"),
            ("tools/malware/sigcheck.yaml", "Offline VT workflow (-o)"),
            ("tools/malware/sigcheck.yaml", "Use -vt to check"),
            ("tools/malware/sigcheck.yaml", "Use -v/-vt to check"),
            ("tools/triage/kape.yaml", "Use --tsource for target source"),
            ("tools/triage/kape.yaml", "Use --tsource to specify"),
            ("tools/triage/kape.yaml", "Use --tdest to specify"),
            ("tools/triage/kape.yaml", "Use --target to select"),
            ("tools/zimmerman/appcompatcacheparser.yaml", "On SIFT/Linux requires"),
            ("tools/malware/hollows_hunter.yaml", "The -dir flag"),
            ("tools/malware/hollows_hunter.yaml", "Use -json for JSON"),
            ("tools/malware/moneta.yaml", "Use -p <PID>"),
            ("tools/malware/moneta.yaml", "Use -m ioc mode"),
            ("tools/malware/moneta.yaml", "Use -m region"),
            ("tools/malware/moneta.yaml", "Use -d flag"),
            ("tools/malware/moneta.yaml", "Use --filter options"),
        )
    },
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
        f"{p.relative_to(DATA)}:{line} {FLAG.findall(text)} {text[:80]}"
        for p in _files()
        for line, _kp, text in _scalars(p)
        if FLAG.search(text) and not _allowed(p.relative_to(DATA).as_posix(), text)
    ]
    assert found == []


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
