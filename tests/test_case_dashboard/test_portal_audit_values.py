"""Every audit-line value the portal shows renders, whatever JSON it holds.

An audit line is case data the VM can write: any field can be an object, a
list, or an object whose own "toString" is null, which String() itself can't
convert. Each such value once threw part-way through a render and blanked
the evidence panel, the provenance chain or its tooltip. Every value now
goes through the page's one conversion that never throws: "[unprintable]"
when it can't be text. The same harness as test_portal_case_text.py.
"""

from __future__ import annotations

import copy
import json

import pytest

from .test_portal_case_text import V2, _injected, _render

AID = "sift-a-001"
BAD = {"toString": None}  # valid JSON; String() throws on it
ENTRY = {
    "audit_id": AID,
    "tool": "run_command",
    "mcp": "sift-mcp",
    "_backend": "sift-mcp",
    "source": "mcp",
    "ts": "2026-10-01T03:12:00Z",
    "elapsed_ms": 1500,
    "params": {
        "command": ["EvtxECmd", "-f", "Security.evtx"],
        "purpose": "parse the log",
        "hosts": ["wkstn05", "dc01"],
    },
    "input_files": ["/cases/c/evidence/Security.evtx"],
    "input_sha256s": ["ab" * 32],
    "result_summary": {
        "exit_code": 0,
        "output_file": "/cases/c/extractions/out.csv",
        "output_sha256": "cd" * 32,
        "stdout_bytes": 1234,
        "stdout_head": "Processed 1 file",
    },
}
FINDING = {
    "id": "F-a-001",
    "audit_ids": [AID],
    "artifacts": [{"audit_id": AID, "source": "/cases/c/evidence/Security.evtx",
                   "provenance_grade": "FULL",
                   "provenance_chain": [{"audit_id": AID, "role": "query"}]}],
}  # fmt: skip


def _panel(fn: str, box: str, entry: dict, read: str = "") -> str:
    """The panel `fn` builds from `entry`, read from its container (or from
    `read`). A throw leaves it empty (the async function rejects, handled)."""
    e, f, read = json.dumps(entry), json.dumps(FINDING), read or box
    return (f"(document.getElementById('{box}').innerHTML = '', document.getElementById('{read}')"
            f".innerHTML = '', auditCache['F-a-001'] = [{e}], {fn}({f}).catch(function() {{}}),"
            f" document.getElementById('{read}').innerHTML)")  # fmt: skip


def _paths(entry: dict) -> dict:
    """{path: html} for every render path an audit line reaches."""
    shell = dict(entry, _backend="sift-exec")  # the shell branch of the panels
    return _render_all(V2, {
        "evidence": _panel("loadEvidencePanel", "evidenceItems", entry),
        "evidence-shell": _panel("loadEvidencePanel", "evidenceItems", shell),
        "sources": _panel("loadEvidencePanel", "evidenceItems", entry, "groundingSummary"),
        "chain": _panel("loadToolInvocations", "toolInvocationsList", entry),
        "tooltip": f"_buildTooltipHtml({json.dumps(entry)}, {{role: 'query'}})",
    })  # fmt: skip


_TMP: list = []


def _render_all(page, calls: dict) -> dict:
    out = _render(_TMP[0], page, {"calls": list(calls.values())})
    return {name: out[call] for name, call in calls.items()}


@pytest.fixture(autouse=True)
def _tmp(tmp_path):
    _TMP[:] = [tmp_path]


def _with(path: str, value) -> dict:
    """ENTRY with the field at `path` (dots; a number indexes a list) set to `value`."""
    entry = copy.deepcopy(ENTRY)
    *parents, last = path.split(".")
    node = entry
    for key in parents:
        node = node[int(key)] if key.isdigit() else node[key]
    node[int(last) if last.isdigit() else last] = value
    return entry


FIELDS = [
    "audit_id", "tool", "mcp", "_backend", "source", "ts", "elapsed_ms",
    "params.command", "params.command.0", "params.purpose", "params.hosts.0",
    "input_files", "input_files.0", "input_sha256s", "input_sha256s.0",
    "result_summary", "result_summary.exit_code", "result_summary.output_file",
    "result_summary.output_sha256", "result_summary.stdout_bytes",
    "result_summary.stdout_head",
]  # fmt: skip


@pytest.mark.parametrize("field", FIELDS)
def test_a_value_string_conversion_throws_on_renders_in_every_path(field):
    """{"toString": null} in one field: every path still renders its entry."""
    out = _paths(_with(field, BAD))
    for path, html in out.items():
        assert html and not html.startswith("THREW"), (path, html)
        assert AID in html or path in ("tooltip", "sources"), (
            path,
            html,
        )
        assert _injected(html) == [], (path, html)
    # shown somewhere unless it only steers a branch (`source`) or is the
    # lookup key itself (the finding's id is shown instead)
    if field not in ("source", "audit_id", "result_summary"):
        assert any("[unprintable]" in h for h in out.values()), (field, out)


def test_an_object_output_file_renders_in_the_chain():
    """The chain step split output_file as text: an object threw before the
    tooltip was ever reached, and the chain panel stayed empty."""
    html = _paths(_with("result_summary.output_file", {}))["chain"]
    assert AID in html and "→ [object Object]" in html, html


def test_normal_audit_values_render_as_before():
    out = _paths(ENTRY)
    html = out["evidence"]
    for shown in ('Tool:</span> run_command', 'Exit:</span> <span class="conf-high">0<',
                  '/cases/c/extractions/out.csv', 'SHA-256:</span> <span class="mono">'
                  + "cd" * 8 + "...", "Size:</span> 1234 bytes", "Elapsed:</span> 1500ms"):  # fmt: skip
        assert shown in html, (shown, html)
    shell = out["evidence-shell"]
    assert "Command:</span><pre>EvtxECmd,-f,Security.evtx</pre>" in shell, shell
    assert "Purpose:</span> parse the log" in shell, shell
    assert out["sources"] == "<strong>Sources:</strong> sift", out["sources"]
    chain = out["chain"]
    for shown in ("<strong>run_command</strong>", " · 1.5s", "$ EvtxECmd -f Security.evtx",
                  "→ out.csv"):  # fmt: skip
        assert shown in chain, (shown, chain)
    tip = out["tooltip"]
    for shown in ("Elapsed:</span> <span>1.5s", "$ EvtxECmd -f Security.evtx",
                  "Purpose:</span> <span>parse the log", "hosts:</span> <span>wkstn05, dc01",
                  "Input files:</span> <span>Security.evtx",
                  "Input SHA-256:</span> <span style=\"font-family:monospace\">" + "ab" * 8 + "...",
                  "Output file:</span> <span style=\"font-family:monospace\">out.csv",
                  "Size:</span> <span>1,234 bytes", "Backend:</span> <span>sift-mcp"):  # fmt: skip
        assert shown in tip, (shown, tip)
