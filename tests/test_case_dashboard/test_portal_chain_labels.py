"""The provenance view's labels: a hover shows a list of records as a count,
and a chain step with no audit entry names no tool.

A hover showed each record of a list parameter (an index search's result_docs)
as "[object Object]". The registered-path and manifest steps have no audit
entry, and their chain step was labelled "unknown". These rows run the page's
own _buildTooltipHtml and loadToolInvocations (which reaches renderStep) under
node with the test_portal_case_text.py harness."""

from __future__ import annotations

import json

import pytest

from .test_portal_case_text import V2, _render

AID, AID_NOTOOL, AID_MISSING = "sift-a-001", "sift-a-002", "sift-a-404"
FI = "fileidentity-a-009"
EV = "/cases/c/evidence/disk.iso"


def Q(s: str) -> str:
    """escapeHtml's quotes."""
    return s.replace('"', "&quot;")


def _tip(tmp_path, params: dict) -> str:
    entry = {"audit_id": AID, "tool": "idx_search", "params": params}
    call = f"_buildTooltipHtml({json.dumps(entry)}, {{role: 'query'}})"
    html = _render(tmp_path, V2, {"calls": [call]})[call]
    assert html and not html.startswith("THREW"), html
    return html


def _chain(tmp_path, step: dict) -> str:
    """The chain panel for one artifact whose chain is just `step`."""
    audit = [{"audit_id": AID, "tool": "run_command", "_backend": "sift-mcp"},
             {"audit_id": AID_NOTOOL, "_backend": "sift-mcp"}]  # fmt: skip
    art = {"audit_id": AID, "source": EV, "provenance_grade": "FULL",
           "source_evidence": EV, "provenance_root": {"path": EV, "sha256": "a" * 64,
                                                     "label": "AI-registered"},
           "provenance_chain": [step]}  # fmt: skip
    f = {"id": "F-a-001", "audit_ids": [AID], "artifacts": [art]}
    call = (f"(document.getElementById('toolInvocationsList').innerHTML = '', "
            f"auditCache['F-a-001'] = {json.dumps(audit)}, "
            f"loadToolInvocations({json.dumps(f)}).catch(function(e) {{}}), "
            f"document.getElementById('toolInvocationsList').innerHTML)")  # fmt: skip
    html = _render(tmp_path, V2, {"calls": [call]})[call]
    assert html and not html.startswith("THREW"), html
    # the step's own div: from its arrow to the end of its evidence line (the
    # audit entries the chain didn't cite follow it)
    return html[html.index("↓") :].split("Additional Tool Invocations")[0]


def _link(method, aid):
    return {"method": method, "audit_id": aid, "entry_sha256": "",
            "from": {"path": EV, "sha256": "a" * 64}, "to": {"path": EV, "sha256": "a" * 64}}  # fmt: skip


# --- the hover --------------------------------------------------------------


def test_a_list_of_records_shows_as_a_count(tmp_path):
    docs = [{"index": "i", "id": "a"}, {"index": "i", "id": "b"}]
    html = _tip(tmp_path, {"result_docs": docs})
    assert "result_docs:</span> <span>2 items</span>" in html, html
    assert "[object Object]" not in html


def test_a_list_of_strings_shows_its_items(tmp_path):
    html = _tip(tmp_path, {"hosts": ["a", "b"]})
    assert "hosts:</span> <span>a, b</span>" in html, html


def test_an_object_param_shows_its_json(tmp_path):
    html = _tip(tmp_path, {"query": {"term": {"x": "y"}}})
    assert "query:</span> <span>" + Q('{"term":{"x":"y"}}') + "</span>" in html, html


def test_a_list_with_an_item_string_cannot_convert_shows_its_items(tmp_path):
    html = _tip(tmp_path, {"hosts": [{"toString": None}, "dc01"]})
    assert "hosts:</span> <span>[unprintable], dc01</span>" in html, html


@pytest.mark.parametrize(
    "value,shown",
    [([{"toString": None}], "[unprintable]"),
     ([{"toString": "x"}, {"id": "a"}], "[unprintable], [object Object]"),
     ([{"id": "a"}, "dc01"], "[object Object], dc01"),
     ([{"id": "a"}, None], "[object Object], "),
     ([["a", "b"], ["c"]], "a,b, c"),
     (["a", 3, None, True], "a, 3, , true")],
    ids=["unprintable-only", "uncallable-toString", "record-and-string", "record-and-null",
         "nested-lists", "scalars"],
)  # fmt: skip
def test_a_list_not_all_records_shows_its_items_as_before(tmp_path, value, shown):
    html = _tip(tmp_path, {"ids": value})
    assert f"ids:</span> <span>{shown}</span>" in html, html


def test_an_empty_list_is_skipped(tmp_path):
    html = _tip(tmp_path, {"ids": []})
    assert "ids:" not in html, html


# --- the chain step ---------------------------------------------------------


@pytest.mark.parametrize("method", ["registered-path", "manifest"])
def test_a_step_with_no_audit_entry_names_no_tool(tmp_path, method):
    html = _chain(tmp_path, _link(method, ""))
    assert "unknown" not in html, html
    assert f"[{method}]" in html
    assert "disk.iso" in html and "→" in html  # the evidence line


def test_a_step_whose_entry_has_a_tool_names_it(tmp_path):
    html = _chain(tmp_path, _link("recorded-id", AID))
    assert "<strong>run_command</strong>" in html and "unknown" not in html, html


def test_a_step_whose_entry_has_no_tool_shows_unknown(tmp_path):
    html = _chain(tmp_path, _link("recorded-id", AID_NOTOOL))
    assert "<strong>unknown</strong>" in html, html


def test_a_step_whose_entry_is_missing_shows_unknown(tmp_path):
    html = _chain(tmp_path, _link("recorded-id", AID_MISSING))
    assert "<strong>unknown</strong>" in html, html


def test_a_step_whose_file_identity_is_unread_names_no_tool(tmp_path):
    html = _chain(tmp_path, _link("recorded-id", FI))
    assert "unknown" not in html and "not checked (the file-identity log" in html, html
