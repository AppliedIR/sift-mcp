"""Free text keeps its dots: a description, a command line, reasoning, an
output summary or a purpose that holds ".." ("then prefetch...", "cd ..",
"0.6.4..0.6.5", a quoted `ls -la`) is stored as written, at every tool that
takes one. Path fields still refuse "..", and every field still refuses a null
byte and a value past its length limit."""

import json

import pytest
import yaml
from case_mcp.server import _MAX_NAME, _MAX_TEXT, create_server

from .test_server import _parse, case_dir  # noqa: F401 (case_dir is a fixture)

DOTS = {
    "ellipsis": "check the MFT... then prefetch",
    "cd up": "cd .. && ls",
    "version range": "0.6.4..0.6.5",
    "ls -la": (
        "total 8\n"
        "drwxr-xr-x 2 sansforensics sansforensics 4096 Oct 16 14:00 .\n"
        "drwxr-xr-x 9 sansforensics sansforensics 4096 Oct 16 13:58 ..\n"
    ),
    "quoted refusal": (
        "BLOCKED: write to findings.json. Case records, audit/ and evidence "
        "files are protected; move other files to the case's DELETE/ directory "
        "instead.. Command: echo x >> findings.json"
    ),
}


def _tools():
    srv = create_server()
    return {n: t.fn for n, t in srv._tool_manager._tools.items()}


def _audit(case, tool):
    p = case["path"] / "audit" / "case-mcp.jsonl"
    entries = [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
    return [e for e in entries if e["tool"] == tool][-1]


def _action(case):
    return json.loads((case["path"] / "actions.jsonl").read_text().splitlines()[-1])


def _evidence_file(case):
    f = case["path"] / "evidence" / "disk.raw"
    f.write_bytes(b"x" * 16)
    return str(f)


def _ok(result):
    return not (isinstance(result, dict) and "error" in result)


def _then(result, stored):
    """The tool's answer, and what it stored (None when it refused)."""
    return result, stored() if _ok(result) else None


def _meta(result):
    return yaml.safe_load(open(f"{result['case_dir']}/CASE.yaml"))


def _files(case):
    return json.loads((case["path"] / "evidence.json").read_text())["files"]


def _case_init(case, value):
    result = _parse(_tools()["case_init"](name="Dots", description=value,
                                          share_wintools=False))  # fmt: skip
    return _then(result, lambda: _meta(result)["description"])


def _evidence_register(case, value):
    result = _parse(_tools()["evidence_register"](path=_evidence_file(case),
                                                  description=value))  # fmt: skip
    return _then(result, lambda: _files(case)[-1]["description"])


def _record_description(case, value):
    result = _parse(_tools()["record_action"](description=value))
    return _then(result, lambda: _action(case)["description"])


def _record_command(case, value):
    result = _parse(_tools()["record_action"](description="note", command=value))
    return _then(result, lambda: _action(case)["command"])


def _reasoning(case, value):
    result = _parse(_tools()["log_reasoning"](text=value))
    return _then(result, lambda: _audit(case, "log_reasoning")["params"]["text"])


def _external(field):
    def call(case, value):
        args = {"command": "ls", "output_summary": "files", "purpose": "listing"}
        result = _parse(_tools()["log_external_action"](**{**args, field: value}))
        return _then(
            result, lambda: _audit(case, "log_external_action")["params"][field]
        )

    return call


def _backup_purpose(case, value):
    dest = str(case["parent"] / "backups")
    result = _parse(_tools()["backup_case"](destination=dest, purpose=value))
    return _then(result, lambda: _audit(case, "backup_case")["params"]["purpose"])


SITES = {
    "case_init description": _case_init,
    "evidence_register description": _evidence_register,
    "record_action description": _record_description,
    "record_action command": _record_command,
    "log_reasoning text": _reasoning,
    "log_external_action command": _external("command"),
    "log_external_action output_summary": _external("output_summary"),
    "log_external_action purpose": _external("purpose"),
    "backup_case purpose": _backup_purpose,
}


@pytest.mark.parametrize("dots", DOTS)
@pytest.mark.parametrize("site", SITES)
def test_free_text_with_dots_is_stored_as_written(case_dir, site, dots):  # noqa: F811
    result, stored = SITES[site](case_dir, DOTS[dots])
    assert _ok(result), result
    assert stored == DOTS[dots]


@pytest.mark.parametrize("site", SITES)
def test_free_text_still_refuses_a_null_byte(case_dir, site):  # noqa: F811
    field = site.split()[-1]
    try:
        result, _ = SITES[site](case_dir, "cd ..\x00x")
    except ValueError as e:  # log_reasoning and log_external_action raise
        result = {"error": str(e)}
    assert result == {"error": f"{field} contains invalid null byte"}


@pytest.mark.parametrize("site", SITES)
def test_free_text_still_refuses_a_value_past_the_limit(case_dir, site):  # noqa: F811
    field = site.split()[-1]
    try:
        result, _ = SITES[site](case_dir, "." * (_MAX_TEXT + 1))
    except ValueError as e:
        result = {"error": str(e)}
    want = f"{field} exceeds maximum length of {_MAX_TEXT} characters"
    assert result == {"error": want}


def test_a_value_at_the_limit_full_of_dots_is_stored(case_dir):  # noqa: F811
    result, stored = _reasoning(case_dir, "." * _MAX_TEXT)
    assert _ok(result) and stored == "." * _MAX_TEXT


PATHS = {
    "case_init cases_dir": lambda t, v: t["case_init"](name="x", cases_dir=v,
                                                       share_wintools=False),
    "case_activate cases_dir": lambda t, v: t["case_activate"](case_id="x",
                                                               cases_dir=v),
    "backup_case destination": lambda t, v: t["backup_case"](destination=v),
}  # fmt: skip


@pytest.mark.parametrize("value", ["../x", "a/../b", "cases.."])
@pytest.mark.parametrize("site", PATHS)
def test_a_path_field_still_refuses_dots(case_dir, site, value):  # noqa: F811
    result = _parse(PATHS[site](_tools(), value))
    assert result == {"error": f"{site.split()[-1]} contains invalid path traversal"}


@pytest.mark.parametrize("site", PATHS)
def test_a_path_field_still_refuses_a_null_byte_and_length(case_dir, site):  # noqa: F811
    field = site.split()[-1]
    nul = _parse(PATHS[site](_tools(), "x\x00y"))
    long = _parse(PATHS[site](_tools(), "x" * (_MAX_NAME + 1)))
    assert nul == {"error": f"{field} contains invalid null byte"}
    assert long == {
        "error": f"{field} exceeds maximum length of {_MAX_NAME} characters"
    }


@pytest.mark.parametrize("value", ["../x", "a..b"])
@pytest.mark.parametrize(
    "tool,field,args",
    [("case_init", "name", {}), ("record_action", "tool", {"description": "n"}),
     ("log_reasoning", "analyst_override", {"text": "t"}),
     ("log_external_action", "hook_audit_id",
      {"command": "ls", "output_summary": "o", "purpose": "p"})],
)  # fmt: skip
def test_short_fields_still_refuse_dots(case_dir, tool, field, args, value):  # noqa: F811
    try:
        result = _parse(_tools()[tool](**args, **{field: value}))
    except ValueError as e:
        result = {"error": str(e)}
    assert result == {"error": f"{field} contains invalid path traversal"}
