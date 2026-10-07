"""case_init and case_activate don't write the Samba share for a cases_dir
with a line break in it.

cases_dir is only length-checked, and the share's `path = <case dir>` line
is written with `sudo tee`, so a line break in it added smb.conf lines of its
own (a second `path = /`, read-write). The case is still created; the share
is left alone, and the result says why.
"""

from __future__ import annotations

import json

import case_mcp.server as case_server
import pytest
import yaml
from case_mcp.server import create_server

INJECTED = "inj\n    path = /\n    #"


@pytest.fixture
def sudo(tmp_path, monkeypatch):
    """Samba set up in a scratch HOME, and a fake sudo on PATH that records
    each call and what tee was given."""
    for var in ("VHIR_CASE_DIR", "VHIR_CASES_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    (home / ".vhir" / "samba.yaml").write_text(
        yaml.dump({"share_name": "cases", "wintools_ip": "192.0.2.5"})
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    # Not under test: group permissions need a real sift group, and the
    # notification needs a wintools host.
    monkeypatch.setattr(case_server, "_set_case_wintools_permissions", lambda d: None)
    monkeypatch.setattr(case_server, "notify_wintools_case_activated", lambda c: True)
    log = tmp_path / "sudo.log"
    stub = tmp_path / "bin" / "sudo"
    stub.parent.mkdir()
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "data = sys.stdin.read() if sys.argv[1:2] == ['tee'] else None\n"
        f"open({str(log)!r}, 'a').write(json.dumps([sys.argv[1:], data]) + '\\n')\n"
    )
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{stub.parent}:/usr/bin:/bin")

    def calls():
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    return calls


def _tool(tool, **kw):
    return create_server()._tool_manager._tools[tool].fn(**kw)


def test_case_init_leaves_the_share_alone(sudo, tmp_path):
    cases = tmp_path / INJECTED
    result = _tool(
        "case_init", name="n", case_id="inj1", share_wintools=True, cases_dir=str(cases)
    )
    assert "control character" in result.get("wintools_warning", ""), result
    assert (cases / "inj1" / "CASE.yaml").is_file()  # the case itself is made
    assert sudo() == []


def test_case_activate_leaves_the_share_alone(sudo, tmp_path):
    cases = tmp_path / INJECTED
    (cases / "inj1").mkdir(parents=True)
    (cases / "inj1" / "CASE.yaml").write_text("case_id: inj1\nstatus: open\n")
    result = _tool("case_activate", case_id="inj1", cases_dir=str(cases))
    assert "control character" in result.get("wintools_warning", ""), result
    assert sudo() == []


def test_anchor_a_plain_case_is_shared_as_before(sudo, tmp_path):
    cases = tmp_path / "cases"
    result = _tool(
        "case_init", name="n", case_id="ok1", share_wintools=True, cases_dir=str(cases)
    )
    assert result.get("wintools_shared") is True, result
    calls = sudo()
    assert calls[0][0] == ["tee", "/etc/samba/smb.conf.d/vhir-cases.conf"]
    assert f"    path = {cases / 'ok1'}\n" in calls[0][1]
    assert calls[0][1].count("path = ") == 1
