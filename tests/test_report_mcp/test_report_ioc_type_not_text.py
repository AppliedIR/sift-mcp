"""An IOC type that isn't text (None, 5, a list) or is empty raises nothing in
report-mcp: generate_report in the ioc, executive and full profiles, and
save_report, on a case whose approved finding cites the value and whose IOC
record of it was approved with the finding (the cascade). A list type holding
a network type (["domain-name"]) is network: the saved report holds its value
defanged. An empty type gives the same outcome as no type. vhir-cli's tests
state the same for its routes."""

from __future__ import annotations

import json
import traceback

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vhir_cli import keys, ledger
from vhir_cli.case_io import signed_text
from vhir_signing import _KEYS, AT, NOT_CHECKED

F, IOC = "F-tester-001", "IOC-tester-001"
TYPES = {"None": None, "5": 5, "list-domain-name": ["domain-name"]}
PROFILES = ("ioc", "executive", "full")


@pytest.fixture
def rs(tmp_path, monkeypatch):
    import report_mcp.server as rs

    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return rs


def _cascade(root, monkeypatch, case_id, t, v):
    """The finding and its IOC record approved together, as `vhir approve` of
    the finding signs them: one decision each, the record's coupled from the
    finding's, same key and time."""
    case = root / case_id
    case.mkdir()
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    (case / "CASE.yaml").write_text(yaml.dump({"case_id": case_id, "name": "Types"}))
    finding = {"id": F, "status": "APPROVED", "title": "Beacon", "confidence": "LOW",
               "observation": "o", "interpretation": "i", "iocs": [{"value": v, "type": t}],
               "approved_by": "tester", "approved_at": AT}  # fmt: skip
    record = {"id": IOC, "value": v, "type": t, "category": "network", "status": "APPROVED",
              "source_findings": [F], "manually_reviewed": False,
              "approved_by": "tester", "approved_at": AT}  # fmt: skip
    (case / "findings.json").write_text(json.dumps([finding]))
    (case / "iocs.json").write_text(json.dumps([record]))
    (case / "timeline.json").write_text("[]")
    key = _KEYS.setdefault((str(case), "tester"), Ed25519PrivateKey.generate())
    pub = keys.b64(keys.public_raw(key))
    decisions = [
        {"item_id": F, "type": "finding", "decision": "approve", "status_after": "APPROVED",
         "coupled_from": None, "content_snapshot": signed_text(finding, "finding"),
         "checks": NOT_CHECKED},
        {"item_id": IOC, "type": "ioc", "decision": "approve", "status_after": "APPROVED",
         "coupled_from": F, "content_snapshot": signed_text(record, "ioc")},
    ]  # fmt: skip
    ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    bodies = ledger.prepare(case_id, decisions, "tester", pub, "cli", AT)
    with ledger.case_lock(case_id) as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)
    return case


def _tool(rs, name, **kw) -> dict:
    """The tool's reply, parsed; a raise fails the row with where it came from."""
    tool = {t.name: t for t in rs.create_server()._tool_manager.list_tools()}[name]
    try:
        got = tool.fn(**kw)
    except Exception as e:  # noqa: BLE001  (the row's property: nothing raises)
        pytest.fail(f"{name} raised {type(e).__name__}: {e} at "
                    f"{traceback.extract_tb(e.__traceback__)[-1]}")  # fmt: skip
    return got if isinstance(got, dict) else json.loads(got)


def _outcome(rs, case, profile, v) -> dict:
    if profile == "save":
        got = _tool(rs, "save_report", filename="r7.md", content=f"# Report\n\nBeacon to {v}.\n",
                    profile="full")  # fmt: skip
        path = case / "reports" / "r7.md"
        body = path.read_text() if path.exists() else None
    else:
        got = _tool(rs, "generate_report", profile=profile)
        body = None
    return {"error": got.get("error"), "saved": body is not None,
            "live": (body or "").count(v), "defanged": (body or "").count(v.replace(".", "[.]")),
            "returned": json.dumps(got, default=str).count(v)}  # fmt: skip


@pytest.mark.parametrize("profile", [*PROFILES, "save"])
@pytest.mark.parametrize("tname", list(TYPES))
def test_report_mcp_raises_nothing(rs, tmp_path, monkeypatch, tname, profile):
    t, v = TYPES[tname], f"t7-{tname}.example.com"
    case = _cascade(tmp_path, monkeypatch, "C-7", t, v)
    got = _outcome(rs, case, profile, v)
    assert got["error"] is None, got["error"]
    if profile == "save":
        assert got["saved"], "the report wasn't saved"
        if tname == "list-domain-name":
            assert got["live"] + got["defanged"] > 0, (
                "the value isn't in the saved report"
            )
            assert got["live"] == 0, f"{v} is live in the saved report"


@pytest.mark.parametrize("profile", [*PROFILES, "save"])
def test_an_empty_type_is_no_type(rs, tmp_path, monkeypatch, profile):
    v = "t7-twin.example.com"
    got = {}
    for name, t in (("empty", ""), ("none", None)):
        root = tmp_path / name
        root.mkdir()
        got[name] = _outcome(
            rs, _cascade(root, monkeypatch, f"C-7{name}", t, v), profile, v
        )
    assert got["none"]["error"] is None, got["none"]["error"]
    assert got["empty"] == got["none"]
