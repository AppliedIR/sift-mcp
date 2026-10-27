"""What a forensic-rag reply says when its entry isn't recorded: no case under
`audit`, a case gone or a failed write under `warning`, after any warning
already there, in the same words as every other server's."""

from __future__ import annotations

import pytest
from rag_mcp.server import RAGServer
from sift_common import audit as audit_mod
from sift_common.audit import AuditWriter

NO_CASE = "not recorded: no case was active for this call"
GONE_PATH = "/cases/moved-away"
GONE = (
    f"not recorded: {GONE_PATH} is no longer a case (no CASE.yaml). "
    "The call itself ran; calling it again repeats it."
)
REASON = "[Errno 28] No space left on device"
FAILED = (
    f"Audit write failed — not recorded: {REASON}. "
    "The call itself ran; calling it again repeats it."
)
DETAIL = {"case_gone": GONE_PATH, "write_failed": REASON}


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    return home


def _fix(monkeypatch, kind: str) -> None:
    def record(self, tool, *args, **kwargs):
        if kind == "recorded":
            return audit_mod.AuditOutcome(audit_id=f"{tool}-stub-001")
        return audit_mod.AuditOutcome(kind=kind, detail=DETAIL.get(kind, ""))

    monkeypatch.setattr(AuditWriter, "record", record)


def _search(result: dict) -> dict:
    server = object.__new__(RAGServer)
    server._audit = AuditWriter("forensic-rag-mcp")
    return server._wrap_response("search", {"q": "x"}, dict(result))


@pytest.mark.parametrize("kind", ["recorded", "no_case", "case_gone", "write_failed"])
def test_a_search_answers_each_outcome_from_the_table(kind, monkeypatch):
    _fix(monkeypatch, "recorded")
    control = _search({"results": []})
    _fix(monkeypatch, kind)
    reply = _search({"results": []})
    warning = reply.get("warning") or ""
    if kind == "recorded":
        assert "audit" not in reply and "not recorded" not in warning, reply
    elif kind == "no_case":
        assert reply.get("audit") == NO_CASE and "not recorded" not in warning, reply
    else:
        text = GONE if kind == "case_gone" else FAILED
        assert "audit" not in reply and warning.endswith(text), reply
        assert warning.count("not recorded") == 1, reply
    own = {"audit", "warning", "audit_id"}
    assert set(reply) - own == set(control) - own


def test_an_earlier_warning_is_kept_and_the_note_follows_it(monkeypatch):
    _fix(monkeypatch, "write_failed")
    reply = _search({"results": [], "warning": "index is stale"})
    assert reply["warning"] == f"index is stale | {FAILED}"


def test_with_no_case_a_search_says_so_and_warns_nothing():
    reply = _search({"results": []})
    assert reply.get("audit") == NO_CASE and "warning" not in reply, reply
