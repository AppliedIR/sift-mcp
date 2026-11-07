"""save_report on a case whose approved view is blanked (verify's case-level
failures are non-empty) ends the saved block's PROVENANCE with
`Approved findings: withheld: the case fails verification (see below)`, once,
never "No approved, verified findings.". Fixture (i) holds one cell per
measured case-level code, on a signed case and, for DUPLICATE_ID and
MALFORMED_RECORD, on a DRAFT case. Fixtures (ii) and (iii) are item-level: an
item drops to not verified, the view isn't blanked, no withheld line appears,
and the block names each verified finding, never the dropped one. Every cell
asserts the codes verify emits for it first, so its class is measured, not
assumed. Every cell saves.

The caller's text is saved with every IOC record's value defanged on a failing
case, and so is a value only verify's own read holds. vhir-cli's tests state
the same rows for `vhir report`."""

from __future__ import annotations

import json
import os
import sys

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vhir_cli import case_io, keys, ledger
from vhir_cli.case_io import signed_text
from vhir_cli.ledger_verify import approved_view, verify_case
from vhir_signing import _KEYS, NOT_CHECKED, sign_approved

W = "withheld: the case fails verification (see below)"
CASE = "INC-2026-WITHHELD"
AT = "2026-10-08T10:00:00+00:00"
VALUE = "c2.example.net"
DEFANGED = "c2[.]example[.]net"
B_ONLY = "b-only.example.org"
FINDING = {"id": "F-tester-001", "status": "APPROVED", "title": "Beacon to a C2 host",
           "confidence": "HIGH", "observation": f"beacons to {VALUE}",
           "interpretation": "C2", "iocs": []}  # fmt: skip
EVENT = {"id": "T-tester-001", "status": "APPROVED", "timestamp": "2026-10-08T09:00:00Z",
         "description": f"DNS query for {VALUE}"}  # fmt: skip
IOC = {"id": "IOC-tester-001", "value": VALUE, "type": "domain-name",
       "status": "APPROVED", "manually_reviewed": True, "approved_by": "tester",
       "approved_at": "2026-10-08T12:00:00+00:00",
       "source_findings": [FINDING["id"]]}  # fmt: skip
CONTENT = f"# Report\n\nBeacon to {VALUE}.\n"
NONE_SHOWN = "No approved, verified findings."


@pytest.fixture
def rs(tmp_path, monkeypatch):
    import report_mcp.server as rs

    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return rs


# --- building the cases -----------------------------------------------------
def _new_case(tmp_path, monkeypatch, items):
    case = tmp_path / CASE
    case.mkdir()
    (case / "reports").mkdir()
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    (case / "CASE.yaml").write_text(yaml.dump({"case_id": CASE, "name": "Withheld"}))
    for name, recs in items.items():
        (case / name).write_text(json.dumps(recs, indent=2))
    return case


def _writable(path):
    if path.exists():
        path.chmod(0o644)


def _rewrite(path, fn):
    _writable(path)
    path.write_text(json.dumps(fn(json.loads(path.read_text())), indent=2))


def _chain():
    path = ledger.chain_path(CASE)
    assert path.is_file(), path
    return path


def _put_lines(path, lines):
    _writable(path)
    path.write_text("".join(x + "\n" for x in lines))


def _edit_line(i, fn, key=None):
    """Line i of the box chain, changed by fn; re-signed with `key` if given."""
    lines = _chain().read_text().splitlines()
    obj = json.loads(lines[i])
    fn(obj)
    lines[i] = (ledger.sign_body(ledger.body_of(obj), key) if key
                else ledger.canonical(obj).decode("ascii"))  # fmt: skip
    _put_lines(_chain(), lines)


def _flip(obj):
    obj["sig"] = ("B" if obj["sig"][0] == "A" else "A") + obj["sig"][1:]


def _key(case):
    return _KEYS[(str(case), "tester")]


def _sign(key, kind, item, at=AT):
    """One approve line for `item`, signed with `key`."""
    d = [{"item_id": item["id"], "type": kind, "decision": "approve",
          "status_after": "APPROVED", "coupled_from": None,
          "content_snapshot": signed_text(item, kind),
          **({"checks": NOT_CHECKED} if kind != "ioc" else {})}]  # fmt: skip
    pub = keys.b64(keys.public_raw(key))
    bodies = ledger.prepare(CASE, d, "tester", pub, "cli", at)
    with ledger.case_lock(CASE) as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)


def _record(case, name, item_id):
    return next(i for i in json.loads((case / name).read_text()) if i["id"] == item_id)


def _aside(case):
    aside = case.parent / "aside"
    aside.mkdir()
    os.rename(_chain(), aside / _chain().name)


def _signed(tmp_path, monkeypatch):
    """An approved finding and event naming VALUE, signed; then an approved
    IOC record of VALUE citing the finding, signed on its own line."""
    case = _new_case(tmp_path, monkeypatch, {
        "findings.json": [FINDING], "timeline.json": [EVENT], "iocs.json": []})  # fmt: skip
    sign_approved(case)
    _sign(_key(case), "ioc", IOC, IOC["approved_at"])
    (case / "iocs.json").write_text(json.dumps([IOC], indent=2))
    return case


def _resigned(tmp_path, monkeypatch):
    """_signed with its chain made again by one sign_approved: line 1
    F-tester-001, line 2 T-tester-001, line 3 IOC-tester-001, one key."""
    case = _signed(tmp_path, monkeypatch)
    _aside(case)
    sign_approved(case)
    lines = [json.loads(x) for x in _chain().read_text().splitlines()]
    assert [x["item_id"] for x in lines] == [FINDING["id"], EVENT["id"], IOC["id"]]
    return case


def _two(tmp_path, monkeypatch):
    """_signed's shape with two approved findings and no IOC record, signed."""
    case = _signed(tmp_path, monkeypatch)
    second = dict(FINDING, id="F-tester-002", title="Second beacon",
                  observation=f"also beacons to {VALUE}")  # fmt: skip
    _rewrite(case / "findings.json", lambda d: [dict(FINDING), second])
    _rewrite(case / "iocs.json", lambda d: [])
    _aside(case)
    sign_approved(case)
    return case


def _draft(tmp_path, monkeypatch):
    """A finding, an event and an IOC record of VALUE, all DRAFT; nothing signed."""
    return _new_case(tmp_path, monkeypatch, {
        "findings.json": [dict(FINDING, status="DRAFT")],
        "timeline.json": [dict(EVENT, status="DRAFT")],
        "iocs.json": [{"id": IOC["id"], "value": VALUE, "type": "domain-name",
                       "status": "DRAFT", "source_findings": [FINDING["id"]]}]})  # fmt: skip


def cb_middle(case):
    _edit_line(1, lambda o: o.update(mode=o["mode"] + "x"))


def ccd(case):
    lines = _chain().read_text().splitlines()
    cid = ledger.chain_id(ledger.body_of(json.loads(lines[0])))
    obj = json.loads(lines[2])
    obj["at"] = "2026-10-08T10:00:01+00:00"
    lines[2] = ledger.sign_body(ledger.body_of(obj), _key(case))
    copies = case / "ledger" / "chains"
    copies.mkdir(parents=True, exist_ok=True)
    _put_lines(copies / f"{cid}.jsonl", lines)


def dup(case):
    _rewrite(case / "findings.json", lambda d: d + [dict(d[0])])


def item_missing(name):
    def change(case):
        _rewrite(case / name, lambda d: [])

    return change


def key_second(case):
    ev = _record(case, "timeline.json", EVENT["id"])
    _sign(Ed25519PrivateKey.generate(), "timeline", ev, ev.get("approved_at") or AT)


def mal_noid(case):
    _rewrite(case / "findings.json",
             lambda d: d + [{"status": "APPROVED", "title": "no id", "observation": "o"}])  # fmt: skip


def unparseable(case):
    lines = _chain().read_text().splitlines()
    _put_lines(_chain(), lines[:2] + ["{not json"])


def tampered_line(case):
    _sign(_key(case), "finding", _record(case, "findings.json", FINDING["id"]))
    _edit_line(0, _flip)


def tamper(index):
    def change(case):
        def edit(d):
            d[index]["observation"] += " (altered after approval)"
            return d

        _rewrite(case / "findings.json", edit)

    return change


def body_last(case):
    _edit_line(2, lambda o: o.update(mode=o["mode"] + "x"))


def sig_middle(case):
    _edit_line(1, _flip)


def no_line(case):
    _rewrite(case / "findings.json",
             lambda d: d + [dict(d[0], id="F-tester-009", title="Unsigned")])  # fmt: skip


BUILD = {"signed": _signed, "resigned": _resigned, "draft": _draft, "two": _two}
CASE_LEVEL = {  # cell: (how the case is built, the change, the codes verify emits)
    "CB_middle": ("resigned", cb_middle, ["CHAIN_BROKEN"]),
    "CCD": ("resigned", ccd, ["CHAIN_COPY_DIVERGED"]),
    "DUP_same_file": ("signed", dup, ["DUPLICATE_ID"]),
    "ITEM_MISSING_ioc": ("signed", item_missing("iocs.json"), ["ITEM_MISSING"]),
    "ITEM_MISSING_event": ("signed", item_missing("timeline.json"), ["ITEM_MISSING"]),
    "ITEM_MISSING_findings": ("resigned", item_missing("findings.json"),
                              ["ITEM_MISSING"]),
    "KEY_second_key": ("signed", key_second, ["KEY_CHANGED"]),
    "LEDGER_gone": ("signed", _aside, ["LEDGER_MISSING"]),
    "MAL_noid": ("signed", mal_noid, ["MALFORMED_RECORD"]),
    "UNPARSEABLE": ("resigned", unparseable, ["UNPARSEABLE_LINE"]),
    "TAMPERED_LINE": ("resigned", tampered_line, ["TAMPERED_LINE"]),
    "DRAFT_DUP": ("draft", dup, ["DUPLICATE_ID"]),
    "DRAFT_MAL_noid": ("draft", mal_noid, ["MALFORMED_RECORD"]),
}  # fmt: skip
ITEM_LEVEL = {  # cell: (build, change, not verified, shown findings)
    "TAMPER_one_of_two": ("two", tamper(1),
                          [("F-tester-002", "ALTERED_AFTER_APPROVAL")], ["F-tester-001"]),
    "BODY_last": ("resigned", body_last, [("IOC-tester-001", "TAMPERED")],
                  ["F-tester-001"]),
    "SIG_middle": ("resigned", sig_middle, [("T-tester-001", "TAMPERED")],
                   ["F-tester-001"]),
    "NO_LINE": ("resigned", no_line, [("F-tester-009", "APPROVED_NO_LINE")],
                ["F-tester-001"]),
    "TAMPER_single": ("signed", tamper(0),  # fixture (iii)
                      [("F-tester-001", "ALTERED_AFTER_APPROVAL")], []),
}  # fmt: skip
TITLES = {"F-tester-001": FINDING["title"], "F-tester-002": "Second beacon"}


# --- saving a report --------------------------------------------------------
def _save(rs, case, content=CONTENT):
    """(the tool's reply, the saved text): the save must have written."""
    tool = {t.name: t for t in rs.create_server()._tool_manager.list_tools()}
    got = tool["save_report"].fn(filename="r.md", content=content, profile="full")
    assert got.get("status") == "saved", got
    saved = (case / "reports" / "r.md").read_text()
    assert "Traceback" not in saved, saved[-800:]
    return got, saved


def _withheld_lines(lines):
    return [x for x in lines if x.endswith(f": {W}")]


# --- fixture (i): the view is blanked ---------------------------------------
@pytest.mark.parametrize("cell", sorted(CASE_LEVEL))
def test_a_blanked_view_saves_withheld(rs, tmp_path, monkeypatch, cell):
    build, change, codes = CASE_LEVEL[cell]
    case = BUILD[build](tmp_path, monkeypatch)
    change(case)
    result = verify_case(case)
    assert sorted({c for c, _ in result.failures}) == codes, result.failures
    view = approved_view(case)
    assert [view[k] for k in ("findings", "timeline", "iocs")] == [[], [], []]
    got, saved = _save(rs, case)
    for where, lines in (("reply", got["verification_block"]),
                         ("saved", saved.splitlines())):  # fmt: skip
        assert _withheld_lines(lines) == [f"Approved findings: {W}"], (where, lines)
        assert NONE_SHOWN not in lines, (where, lines)


@pytest.mark.parametrize("cell", sorted(CASE_LEVEL))
def test_a_failing_case_saves_the_callers_text_defanged(
    rs, tmp_path, monkeypatch, cell
):
    """VALUE is an IOC record's value, and the caller's text names it. The
    saved text holds it defanged only."""
    if cell == "ITEM_MISSING_ioc":
        pytest.skip("its iocs.json is []: no record holds VALUE, only text names it")
    build, change, codes = CASE_LEVEL[cell]
    case = BUILD[build](tmp_path, monkeypatch)
    change(case)
    assert sorted({c for c, _ in verify_case(case).failures}) == codes
    _, saved = _save(rs, case)
    assert saved.count(VALUE) == 0, saved[-1500:]
    assert DEFANGED in saved.split("\n\n```")[0], saved[-1500:]  # control: the text


# --- fixtures (ii) and (iii): an item drops, the view isn't blanked ---------
@pytest.mark.parametrize("cell", sorted(ITEM_LEVEL))
def test_an_item_level_failure_saves_no_withheld(rs, tmp_path, monkeypatch, cell):
    build, change, dropped, shown = ITEM_LEVEL[cell]
    case = BUILD[build](tmp_path, monkeypatch)
    change(case)
    assert verify_case(case).failures == []
    view = approved_view(case)
    assert [(x.get("id"), x["status"]) for x in view["not_verified"]] == dropped
    assert [i["id"] for i in view["findings"]] == shown
    got, saved = _save(rs, case)
    for where, lines in (("reply", got["verification_block"]),
                         ("saved", saved.splitlines())):  # fmt: skip
        assert _withheld_lines(lines) == [], (where, _withheld_lines(lines))
        for fid in shown:  # PROVENANCE names each verified finding
            assert f"[{fid}] {TITLES[fid]}" in lines, (where, fid)
        for fid, _ in dropped:
            assert not [x for x in lines if x.startswith(f"[{fid}]")], (where, fid)
        assert (NONE_SHOWN in lines) == (not shown), (where, lines)


# --- a value only verify's read holds ---------------------------------------
# held only by verify's read, in a record the view leaves out
C_ONLY = "c-only.example.net"
STATES = {  # state: (the record verify reads, what's signed for it, its expected status)
    "altered": (dict(IOC, id="IOC-tester-003", value=C_ONLY, approved_at=AT),
                dict(IOC, id="IOC-tester-003", value="c-old.example.net", approved_at=AT),
                "ALTERED_AFTER_APPROVAL"),
    "draft": ({k: v for k, v in dict(IOC, id="IOC-tester-003", value=C_ONLY,
                                     status="DRAFT").items()
               if k not in ("manually_reviewed", "approved_by", "approved_at")},
              None, "DRAFT"),
}  # fmt: skip


@pytest.mark.parametrize("state", sorted(STATES))
def test_a_value_only_verify_read_holds_is_defanged(rs, tmp_path, monkeypatch, state):
    """verify's read of iocs.json holds a signed IOC record of B_ONLY, and
    IOC-tester-003 of C_ONLY, that the file on disk doesn't (the state an edit
    between two reads leaves). IOC-tester-003 is in verify's records but not
    in the approved view: APPROVED and edited after signing, or DRAFT. The
    finding F-tester-002 names C_ONLY in its title, the caller's text names
    both. The saved text holds each defanged only."""
    third, signed, status = STATES[state]
    case = _signed(tmp_path, monkeypatch)
    second = dict(FINDING, id="F-tester-002", title=f"Second beacon to {C_ONLY}",
                  observation=f"beacons to {B_ONLY}", approved_by="tester",
                  approved_at=AT)  # fmt: skip
    _sign(_key(case), "finding", second)
    _rewrite(case / "findings.json", lambda d: d + [second])
    # approved_at as `_sign` signs it, or verify calls the record altered
    rec = dict(IOC, id="IOC-tester-002", value=B_ONLY, source_findings=[second["id"]],
               approved_at=AT)  # fmt: skip
    _sign(_key(case), "ioc", rec)
    if signed is not None:
        _sign(_key(case), "ioc", signed)
    verify_sees = json.dumps([IOC, rec, third]).encode()
    on_disk = (case / "iocs.json").read_text()
    assert B_ONLY not in on_disk and C_ONLY not in on_disk, on_disk
    real, hits = case_io.read_case_document, []

    def patched(path, *a, **kw):
        if sys._getframe(1).f_code.co_name == "_items" and path.name == "iocs.json":
            hits.append(path)
            return verify_sees
        return real(path, *a, **kw)

    monkeypatch.setattr(case_io, "read_case_document", patched)
    view = approved_view(case)
    result = view["result"]
    assert hits, "verify's read wasn't patched"
    assert result.failures == [], result.failures
    assert [i["id"] for i in view["iocs"]] == [IOC["id"], rec["id"]]
    # precondition: in verify's records, out of the view, with its own status
    read = [i for k, i in result.records if k == "iocs" and i.get("id") == third["id"]]
    assert read == [third], result.records
    assert C_ONLY not in [i.get("value") for i in view["iocs"]], view["iocs"]
    nv = [x["status"] for x in view["not_verified"] if x.get("id") == third["id"]]
    if status == "DRAFT":  # the view skips a record that isn't APPROVED
        assert (third["status"], nv) == ("DRAFT", []), view["not_verified"]
    else:
        assert nv == [status], view["not_verified"]
    content = f"# Report\n\nBeacon to {VALUE}, then {B_ONLY} and {C_ONLY}.\n"
    _, saved = _save(rs, case, content)
    assert saved.count(B_ONLY) == 0, saved[-1500:]
    assert saved.count(C_ONLY) == 0, saved[-1500:]
    text = saved.split("\n\n```")[0]  # control: the caller's text holds each defanged
    assert "b-only[.]example[.]org" in text, saved[-1500:]
    assert "c-only[.]example[.]net" in text, saved[-1500:]
