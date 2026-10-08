"""The page's signing block, run in Node's WebCrypto against the gateway.

The block between `// BEGIN vhir-commit-sign` and `// END vhir-commit-sign`
in the v2 page is the browser's whole signing path: it checks the plan
against the dialog's frozen copy, signs in, unwraps the key and signs each
body as handed. These rows run that exact text in Node and drive the
gateway with Python, as the page would.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from vhir_cli import keys
from vhir_cli.case_io import IOC_DERIVED_KEYS, VIEW_EXCLUDES
from vhir_cli.ledger_verify import verify_case

from .conftest import PASSWORD, enrol, event, finding, reviewed

STATIC = Path(__import__("case_dashboard").__file__).parent / "static"
V2 = STATIC / "v2" / "index.html"


def _node() -> str:
    node = shutil.which("node")
    if not node:
        pytest.skip("node isn't installed")
    major = int(subprocess.run([node, "--version"], capture_output=True, text=True)
                .stdout.strip().lstrip("v").split(".")[0])  # fmt: skip
    if major < 20:
        pytest.skip("the signing rows need Node 20 or later (WebCrypto Ed25519)")
    return node


def block(page: Path = V2) -> str:
    text = page.read_text()
    found = re.findall(
        r"// BEGIN vhir-commit-sign\n(.*?)// END vhir-commit-sign", text, re.S
    )
    assert len(found) == 1, "one signing block"
    return found[0]


DRIVER = """
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const T = VHIR_SIGN._test;
(async () => {
  const out = {};
  if (input.op === 'constants') {
    Object.assign(out, {view1: T.VIEW1_EXCLUDES, derived: T.IOC_DERIVED,
                        editable: T.EDITABLE, ioc_editable: T.IOC_EDITABLE});
  } else if (input.op === 'check') {
    out.problems = await T.checkPlan(input.frozen, input.plan, input.selected);
    out.shown = T.shownOf(input.plan);
  } else if (input.op === 'login') {
    const auth = await T.deriveAuth(input.password, input.plan.salt_auth, input.plan.iterations);
    out.response = await T.loginResponse(auth, input.plan.nonce);
  } else if (input.op === 'sign') {
    const kek = await T.deriveKek(input.password, input.key.salt_ledger, input.key.iterations);
    try {
      const key = await T.unwrapKey(kek, input.key, input.examiner);
      out.sigs = await T.signBodies(key, input.plan);
    } catch (e) { out.error = String(e && e.name || e); }
  }
  process.stdout.write(JSON.stringify(out));
})().catch(e => { process.stderr.write(String(e.stack || e)); process.exit(1); });
"""


def run(op: str, **data) -> dict:
    node = _node()
    script = (
        "var API_BASE = ''; function apiHeaders() { return {}; }\n" + block() + DRIVER
    )
    r = subprocess.run([node, "-e", script], input=json.dumps({"op": op, **data}),
                       capture_output=True, text=True, timeout=120)  # fmt: skip
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def frozen(portal, items) -> dict:
    """What the dialog freezes: the staged entries and the items as served."""
    return {
        "items": items,
        "findings": portal.get("/api/findings").json(),
        "timelineEvents": portal.get("/api/timeline").json(),
        "iocs": portal.get("/api/iocs").json(),
        "case_id": "C-1",
        "examiner": "steve",
    }


@pytest.fixture
def case(portal):
    enrol("steve")
    portal.write("findings.json", [finding("F-steve-001", timeline_event_id="T-steve-001"),
                                   finding("F-steve-002")])  # fmt: skip
    portal.write("timeline.json", [event("T-steve-001", "F-steve-001")])
    portal.write("iocs.json", [])
    return portal


def _sign_in_node(case, entries):
    plan = case.plan(entries).json()
    login = run("login", password=PASSWORD, plan=plan)
    k = case.post("/api/commit/key", {"challenge_id": plan["challenge_id"], **login})
    assert k.status_code == 200, k.text
    return plan, k.json()


def test_the_block_signs_what_the_gateway_accepts(case):
    entries = [dict(reviewed(case, "F-steve-001"), staged_by="steve")]
    plan, key = _sign_in_node(case, entries)
    checked = run("check", frozen=frozen(case, entries), plan=plan, selected=entries)
    assert checked["problems"] == []
    signed = run("sign", password=PASSWORD, key=key, examiner="steve", plan=plan)
    r = case.commit(plan, signed["sigs"])
    assert r.status_code == 200, r.text
    assert [ln["item_id"] for ln in case.chain()] == ["F-steve-001", "T-steve-001"]
    assert verify_case(case.dir).exit_code == 0


def test_a_wrong_passphrase_fails_the_login_and_opens_no_key(case):
    entries = [reviewed(case, "F-steve-001")]
    plan = case.plan(entries).json()
    login = run("login", password="not the passphrase", plan=plan)
    k = case.post("/api/commit/key", {"challenge_id": plan["challenge_id"], **login})
    assert k.status_code == 401 and k.json()["code"] == "BAD_PASSWORD"


def test_a_key_swapped_in_the_file_does_not_unwrap(case):
    entries = [reviewed(case, "F-steve-001")]
    plan, key = _sign_in_node(case, entries)
    other = keys.new_credential("steve", PASSWORD)
    swapped = dict(key, public_key=keys.active(other)["public_key"])
    assert run("sign", password=PASSWORD, key=swapped, examiner="steve", plan=plan)[
        "error"
    ]


def _check(case, entries, mutate):
    plan = case.plan(entries).json()
    mutate(plan)
    return run("check", frozen=frozen(case, entries), plan=plan, selected=entries)[
        "problems"
    ]


def _edit_body(plan, i, **changes):
    body = json.loads(plan["bodies"][i]["body"])
    body.update(changes)
    plan["bodies"][i]["body"] = json.dumps(body)


def test_a_changed_snapshot_is_refused(case):
    import hashlib

    entries = [reviewed(case, "F-steve-001")]

    def swap(plan):
        body = json.loads(plan["bodies"][0]["body"])
        snap = json.loads(body["content_snapshot"])
        snap["title"] = "not what you saw"
        text = json.dumps(snap, sort_keys=True)
        _edit_body(plan, 0, content_snapshot=text,
                   content_sha256=hashlib.sha256(text.encode()).hexdigest())  # fmt: skip

    assert any("title differ" in p for p in _check(case, entries, swap))


def test_a_snapshot_that_does_not_match_its_hash_is_refused(case):
    entries = [reviewed(case, "F-steve-001")]
    problems = _check(
        case, entries, lambda p: _edit_body(p, 0, content_sha256="0" * 64)
    )
    assert any("does not match its hash" in p for p in problems)


@pytest.mark.parametrize(
    "field,value,why",
    [("examiner", "mallory", "signed as mallory"), ("case_id", "C-2", "another case"),
     ("at", "2020-01-01T00:00:00+00:00", "not dated by this plan"),
     ("decision", "reject", "planned as reject"), ("mode", "cli", "not a portal decision")],
)  # fmt: skip
def test_a_body_that_does_not_follow_the_entry_is_refused(case, field, value, why):
    entries = [reviewed(case, "F-steve-001")]
    problems = _check(case, entries, lambda p: _edit_body(p, 0, **{field: value}))
    assert any(why in p for p in problems), problems


def test_an_extra_direct_decision_is_refused(case):
    entries = [reviewed(case, "F-steve-001")]
    other = case.plan([reviewed(case, "F-steve-002")]).json()

    def add(plan):
        plan["bodies"].append(other["bodies"][0])

    assert any("not the ones selected" in p for p in _check(case, entries, add))


def test_a_cascade_from_nothing_decided_here_is_refused(case):
    entries = [reviewed(case, "F-steve-002")]
    cascade = case.plan([reviewed(case, "F-steve-001")]).json()["bodies"][1]

    def add(plan):
        plan["bodies"].append(cascade)

    problems = _check(case, entries, add)
    assert any("which is not decided here" in p or "not dated" in p for p in problems)


def test_the_shown_set_ignores_only_seq_prev_at_and_nonce(case):
    entries = [reviewed(case, "F-steve-001")]
    a = case.plan(entries).json()
    b = case.plan(entries).json()
    f = frozen(case, entries)
    assert (
        run("check", frozen=f, plan=a, selected=entries)["shown"]
        == run("check", frozen=f, plan=b, selected=entries)["shown"]
    )


def test_the_block_s_constants_are_vhir_s():
    out = run("constants")
    assert set(out["view1"]) == set(VIEW_EXCLUDES[1])
    assert set(out["derived"]) == set(IOC_DERIVED_KEYS)
    from case_dashboard import signing
    from vhir_cli.decide import DELTA_EDITABLE_FIELDS

    assert set(out["editable"]) == set(DELTA_EDITABLE_FIELDS)
    assert set(out["ioc_editable"]) == set(signing._IOC_EDITABLE)


def test_one_signing_block_and_submit_inside_it():
    page = V2.read_text()
    assert page.count("// BEGIN vhir-commit-sign") == 1
    assert page.count("// END vhir-commit-sign") == 1
    assert "function submitCommit()" in block()
    assert page.count("function submitCommit(") == 1
    v1 = (STATIC / "index.html").read_text()
    assert "vhir-commit-sign" not in v1 and "/api/commit" not in v1
    assert 'href="/portal/"' in v1


def test_the_passphrase_field_is_for_the_current_password():
    assert (
        'id="commitPassword" autocomplete="current-password" disabled' in V2.read_text()
    )


def test_a_wrapped_key_that_isn_t_the_served_public_key_is_refused(case):
    """The page checks that the unwrapped key is the served public key: a
    key wrapped under the right KEK and AAD, but holding another private key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    entries = [reviewed(case, "F-steve-001")]
    plan, key = _sign_in_node(case, entries)
    other = Ed25519PrivateKey.generate()
    der = other.private_bytes(serialization.Encoding.DER,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())  # fmt: skip
    kek = keys.derive_kek(PASSWORD, key["salt_ledger"])
    nonce = b"\x01" * 12
    blob = nonce + AESGCM(kek).encrypt(
        nonce, der, keys._aad("steve", key["public_key"])
    )
    forged = dict(key, wrapped_private=keys.b64(blob))
    assert run("sign", password=PASSWORD, key=forged, examiner="steve", plan=plan)[
        "error"
    ]
