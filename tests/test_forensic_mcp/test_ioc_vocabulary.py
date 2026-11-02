"""The IOC type vocabulary: one table of ids, each with its category, label and
aliases. record_finding stores an IOC typed with an id, an alias, or either in
another case or separator, as the id with the id's category. A type the table
doesn't hold is refused, naming it and listing the ids by category, and
nothing is written. validate_finding gives the same answer. A type left out,
empty or whitespace is detected from the value, as before.

The table, the aliases and the refused spellings are stated in
ioc_vocabulary.json beside this file; the record_finding tool text and the
IOC template in the FORENSIC_DISCIPLINE.md copies name the ids.

The real forensic-mcp server runs in-process on scratch cases."""

from __future__ import annotations

import ast
import asyncio
import json
import re
from pathlib import Path

import pytest
import sift_common
from forensic_mcp.server import create_server

from .test_finding_challenge import (  # noqa: F401 (case and home are fixtures)
    FINDING,
    _record,
    case,
    home,
)

DATA = json.loads(Path(__file__).with_name("ioc_vocabulary.json").read_text())
IDS = [i for _, i, _ in DATA["ids"]]
CATEGORY = {i: c for c, i, _ in DATA["ids"]}
LABEL = {i: lb for _, i, lb in DATA["ids"]}
VALUES = DATA["values"]
ALIASES = [(a, i) for i, names in DATA["aliases"].items() for a in names]
REFUSED = DATA["refused"]
STORED_BY_BASE = DATA["stored_by_base"]  # ids base already files rightly
REPO = Path(__file__).resolve().parents[2]


def fold(t: str) -> str:
    return re.sub(r"[\s_-]", "", t.strip().lower())


def variant(t: str) -> str:
    """The same spelling in another case and with another separator."""
    if "-" in t:
        return t.upper().replace("-", "_")
    if "_" in t:
        return t.upper().replace("_", " ")
    return t.upper()


# Every spelling the table takes, and the id it stores.
SPELLINGS = (
    [(i, i) for i in IDS]
    + [(variant(i), i) for i in IDS]
    + ALIASES
    + [(variant(a), i) for a, i in ALIASES]
    + list(DATA["accepted_census"].items())
    + [(LABEL[i], i) for i in IDS]
)
SPELLINGS = list(dict.fromkeys(SPELLINGS))
WRITTEN = [s for s in SPELLINGS if not (s[0] == s[1] and s[1] in STORED_BY_BASE)]


def _validate(finding: dict) -> dict:
    r = asyncio.run(
        create_server(reference_mode="tools").call_tool(
            "validate_finding", {"finding_json": finding}
        )
    )
    r = r[0] if isinstance(r, tuple) else r
    return json.loads(r[0].text)


def _records(case: Path) -> list[dict]:
    path = case / "iocs.json"
    return json.loads(path.read_text()) if path.is_file() else []


def _snapshot(case: Path) -> tuple[dict, list[str]]:
    audit = case / "audit" / "forensic-mcp.jsonl"
    files = {
        str(p.relative_to(case)): p.read_bytes()
        for p in case.rglob("*")
        if p.is_file() and p != audit
    }
    lines = audit.read_text().splitlines() if audit.is_file() else []
    return files, lines


def _mentions(text: str) -> list[tuple[int, str]]:
    """(position, id) of every id named in the text, in order."""
    found = []
    for i in IDS:
        for m in re.finditer(rf"(?<![\w:-]){re.escape(i)}(?![\w:-])", text):
            found.append((m.start(), i))
    return sorted(found)


def _ungrouped(text: str) -> list[str]:
    """Categories whose ids are not all named in one run of that category."""
    runs: list[tuple[str, set]] = []
    for _, i in _mentions(text):
        if runs and runs[-1][0] == CATEGORY[i]:
            runs[-1][1].add(i)
        else:
            runs.append((CATEGORY[i], {i}))
    bad = []
    for c in dict.fromkeys(CATEGORY.values()):
        want = {i for i in IDS if CATEGORY[i] == c}
        if not any(rc == c and want <= got for rc, got in runs):
            bad.append(c)
    return bad


def _vocabulary():
    from sift_common import ioc_types

    return ioc_types


# --- the table as stated ----------------------------------------------------


def test_the_stated_table_has_no_two_spellings_folding_alike():
    keys = [fold(i) for i in IDS] + [fold(a) for a, _ in ALIASES]
    assert len(IDS) == 37 and len(ALIASES) == 99
    assert sorted(set(CATEGORY.values())) == [
        "host", "identity", "network", "system", "unknown"
    ]  # fmt: skip
    assert len(keys) == len(set(keys)), sorted(k for k in keys if keys.count(k) > 1)
    assert not [r for r in REFUSED if fold(r) in keys]
    assert set(STORED_BY_BASE) <= set(IDS)
    folded = dict(zip(keys, IDS + [i for _, i in ALIASES], strict=True))
    assert all(folded[fold(t)] == i for t, i in DATA["accepted_census"].items())
    assert not [lb for lb in LABEL.values() if lb and (":" in lb or "_" in lb)]


# --- the module -------------------------------------------------------------


@pytest.mark.parametrize(("given", "want"), SPELLINGS)
def test_each_spelling_the_table_takes_folds_to_its_id(given, want):
    assert _vocabulary().canonical(given) == want


@pytest.mark.parametrize("given", REFUSED)
def test_a_refused_spelling_folds_to_no_id(given):
    assert _vocabulary().canonical(given) is None


@pytest.mark.parametrize("ioc_id", IDS)
def test_each_id_has_its_label(ioc_id):
    label = _vocabulary().label(ioc_id)
    if LABEL[ioc_id] is not None:
        assert label == LABEL[ioc_id]
    assert label and label != ioc_id and ":" not in label and "_" not in label


def test_each_alias_is_written_only_inside_its_ids_entry():
    tree = ast.parse((Path(_vocabulary().__file__).parent / "ioc_types.py").read_text())
    parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
    id_folds = {fold(i): i for i in IDS}
    alias_folds = {fold(a): i for a, i in ALIASES}

    seen, misplaced = set(), []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        # A string of aliases: each whitespace-separated word folds to one.
        words = [fold(w) for w in node.value.split()]
        if not words or not all(w in alias_folds for w in words):
            continue
        seen.update(words)
        # Its holder: the entry whose key is an id and whose value holds it.
        child, held = node, set()
        while child in parents and not held:
            parent = parents[child]
            if isinstance(parent, ast.Dict) and child in parent.values:
                k = parent.keys[parent.values.index(child)]
                if isinstance(k, ast.Constant) and fold(str(k.value)) in id_folds:
                    held = {id_folds[fold(k.value)]}
            child = parent
        owners = {alias_folds[w] for w in words}
        if held != owners or len(owners) != 1:
            misplaced.append((node.value, sorted(owners), sorted(held)))
    assert not misplaced
    assert seen == set(alias_folds)


def test_the_map_canonical_reads_holds_exactly_the_spellings_the_entries_declare():
    vocab = _vocabulary()
    names = vocab.canonical.__code__.co_names
    maps = [n for n in names if isinstance(vars(vocab).get(n), dict)]
    assert len(maps) == 1, maps
    used = vars(vocab)[maps[0]]
    declared = {
        fold(s): i for i, (_, _, more) in vocab.IDS.items() for s in [i, *more.split()]
    }
    assert {k: v for k, v in used.items() if declared.get(k) != v} == {}
    assert {k: v for k, v in declared.items() if used.get(k) != v} == {}


def test_the_misp_types_the_table_places_are_the_stated_ones():
    canonical = _vocabulary().canonical
    placed = sorted([t, canonical(t)] for t in DATA["misp_types"] if canonical(t))
    assert placed == sorted(DATA["misp_placed"])


# --- record_finding and validate_finding --------------------------------------


def _stores_as(case: Path, given: str, want: str) -> None:
    result = _record({**FINDING, "iocs": [{"value": VALUES[want], "type": given}]})
    assert result["status"] == "STAGED", result
    (record,) = _records(case)
    assert (record["value"], record["type"], record["category"]) == (
        VALUES[want], want, CATEGORY[want]
    )  # fmt: skip


@pytest.mark.parametrize(("given", "want"), WRITTEN)
def test_record_finding_stores_each_spelling_as_its_id_and_category(case, given, want):  # noqa: F811
    _stores_as(case, given, want)


@pytest.mark.parametrize("ioc_id", STORED_BY_BASE)
def test_record_finding_still_stores_an_id_it_already_filed_rightly(case, ioc_id):  # noqa: F811
    _stores_as(case, ioc_id, ioc_id)


@pytest.mark.parametrize("ioc_id", IDS)
def test_validate_finding_accepts_each_id(case, ioc_id):  # noqa: F811
    result = _validate({**FINDING, "iocs": [{"value": VALUES[ioc_id], "type": ioc_id}]})
    assert result["valid"] is True, result


KINDS = {  # each kind the refusal says the detector knows -> the ids it files
    "URL": {"url"},
    "email address": {"email-addr"},
    "MD5": {"file:hash:md5"},
    "SHA1": {"file:hash:sha1"},
    "SHA256": {"file:hash:sha256"},
    "IPv4": {"ipv4-addr"},
    "IPv6": {"ipv6-addr"},
    "domain": {"domain-name"},
    "file name or path": {"file:name", "file:path"},
    "registry key": {"registry-key"},
    "scheduled task": {"scheduled-task"},
    "SID": {"windows-sid"},
    "DOMAIN\\user account": {"user-account"},
}
UNUSUAL = (
    "Every other kind must be typed, and so must a value whose form is unusual "
    "for its kind."
)
WHERE = "What each type holds is in the iocs part of record_finding's description."


def _detected_kinds(text: str) -> list[str]:
    """The kinds the text says may be left untyped."""
    m = re.search(
        r"Leaving the type out works only for the kinds the detector knows, in "
        r"their usual forms: (.+?)\. " + re.escape(UNUSUAL),
        text,
    )
    assert m, text
    return re.split(r", and |, ", m.group(1))


def _refusal_text(errors: list, given: str, value: str, n: int = 1) -> str:
    text = " ".join(map(str, errors))
    for part in (
        (
            f'Nothing was recorded, neither the finding nor IOC {n} ({value}): "{given}" '
            "is not an IOC type Valhuntir knows."
        ),
        "Send the finding again with one of these types:",
        WHERE,
    ):
        assert part in text, text
    assert sorted(_detected_kinds(text)) == sorted(KINDS), text
    assert "with no type and the type will be detected" not in text, text
    assert not [i for i in IDS if i not in {m for _, m in _mentions(text)}], text
    assert not _ungrouped(text), text
    return text


def _refused(case: Path, finding: dict) -> dict:
    """record_finding refuses the finding and writes nothing but its audit line."""
    _record({**FINDING, "iocs": ["10.0.0.1"]})  # a case with records already
    files, lines = _snapshot(case)
    result = _record(finding)
    assert result["status"] == "VALIDATION_FAILED", result
    assert "finding_id" not in result
    after, after_lines = _snapshot(case)
    assert after == files
    assert after_lines[: len(lines)] == lines and len(after_lines) == len(lines) + 1
    assert json.loads(after_lines[-1]).get("tool") == "record_finding"
    return result


def test_each_kind_the_refusal_names_is_one_the_detector_files():
    source = (
        REPO / "packages/forensic-mcp/src/forensic_mcp/case/manager.py"
    ).read_text()
    detector = next(
        n
        for n in ast.walk(ast.parse(source))
        if isinstance(n, ast.FunctionDef) and n.name == "_detect_ioc_type"
    )
    filed = {
        n.value.elts[0].value
        for n in ast.walk(detector)
        if isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple)
    }
    result = _validate({**FINDING, "iocs": [{"value": "zz.example.net", "type": "zz"}]})
    named = _detected_kinds(" ".join(map(str, result.get("errors", []))))
    assert sorted(named) == sorted(KINDS)
    assert not [k for k in named if not KINDS[k] <= filed]


ROUTES = ["list", "mapping", "validate"]


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("given", REFUSED)
def test_a_spelling_the_table_doesnt_hold_is_refused_and_nothing_written(
    case, given, route
):  # noqa: F811
    value = "zz.example.net"
    ioc = {"value": value, "type": given}
    finding = {**FINDING, "iocs": {"seen": [ioc]} if route == "mapping" else [ioc]}
    if route == "validate":
        result = _validate(finding)
        assert result["valid"] is False, result
        _refusal_text(result["errors"], given, value)
        return
    _refusal_text(_refused(case, finding)["errors"], given, value)


def test_an_unknown_type_under_a_type_named_key_is_refused(case):  # noqa: F811
    ioc = {"value": "zz4c.example.net", "type": "frobnitz"}
    result = _refused(case, {**FINDING, "iocs": {"IPv4": [ioc]}})
    _refusal_text(result["errors"], "frobnitz", "zz4c.example.net")


def test_an_unknown_type_past_the_first_hundred_iocs_is_refused(case):  # noqa: F811
    iocs = [f"10.40.{i // 250}.{i % 250 + 1}" for i in range(100)]
    iocs.append({"value": "zz7.example.net", "type": "frobnitz"})
    result = _refused(case, {**FINDING, "iocs": iocs})
    _refusal_text(result["errors"], "frobnitz", "zz7.example.net", n=101)


@pytest.mark.parametrize("value", ["", "  "], ids=["empty", "spaces"])
def test_an_empty_value_is_skipped_whatever_its_type(case, value):  # noqa: F811
    result = _record({**FINDING, "iocs": [{"value": value, "type": "frobnitz"}]})
    assert result["status"] == "STAGED", result
    assert _records(case) == []


def test_validate_finding_still_takes_a_spelling_base_took():
    result = _validate({**FINDING, "iocs": [{"value": "10.20.30.40", "type": "IPv4"}]})
    assert result["valid"] is True, result


# --- the ipv4-addr type ----------------------------------------------------------

IPV4_SPELLINGS = ["ipv4-addr", "IPv4", "IPV4-ADDR", " ipv4-addr "] + [
    a for a, i in ALIASES if i == "ipv4-addr"
]


def _not_ipv4_text(errors: list, given: str, value: str, n: int = 1) -> str:
    text = " ".join(map(str, errors))
    for part in (
        (
            f"Nothing was recorded, neither the finding nor IOC {n} ({value}): its type "
            f'"{given}" means ipv4-addr, but the value is not one IPv4 address with an '
            "optional port."
        ),
        (
            "Send the finding again with this IOC typed ipv6-addr if it is an IPv6 "
            "address, with no type to have it detected, or with the address alone."
        ),
        WHERE,
    ):
        assert part in text, text
    return text


@pytest.mark.parametrize("given", IPV4_SPELLINGS)
def test_an_ipv4_type_on_an_ipv6_address_is_refused(case, given):  # noqa: F811
    result = _refused(case, {**FINDING, "iocs": [{"value": "fe80::5", "type": given}]})
    _not_ipv4_text(result["errors"], given, "fe80::5")


@pytest.mark.parametrize(
    ("iocs", "given", "value"),
    [
        (
            [
                {"value": "fe80::1", "type": "ip"},
                {"value": "fe80::2", "type": "ip"},
                {"value": "2001:db8::1", "type": "IPv4"},
                {"value": "2001:db8::7", "type": "IPv4"},
            ],
            "ip",
            "fe80::1",
        ),
        (
            [
                {"value": "fe80::1", "type": "ipv4-addr"},
                {"value": "fe80::2", "type": "ipv4-addr"},
            ],
            "ipv4-addr",
            "fe80::1",
        ),
        (
            [{"value": "10.20.30.89:443:80", "type": "IPv4"}],
            "IPv4",
            "10.20.30.89:443:80",
        ),
        (
            [{"value": "10.20.30.91/24:443", "type": "IPv4"}],
            "IPv4",
            "10.20.30.91/24:443",
        ),
        ([{"value": "999.20.30.41:443", "type": "IPv4"}], "IPv4", "999.20.30.41:443"),
    ],
    ids=[
        "ipv6 typed ip and IPv4",
        "ipv6 typed ipv4-addr",
        "two ports",
        "prefix and port",
        "octet over 255",
    ],
)
def test_an_ipv4_type_on_a_value_that_is_not_one_ipv4_address_is_refused(
    case, iocs, given, value
):  # noqa: F811
    _not_ipv4_text(_refused(case, {**FINDING, "iocs": iocs})["errors"], given, value)


def test_validate_finding_refuses_an_ipv4_type_on_an_ipv6_address():
    ioc = {"value": "fe80::9", "type": "ipv4-addr"}
    result = _validate({**FINDING, "iocs": [ioc]})
    assert result["valid"] is False, result
    _not_ipv4_text(result["errors"], "ipv4-addr", "fe80::9")


@pytest.mark.parametrize(
    ("ioc", "check"),
    [
        ({"value": "a" * 300, "type": "b" * 300}, _refusal_text),
        ({"value": "f" * 300, "type": "i" + "-" * 298 + "p"}, _not_ipv4_text),
    ],
    ids=["unknown type", "ipv4 type"],
)
def test_a_refusal_echoes_a_long_value_and_type_cut_short(case, ioc, check):  # noqa: F811
    errors = _refused(case, {**FINDING, "iocs": [ioc]})["errors"]
    text = check(errors, ioc["type"][:64], ioc["value"][:200])
    assert ioc["type"][:65] not in text and ioc["value"][:201] not in text, text


def test_an_ipv4_type_takes_a_defanged_address_and_port(case):  # noqa: F811
    iocs = [
        {"value": "10[.]20[.]30[.]43", "type": "IPv4"},
        {"value": "10[.]20[.]30[.]44[:]443", "type": "ip"},
    ]
    assert _record({**FINDING, "iocs": iocs})["status"] == "STAGED"


def test_an_ipv4_type_takes_an_address_with_a_prefix(case):  # noqa: F811
    first = _record(
        {
            **FINDING,
            "iocs": [
                {"value": "10.20.30.93/24", "type": "ipv4-addr"},
                "10.20.30.92/24",
                {"value": "10.20.30.91/24", "type": "ipv4-addr"},
            ],
        }
    )
    second = _record({**FINDING, "iocs": ["10.20.30.91/24"]})
    assert first["status"] == second["status"] == "STAGED", (first, second)
    records = {r["value"]: r for r in _records(case)}
    assert sorted(records) == ["10.20.30.91/24", "10.20.30.92/24", "10.20.30.93/24"]
    for value in records:
        assert (records[value]["type"], records[value]["category"]) == (
            "ipv4-addr", "network"
        )  # fmt: skip
    assert sorted(records["10.20.30.91/24"]["source_findings"]) == sorted(
        [first["finding_id"], second["finding_id"]]
    )


PORTED = {  # value as given -> as stored when the port is kept
    "10.20.30.41:443": "10.20.30.41:443",
    "10[.]20[.]30[.]41:8080": "10.20.30.41:8080",
}


@pytest.mark.parametrize("value", PORTED)
@pytest.mark.parametrize("given", IPV4_SPELLINGS)
def test_an_ipv4_type_drops_the_port_only_when_spelled_as_the_id(case, given, value):  # noqa: F811
    result = _record({**FINDING, "iocs": [{"value": value, "type": given}]})
    assert result["status"] == "STAGED", result
    (record,) = _records(case)
    kept = PORTED[value]
    want = (
        (kept.rsplit(":", 1)[0], "ipv4-addr") if given == "ipv4-addr" else (kept, given)
    )
    assert (record["value"], record["type"]) == want


@pytest.mark.parametrize("given", IPV4_SPELLINGS)
def test_an_ipv4_address_with_a_port_is_filed_under_network(case, given):  # noqa: F811
    result = _record({**FINDING, "iocs": [{"value": "10.20.30.41:443", "type": given}]})
    assert result["status"] == "STAGED", result
    (record,) = _records(case)
    assert record["category"] == "network"


@pytest.mark.parametrize("value", ["10[.]20[.]30[.]41", " 10.20.30.41 "])
@pytest.mark.parametrize("given", IPV4_SPELLINGS)
def test_an_ipv4_address_without_a_port_is_stored_as_the_id(case, given, value):  # noqa: F811
    result = _record({**FINDING, "iocs": [{"value": value, "type": given}]})
    assert result["status"] == "STAGED", result
    (record,) = _records(case)
    assert (record["value"], record["type"], record["category"]) == (
        "10.20.30.41", "ipv4-addr", "network"
    )  # fmt: skip


TYPED = [  # value, type as given, id stored
    ("10.20.30.40", "IPv4", "ipv4-addr"),
    ("C:\\Windows\\Temp\\dropper.exe", "file_path", "file:path"),
    ("a" * 64, "sha256", "file:hash:sha256"),
    ("bad.example.org", "Domain Name", "domain-name"),
    ("10.20.30.42", "ipv4-addr", "ipv4-addr"),
    ("weird-thing-123", "unknown", "unknown"),
    ("HKLM\\Software\\ProbeKey", "registry-key", "registry-key"),
    ("ProbeSvc", "service-name", "service-name"),
    ("\\Microsoft\\Windows\\ProbeTask", "scheduled-task", "scheduled-task"),
    ("probe.exe -x -y", "process:command-line", "process:command-line"),
]


@pytest.mark.parametrize(("value", "given", "want"), TYPED)
def test_a_typed_value_is_stored_with_the_ids_category(case, value, given, want):  # noqa: F811
    result = _record({**FINDING, "iocs": [{"value": value, "type": given}]})
    assert result["status"] == "STAGED", result
    (record,) = _records(case)
    assert (record["value"], record["type"], record["category"]) == (
        value, want, CATEGORY[want]
    )  # fmt: skip


# --- what the readers make of the records ----------------------------------------


def _reader_labels(case: Path, finding: dict) -> tuple[dict, dict]:
    """value -> label, from vhir's IOC listing and from report-mcp's report."""
    from report_mcp.server import _extract_all_iocs
    from vhir_cli.ioc_groups import record_groups

    result = _record(finding)
    assert result["status"] == "STAGED", result
    records = _records(case)
    findings = json.loads((case / "findings.json").read_text())
    listing = {v: lb for lb, vs in record_groups(records).items() for v in vs}
    report = _extract_all_iocs(findings, records=records, all_records=records)
    reported = {
        e["value"]: lb
        for lb, es in report.items()
        if "not recorded" not in lb
        for e in es
    }
    return listing, reported


def test_the_readers_list_a_typed_path_and_domain_with_the_detected_ones(case):  # noqa: F811
    iocs = [
        {"value": "C:\\Windows\\Temp\\dropper.exe", "type": "file_path"},
        "C:\\Users\\Public\\x.ps1",
        {"value": "bad.example.org", "type": "Domain Name"},
        "good.example.com",
    ]
    for labels in _reader_labels(case, {**FINDING, "iocs": iocs}):
        paths = {
            labels.get("C:\\Windows\\Temp\\dropper.exe"),
            labels.get("C:\\Users\\Public\\x.ps1"),
        }
        domains = {labels.get("bad.example.org"), labels.get("good.example.com")}
        assert len(paths) == len(domains) == 1 and None not in paths | domains, labels


PORT_ENTRIES = [
    {"value": "10.20.30.45:443", "type": "IPv4"},
    {"value": "10.20.30.46:443", "type": "IPV4-ADDR"},
    {"value": "10.20.30.47:443", "type": " ipv4-addr "},
    {"value": "10.20.30.48:443", "type": "ipv4-addr"},
    "10.20.30.44:443",
]


@pytest.mark.parametrize("entry", PORT_ENTRIES, ids=lambda e: json.dumps(e))
def test_an_approval_moves_the_one_record_a_finding_with_a_port_names(case, entry):  # noqa: F811
    from report_mcp.server import _TEXT_ONLY, _extract_all_iocs
    from vhir_cli.case_io import _ioc_outcomes
    from vhir_cli.ioc_groups import not_recorded

    result = _record({**FINDING, "iocs": [entry]})
    assert result["status"] == "STAGED", result
    fid = result["finding_id"]
    findings = [
        f for f in json.loads((case / "findings.json").read_text()) if f["id"] == fid
    ]
    records = _records(case)
    mine = [r for r in records if fid in (r.get("source_findings") or [])]
    assert len(mine) == 1, records
    outcomes = list(_ioc_outcomes({fid: "APPROVED"}, findings, mine, set()))
    assert [o[4] for o in outcomes] == ["APPROVED"]
    assert not_recorded(findings, records) == []
    report = _extract_all_iocs(findings, records=mine, all_records=records)
    assert report.get(_TEXT_ONLY, []) == []


# --- types read as untyped, and the rig's controls ------------------------------


@pytest.mark.parametrize("given", ["  ", "\t", " \n "])
def test_a_whitespace_type_is_detected_from_the_value(case, given):  # noqa: F811
    result = _record({**FINDING, "iocs": [{"value": "10.20.30.40", "type": given}]})
    assert result["status"] == "STAGED", result
    (record,) = _records(case)
    assert (record["type"], record["category"]) == ("ipv4-addr", "network")


DETECTED = {  # untyped value -> the detector's (type, category)
    "http://bad.example.org/a": ("url", "network"),
    "ops@bad.example.org": ("email-addr", "network"),
    "a" * 63 + "1": ("file:hash:sha256", "host"),
    "b" * 39 + "1": ("file:hash:sha1", "host"),
    "c" * 31 + "1": ("file:hash:md5", "host"),
    "10.20.30.40": ("ipv4-addr", "network"),
    "fe80::1": ("ipv6-addr", "network"),
    "HKLM\\Software\\Run\\upd": ("registry-key", "system"),
    "\\Microsoft\\Windows\\upd": ("scheduled-task", "system"),
    "S-1-5-21-1-2-3-1001": ("windows-sid", "identity"),
    "corp\\svc-backup": ("user-account", "identity"),
    "dropper.exe": ("file:name", "host"),
    "bad.example.org": ("domain-name", "network"),
    "cmd.exe /c whoami": ("process:command-line", "system"),
    "C:\\Temp\\x.bin": ("file:path", "host"),
    "updsvc": ("service-name", "system"),
    "weird thing": ("unknown", "unknown"),
    # values spelled as types are still detected from the value alone
    "url": ("unknown", "unknown"),
    "hostname": ("unknown", "unknown"),
    "ip": ("unknown", "unknown"),
    "md5": ("unknown", "unknown"),
    "registry": ("unknown", "unknown"),
    "account": ("unknown", "unknown"),
    "other": ("unknown", "unknown"),
}  # fmt: skip


@pytest.mark.parametrize("shape", ["bare", "absent", "empty"])
@pytest.mark.parametrize(("value", "want"), DETECTED.items())
def test_an_untyped_value_is_detected_as_before(case, value, want, shape):  # noqa: F811
    ioc = {
        "bare": value,
        "absent": {"value": value},
        "empty": {"value": value, "type": ""},
    }
    result = _record({**FINDING, "iocs": [ioc[shape]]})
    assert result["status"] == "STAGED", result
    (record,) = _records(case)
    assert (record["value"], record["type"], record["category"]) == (value, *want)


@pytest.mark.parametrize(
    "finding",
    [{"confidence": "NOPE"}]
    + [
        {"iocs": [{"value": "zz.example.net", "type": t}]}
        for t in (None, 0, False, [], {}, 5, ["ipv4"], {"t": "ipv4"})
    ]
    + [
        {"iocs": [{"ip": "10.20.30.40", "type": "IPv4"}]},
        {"iocs": [{"value": None}]},
    ],
    ids=[
        "bad confidence",
        "null type",
        "zero type",
        "false type",
        "list type",
        "mapping type",
        "number type",
        "list of a type",
        "mapping with a type",
        "no value",
        "null value",
    ],
)
def test_a_refusal_the_writer_already_makes_writes_nothing(case, finding):  # noqa: F811
    _record({**FINDING, "iocs": ["10.0.0.1"]})
    files, lines = _snapshot(case)
    result = _record({**FINDING, **finding})
    assert result["status"] == "VALIDATION_FAILED", result
    after, after_lines = _snapshot(case)
    assert after == files
    assert after_lines[: len(lines)] == lines and len(after_lines) == len(lines) + 1


# --- the tool text and the IOC template -----------------------------------------


def _record_finding_text() -> str:
    tools = asyncio.run(create_server(reference_mode="tools").list_tools())
    return next(t.description or "" for t in tools if t.name == "record_finding")


def test_the_record_finding_text_names_every_id_by_category():
    text = _record_finding_text()
    named = {i for _, i in _mentions(text)}
    assert [i for i in IDS if i not in named] == []
    assert _ungrouped(text) == []


def test_the_record_finding_text_says_what_ipv4_addr_holds_and_what_is_detected():
    text = _record_finding_text()
    assert "one IPv4 address with an optional port" in text
    assert sorted(_detected_kinds(text)) == sorted(KINDS)


def test_the_record_finding_iocs_text_has_no_call_syntax():
    text = _record_finding_text()
    part = text[text.find("iocs (list)") :].split("\n\n")[0]
    assert part
    assert not re.search(r"[`{}\[\]]|\"\w+\"\s*:|\w\(\w|\w=\S|--\w|\$[A-Z]", part), part


@pytest.mark.parametrize("copy", DATA["discipline_copies"])
def test_the_ioc_template_points_to_record_finding_for_the_types(copy):
    text = (REPO / copy).read_text()
    (line,) = [ln for ln in text.splitlines() if ln.startswith("IOC Type:")]
    assert "record_finding" in line
    assert not re.search(r"\bHash\b", line)
    assert "IP/Hash/Domain/URL/Path" not in text


def test_the_module_lives_in_sift_common():
    assert (Path(sift_common.__file__).parent / "ioc_types.py").is_file()
