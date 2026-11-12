"""generate_report's IOC listing shows each value a finding's iocs field
holds, as written, for every shape the field takes: the values vhir-cli's
walk (defang.walk_iocs) reads and display.ioc_text shows, never a Python
form of a dict or a list, and none dropped. With no IOC record in the case,
each is listed under the found-in-text group, naming its finding."""

from __future__ import annotations

import pytest

BIG = "a" * (70 << 10) + ".example"


def _deep(n):
    v = "evil.example"
    for _ in range(n):
        v = [v]
    return v


# shape -> the values the listing shows
SHAPES = {
    "typed {value, type}": ([{"value": "evil.example", "type": "domain-name"}],
                            ["evil.example"]),
    "untyped {value}": ([{"value": "evil.example"}], ["evil.example"]),
    "{type: [values]}": ({"domain": ["evil.example", "b.example"]},
                         ["b.example", "evil.example"]),
    "{type: value}": ({"domain": "evil.example"}, ["evil.example"]),
    "{type: [{value, type}]}": (
        {"domain": [{"value": "evil.example", "type": "domain-name"}]}, ["evil.example"]),
    "a list-valued record": (
        [{"value": ["evil.example", "b.example"], "type": "domain-name"}],
        ["b.example", "evil.example"]),
    "a nested list": ([["evil.example"]], ["evil.example"]),
    "7 lists deep": (_deep(7), ["evil.example"]),
    "9 lists deep (past the display's depth)": (_deep(9), []),
    "a plain string in a list": (["evil.example"], ["evil.example"]),
    "a plain string, the field not a list": ("evil.example", ["evil.example"]),
    "the keys in another case": ([{"Value": "evil.example", "TYPE": "domain-name"}],
                                 ["evil.example"]),
    "a number": ([5], ["5"]),
    "a typed number": ([{"value": 5, "type": "domain-name"}], ["5"]),
    "an IPv4 address": ([{"value": "10.1.2.3", "type": "ipv4-addr"}], ["10.1.2.3"]),
    "None": ([None], []),
    "a None value": ([{"value": None, "type": "domain-name"}], []),
    "an empty string": ([""], []),
    "an empty value": ([{"value": "", "type": "domain-name"}], []),
    "control characters": (["evil\x1b[2J.example"], ["evil\x1b[2J.example"]),
    "control characters, typed": ([{"value": "evil.example\x00", "type": "domain-name"}],
                                  ["evil.example\x00"]),
    "over 64 KiB": ([BIG], [BIG]),
    "over 64 KiB, typed": ([{"value": BIG, "type": "domain-name"}], [BIG]),
    "non-ASCII": (["évil.example"], ["évil.example"]),
    "non-ASCII, typed": ([{"value": "bücher.example", "type": "domain-name"}],
                         ["bücher.example"]),
    "HTML metacharacters": (["<script>evil.example</script>"],
                            ["<script>evil.example</script>"]),
    "HTML metacharacters in a URL": (
        [{"value": 'http://evil.example/?a=<b>&c="d"', "type": "url"}],
        ['http://evil.example/?a=<b>&c="d"']),
}  # fmt: skip


@pytest.mark.parametrize("name", SHAPES)
def test_the_listing_shows_each_value_as_written(name):
    import report_mcp.server as rs

    field, values = SHAPES[name]
    finding = {"id": "F-x", "iocs": field, "observation": "", "interpretation": ""}
    got = rs._extract_all_iocs([finding])
    want = (
        {rs._TEXT_ONLY: [{"value": v, "source_findings": ["F-x"]} for v in values]}
        if values
        else {}
    )
    assert got == want, (field, got)


@pytest.mark.parametrize("name", SHAPES)
def test_the_listing_reads_the_field_as_vhir_walks_it(name):
    from vhir_cli.defang import walk_iocs
    from vhir_cli.display import ioc_text

    field, values = SHAPES[name]
    as_text = [str(v) for v, _, _ in walk_iocs(field) if v is not None]
    assert sorted(v for v in as_text if v.strip()) == values, (field, as_text)
    shown = ioc_text(field)
    assert all(v in shown for v in values), (field, shown)


# the own type keys a value as forensic-mcp joins it to a record: a value
# under a {type: values} key has none, so an address with a port is keyed by
# its bare address and is the record's IOC, not one found in the text only
@pytest.mark.parametrize("key", ["domain", "url"])
def test_a_value_under_a_type_key_joins_its_record_by_its_own_type(key):
    import report_mcp.server as rs
    from sift_common import ioc_types

    record = {"id": "IOC-x", "value": "10.1.2.3", "type": "ipv4-addr"}
    finding = {"id": "F-x", "iocs": {key: ["10.1.2.3:8080"]},
               "observation": "", "interpretation": ""}  # fmt: skip
    got = rs._extract_all_iocs([finding], [record])
    label = ioc_types.label("ipv4-addr")
    assert got == {label: [{"value": "10.1.2.3", "source_findings": ["F-x"]}]}, got
