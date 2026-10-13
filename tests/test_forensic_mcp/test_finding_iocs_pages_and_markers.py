"""record_finding and the reads say what they did.

- The IOC-completeness warning compares the text with the IOCs as stored,
  and iocs_extracted counts what was stored: a value stored as the text
  writes it isn't called missing, one stored in another form still is, and
  one past the 100-IOC limit is named as not stored.
- offset refuses true and false, and get_timeline says its pages aren't a
  snapshot.
- A withdrawal lists only its own ids that the case's trail holds, and
  names the others.
- A challenge marker it can't take says what it was, in words.

The real forensic-mcp server runs in-process on scratch cases.
"""

from __future__ import annotations

import asyncio

import pytest
from forensic_mcp.server import create_server
from mcp.types import CallToolRequest, CallToolRequestParams

from .test_finding_challenge import (  # noqa: F401 (case and home are fixtures)
    FINDING,
    OWN,
    WITHDRAWN,
    _entries,
    _record,
    case,
    home,
)

UNKNOWN = "sift-nobody-20990101-999"


def _wire(tool: str, **args):
    """A tools/call request as the MCP route sends it: (isError, text)."""
    handler = create_server()._mcp_server.request_handlers[CallToolRequest]
    request = CallToolRequest(method="tools/call",
                              params=CallToolRequestParams(name=tool, arguments=args))  # fmt: skip
    result = asyncio.run(handler(request)).root
    return result.isError, result.content[0].text


# --- the IOC-completeness warning reads the IOCs as stored ------------------------

STORED_AS_THE_TEXT_WRITES_IT = {
    "typed dict": ([{"value": "10.1.2.3", "type": "ipv4-addr"}], "Beacon to 10.1.2.3 seen."),
    "dict of lists": ({"ipv4": ["10.1.2.4"]}, "Beacon to 10.1.2.4 seen."),
    "upper-case hash": (["D41D8CD98F00B204E9800998ECF8427E"],
                        "Hash D41D8CD98F00B204E9800998ECF8427E seen."),
    "defanged": (["10[.]1[.]2[.]5"], "Beacon to 10.1.2.5 seen."),
    "ip:port": (["10.1.2.6:443"], "Beacon to 10.1.2.6 seen."),
}  # fmt: skip


@pytest.mark.parametrize("name", STORED_AS_THE_TEXT_WRITES_IT)
def test_a_value_stored_as_the_text_writes_it_isnt_called_missing(case, name):  # noqa: F811
    iocs, observation = STORED_AS_THE_TEXT_WRITES_IT[name]
    result = _record({**FINDING, "observation": observation, "iocs": iocs})
    assert "IOC completeness" not in str(result.get("warning"))
    assert result["iocs_extracted"] == 1


@pytest.mark.parametrize(
    "iocs,observation,value",
    [
        ([{"value": "10.1.2.6:443", "type": "IPv4"}], "Beacon to 10.1.2.6 seen.", "10.1.2.6"),
        ([{"value": "10.1.2.7:443", "type": "network-traffic"}], "Beacon to 10.1.2.7 seen.",
         "10.1.2.7"),
        (["300.1.2.3:80"], "Beacon to 300.1.2.3 seen.", "300.1.2.3"),
    ],
    ids=["typed IPv4:port", "network-traffic", "bad octet:port"],
)  # fmt: skip
def test_a_value_stored_in_another_form_is_still_named(case, iocs, observation, value):  # noqa: F811
    result = _record({**FINDING, "observation": observation, "iocs": iocs})
    assert f"not in iocs list: {value}" in str(result.get("warning"))


def test_an_ioc_past_the_100_limit_is_counted_out_and_named(case):  # noqa: F811
    iocs = [f"10.3.{n // 256}.{n % 256}" for n in range(100)] + ["10.9.0.1"]
    result = _record(
        {**FINDING, "observation": "Beacon to 10.9.0.1 seen.", "iocs": iocs}
    )
    assert result["iocs_extracted"] == 100
    assert (
        "IOC completeness: 1 value(s) in text not stored: past the 100-IOC limit: 10.9.0.1"
        in result["warning"]
    )


# --- paging ---------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["get_findings", "get_timeline"])
@pytest.mark.parametrize("value", [True, False])
def test_offset_true_or_false_is_refused(case, tool, value):  # noqa: F811
    _record(dict(FINDING))
    is_error, text = _wire(tool, limit=2, offset=value)
    assert is_error and "offset must be a whole number, not true or false" in text


def test_get_timeline_says_its_pages_arent_a_snapshot():
    tools = {t.name: t for t in asyncio.run(create_server().list_tools())}
    assert (
        "Pages aren't a snapshot: an event recorded between two calls can repeat "
        "one on the next page, so page again from offset 0 if total changes."
    ) in " ".join(tools["get_timeline"].description.split())


# --- a withdrawal's own ids -----------------------------------------------------


def test_a_withdrawal_lists_only_own_ids_the_case_trail_holds(case):  # noqa: F811
    finding = {**FINDING, "audit_ids": [OWN, UNKNOWN], "challenged": WITHDRAWN}
    result = _record(finding)
    assert result["status"] == "WITHDRAWN"
    assert result["audit_ids"] == [OWN]
    assert (
        f"not in this case's audit trail, so not listed: {UNKNOWN}" in result["message"]
    )
    assert _entries(case)[-1]["result_summary"]["audit_ids"] == [OWN]


# --- a challenge marker's shape, in words -----------------------------------------


@pytest.mark.parametrize(
    "value,said",
    [(5, "not a number"), (5.5, "not a number"), (True, "not true or false"),
     ({}, "(it has no outcome)"), ({"outcome": None}, "(it has no outcome)")],
    ids=["int", "float", "bool", "empty object", "outcome null"],
)  # fmt: skip
def test_a_marker_it_cant_take_says_what_it_was_in_words(case, value, said):  # noqa: F811
    result = _record({**FINDING, "challenged": value})
    warning = str(result.get("warning"))
    assert said in warning and "not int" not in warning and "(got null)" not in warning


def test_a_value_listed_twice_is_counted_once(case):  # noqa: F811
    result = _record({**FINDING, "observation": "Beacon to 10.1.2.6 seen.",
                      "iocs": ["10.1.2.6", "10.1.2.6:443"]})  # fmt: skip
    assert result["iocs_extracted"] == 1
