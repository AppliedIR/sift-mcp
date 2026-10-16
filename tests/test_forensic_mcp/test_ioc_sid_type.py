"""A Windows security identifier passed as an IOC is stored as a SID in the
identity category, never as an unknown type; other values keep their types.
The Portal's IOC category filter names the untyped category "Other".

The real forensic-mcp server runs in-process on scratch cases."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from .test_finding_challenge import (  # noqa: F401 (case and home are fixtures)
    FINDING,
    _record,
    case,
    home,
)


def _iocs(case, iocs) -> dict:
    """The case's IOCs after recording a finding with `iocs`: value -> (type, category)."""
    result = _record({**FINDING, "iocs": iocs})
    assert result["status"] == "STAGED", result
    stored = json.loads((case / "iocs.json").read_text())
    return {i["value"]: (i["type"], i["category"]) for i in stored}


@pytest.mark.parametrize(
    "sid",
    ["S-1-5-21-3623811015-3361044348-30300820-1001",  # a domain account
     "S-1-5-32-544",  # the local Administrators group
     "S-1-5-18",  # Local System
     "S-1-1-0",  # Everyone
     "s-1-5-21-1-2-3-500"],  # written in lower case
)  # fmt: skip
def test_a_sid_is_stored_as_a_sid_of_an_identity(case, sid):  # noqa: F811
    assert _iocs(case, [sid])[sid] == ("windows-sid", "identity")


def test_a_sid_passed_with_its_type_is_an_identity(case):  # noqa: F811
    sid = "S-1-5-21-1-2-3-1104"
    assert _iocs(case, [{"value": sid, "type": "windows-sid"}])[sid] == (
        "windows-sid",
        "identity",
    )


@pytest.mark.parametrize(
    ("value", "kept"),
    [("10.0.0.7", ("ipv4-addr", "network")),
     ("fe80::1:2:3", ("ipv6-addr", "network")),
     ("CORP\\jdoe", ("user-account", "identity")),
     ("evil.example", ("domain-name", "network"))],
)  # fmt: skip
def test_other_values_keep_their_types_beside_a_sid(case, value, kept):  # noqa: F811
    assert _iocs(case, ["S-1-5-32-544", value])[value] == kept


@pytest.mark.parametrize(
    "value",
    ["S-1-",  # no authority
     "S-1-5",  # no sub-authority
     "S-1-5-21-x",  # a part that is not a number
     "S-2-5-32-544",  # not revision 1
     "XS-1-5-32-544",  # text before it
     "S-1-5-32-544 admins"],  # text after it
)  # fmt: skip
def test_a_value_that_only_looks_like_a_sid_is_not_typed_as_one(case, value):  # noqa: F811
    assert _iocs(case, [value])[value][0] != "windows-sid"


def test_an_explicit_type_other_than_an_account_or_sid_stays_host(case):  # noqa: F811
    v = "S-1-5-32-545"
    assert _iocs(case, [{"value": v, "type": "file:name"}])[v] == ("file:name", "host")


def test_the_portal_names_the_untyped_category_other():
    from case_dashboard import __file__ as pkg

    page = (Path(pkg).parent / "static" / "v2" / "index.html").read_text()
    start = page.index('<select id="iocFilterCategory">')
    select = page[start : page.index("</select>", start)]
    assert '<option value="unknown">Other</option>' in select
    assert ">Unknown<" not in select
    assert '<option value="identity">Identity</option>' in select
