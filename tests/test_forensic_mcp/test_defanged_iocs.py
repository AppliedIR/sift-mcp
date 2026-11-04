"""A defanged indicator (evil[.]com, bad(dot)example.com, hxxp://..., 185[.]220[.]101[.]45)
is read as the live indicator in the report's IOC section, taken from what an
examiner or the AI wrote. hxxp is a scheme only before its ://, never in a host
name or a path. vhir-cli reads them by the same notation list (a copy; neither
package depends on the other). A finding's own IOCs are still stored by the rule
they are signed under (forensic-mcp's _refang_ioc), unchanged."""

from __future__ import annotations

import inspect

import pytest
from report_mcp.server import _TEXT_ONLY, _extract_all_iocs
from sift_common import defang

from .test_finding_challenge import (  # noqa: F401 (case and home are fixtures)
    FINDING,
    _record,
    case,
    home,
)

SAMPLE = (
    "C2 at hxxp://evil[.]com via bad(dot)example.com, beacon to 185[.]220[.]101[.]45"
)

# every notation refang() undoes, and the forms it must leave as they are
NOTATIONS = [
    "evil[.]com", "evil(.)com", "evil{.}com", "evil[dot]com", "evil(dot)com", "evil{dot}com",
    "evil[DOT]com", "a[.]b[.]example[.]com", "185[.]220[.]101[.]45", "185.220.101[.]45",
    "hxxp://evil.com", "hxxps://evil.com", "HXXP://EVIL.COM", "hXXps://evil.com",
    "hxxp[://]evil.com", "hxxp[:]//evil.com", "hxxp://hxxp[.]example[.]com",
    r"C:\Tools\hxxp\payload.exe", r"C:\Users\victim\.ssh\id_rsa", "see note [.] here",
    "evil . com", "evil dot com", "hxxp is a word", "func(.)call", "[.]", "plain.example.com",
]  # fmt: skip


def test_the_report_reads_a_defanged_sample_as_its_live_indicators():
    got = _extract_all_iocs(
        [{"id": "F-1", "observation": SAMPLE, "interpretation": ""}]
    )
    # named only in the text, so listed in the text-only group
    assert list(got) == [_TEXT_ONLY]
    assert [i["value"] for i in got[_TEXT_ONLY]] == [
        "185.220.101.45",
        "bad.example.com",
        "evil.com",
    ]


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("C2 at hxxp://hxxp[.]example[.]com", "hxxp.example.com"),
        (r"dropped C:\Tools\hxxp\payload.exe", r"C:\Tools\hxxp\payload.exe"),
    ],
)
def test_the_report_refangs_hxxp_only_as_a_scheme(text, value):
    got = _extract_all_iocs([{"id": "F-1", "observation": text, "interpretation": ""}])
    assert [i["value"] for i in got[_TEXT_ONLY]] == [value]


def test_vhir_refangs_by_the_same_notation_list():
    """The vhir-cli copy is the same function, and reads every notation alike."""
    vhir = pytest.importorskip("vhir_cli.defang")
    for name in ("_DOT_RE", "_SCHEME_SEP_RE", "_COLON_RE", "_HXXP_RE"):
        assert getattr(vhir, name).pattern == getattr(defang, name).pattern, name
        assert getattr(vhir, name).flags == getattr(defang, name).flags, name
    assert (
        inspect.getsource(vhir.refang).split('"""')[2]
        == inspect.getsource(defang.refang).split('"""')[2]
    )
    assert [vhir.refang(n) for n in NOTATIONS] == [defang.refang(n) for n in NOTATIONS]


def test_vhir_writes_a_saved_reports_iocs_defanged_by_the_same_functions():
    """vhir report --save and report-mcp's save_report defang alike."""
    vhir = pytest.importorskip("vhir_cli.defang")
    from report_mcp import server as rs

    for name in ("_IPV4", "_URL", "_DOMAIN"):
        assert getattr(vhir, name).pattern == getattr(rs, name).pattern, name
    assert vhir._NETWORK_TYPES == rs._NETWORK_TYPES
    for mine, theirs in ((vhir._defanged, rs._defanged), (vhir.defang_iocs, rs._defang_iocs),
                         (vhir.network_ioc, rs._network_ioc),
        (vhir.structured_iocs, rs._structured_iocs)):  # fmt: skip
        assert (
            inspect.getsource(mine).split('"""')[2]
            == inspect.getsource(theirs).split('"""')[2]
        )
    iocs = ["http://bad.example.com/x.php", "185.220.101.45", "evil.com"]
    text = ("Beacon to evil.com, EVIL.COM, notevil.com, sub.evil.com, evil.com.au, "
            "evil[.]com; 185.220.101.45 and 185.220.101.450; http://bad.example.com/x.php")  # fmt: skip
    assert vhir.defang_iocs(text, iocs) == rs._defang_iocs(text, iocs)
    for value, typed in [*((n, True) for n in NOTATIONS), *((n, False) for n in NOTATIONS),
                         ("a.exe", False), ("a.exe", True)]:  # fmt: skip
        assert vhir.network_ioc(value, typed) == rs._network_ioc(value, typed), value


def test_vhir_leaves_what_the_examiner_rejected_out_of_a_reports_iocs_alike(tmp_path):
    """Both copies of the gathering run the same rows (in each repo's own tests
    too) and agree; the gathering differs only in the names it calls."""
    pytest.importorskip("vhir_cli.defang")
    from report_mcp.server import _report_iocs
    from test_report_mcp.test_report_iocs_rejected import ROWS, gathered
    from vhir_cli.commands.report import _report_iocs as vhir_report_iocs

    for n, (row, field, record, line, expected) in enumerate(ROWS):
        for c, copy in enumerate((_report_iocs, vhir_report_iocs)):
            got = gathered(copy, tmp_path / f"{n}-{c}", field, record, line)
            assert got == expected, (row, copy.__module__)


def test_record_finding_refuses_every_citation_whose_type_changes_a_reports_iocs(case):  # noqa: F811
    """A citation's type decides whether a rejection keeps it out of a report
    (take() keys it by its type, as forensic-mcp joins it) only for a URL with
    a port typed ipv4-addr, and record_finding refuses that type on a URL,
    changing no file of the case. So a finding record_finding wrote gathers
    alike keyed by its types or not; one from `vhir merge` or an imported
    bundle, which write findings.json without that check, is keyed by its
    types (the rejection rows hold it)."""
    from report_mcp.server import _network_ioc
    from sift_common import ioc_types

    values = [*NOTATIONS, "10.0.0.5", "10.0.0.5:8080", "10.0.0.5/24", "10.0.0.5[:]8080",
              "http://10.0.0.5", "http://10.0.0.5:8080", "hxxp://10[.]0[.]0[.]5:8080",
              "http://10.0.0.5:8080/p", "https://evil.example.com:443", "evil.example.com:8080",
              "HTTP://EVIL.EXAMPLE.COM:8080", "user@evil.example.com", "evil.example.com."]  # fmt: skip
    types = [None, "", *(s for i, (_, _, more) in ioc_types.IDS.items()
                         for s in [i, *more.split()])]  # fmt: skip
    changes = [(v, t) for v in values for t in types
               if any(_network_ioc(v, typed) for typed in (True, False))
               and ioc_types.keys(v, t) != ioc_types.keys(v, None)]  # fmt: skip
    assert ("http://10.0.0.5:8080", "ipv4-addr") in changes
    files = {p.name: p.read_bytes() for p in case.iterdir() if p.is_file()}
    for v, t in changes:
        got = _record({**FINDING, "iocs": [{"value": v, "type": t}]})
        assert got["status"] == "VALIDATION_FAILED", (v, t, got)
        assert any("means ipv4-addr" in e for e in got["errors"]), (v, t, got)
    assert {p.name: p.read_bytes() for p in case.iterdir() if p.is_file()} == files


# --- a saved report's IOCs, written defanged: where a domain names a host ------

IOCS = ["https://evil.com/payload", "evil.com"]


@pytest.mark.parametrize(
    "text",
    [
        "evil.com", "https://evil.com/x", "hxxp://evil.com", r"\\evil.com\share",
        r"\\evil.com@SSL\DavWWWRoot\x.dll", "//evil.com/x", "mail@evil.com",
        "https://web.archive.org/web/2026/https://evil.com/payload",
        r"https:/\evil.com/x", r"http:\/evil.com",  # a mixed pair is a host too
    ],
)  # fmt: skip
def test_an_ioc_where_it_names_a_host_is_defanged(text):
    from report_mcp.server import _defang_iocs

    got = _defang_iocs(text, IOCS)
    assert "evil[.]com" in got and "evil.com" not in got, got


@pytest.mark.parametrize(
    ("text", "kept"),
    [
        ("https://vendor.example/download/evil.com/tool", "/download/evil.com/tool"),
        (r"C:\Users\x\evil.com\a", r"\x\evil.com\a"),
        ("https://evil.com/evil.com/payload", "/evil.com/payload"),
    ],
)
def test_a_domain_after_a_single_separator_is_a_path_and_stays(text, kept):
    """After one / or \\ a domain is a path component; after // or \\\\ a host."""
    from report_mcp.server import _defang_iocs

    assert _defang_iocs(text, IOCS).endswith(kept)


def test_a_range_counts_as_its_base_address():
    from report_mcp.server import _defang_iocs, _network_ioc

    assert _network_ioc("185.220.101.0/24", False) == "185.220.101.0"
    assert _network_ioc("185.220.101.45/32", False) == "185.220.101.45"
    got = _defang_iocs(
        "185.220.101.0/24 via http://185.220.101.0/24", ["185.220.101.0"]
    )
    assert got == "185[.]220[.]101[.]0/24 via http://185[.]220[.]101[.]0/24"


NESTED = [
    ("evil7[[.]]example.com", "evil7.example.com"),
    ("evil7[[[.]]]example[.]com", "evil7.example.com"),
    ("hxxp[[:]]//evil7.example.com/a", "http://evil7.example.com/a"),
    ("10[[.]]20[.]30[[[.]]]41", "10.20.30.41"),
]


@pytest.mark.parametrize(("value", "live"), NESTED)
def test_a_bracket_defang_of_any_depth_counts_as_its_live_indicator(value, live):
    from report_mcp.server import _network_ioc

    assert _network_ioc(value, True) == live


# hxxp is a scheme only before its ://: in a path or a host name it is read as
# written, so the report defangs the value as it stands in the text
AS_WRITTEN = ["https://safe.example.com/hxxp/payload", "hxxp.example.com"]


@pytest.mark.parametrize("value", AS_WRITTEN)
def test_hxxp_outside_a_scheme_is_read_as_written(value):
    from report_mcp.server import _network_ioc

    assert _network_ioc(value, True) == value


def test_a_typed_domain_with_its_root_dot_counts_without_it():
    from report_mcp.server import _defang_iocs, _network_ioc

    assert _network_ioc("evil.com.", True) == "evil.com"
    got = _defang_iocs("evil.com. and https://evil.com./x", ["evil.com"])
    assert got == "evil[.]com. and https://evil[.]com./x"


# Where a domain IOC names a host, whatever the separators before it (a browser
# reads each of these as a host), and where it is only a path component. The
# same table is in vhir-cli's and sift's tests.
HOST_FORMS = [
    "https://evil.com/x", "https:/evil.com/x", r"https:\evil.com/x", r"https:\\evil.com/x",
    r"https:/\evil.com/x", r"https:\/evil.com/x", "https:///evil.com/x", "HTTPS://evil.com/x",
    "//evil.com/x", r"\\evil.com\share", r"\\evil.com@SSL\DavWWWRoot\x.dll",
]  # fmt: skip
PATH_FORMS = [
    ("https://vendor.example/download/evil.com/tool", "/download/evil.com/tool"),
    (r"C:\Users\x\evil.com\a", r"\x\evil.com\a"),
    ("https://evil.com/evil.com/payload", "/evil.com/payload"),
]


@pytest.mark.parametrize("text", HOST_FORMS)
def test_a_domain_where_it_names_a_host_is_defanged_whatever_the_separators(text):
    from report_mcp.server import _defang_iocs as defang_iocs

    got = defang_iocs(text, ["evil.com"])
    assert "evil[.]com" in got and "evil.com" not in got, got


@pytest.mark.parametrize(("text", "kept"), PATH_FORMS)
def test_a_domain_that_is_only_a_path_component_stays_as_written(text, kept):
    from report_mcp.server import _defang_iocs as defang_iocs

    assert defang_iocs(text, ["evil.com"]).endswith(kept)


def test_vhir_reads_the_host_and_path_table_alike():
    vhir = pytest.importorskip("vhir_cli.defang")
    from report_mcp.server import _defang_iocs

    for text in [*HOST_FORMS, *(p for p, _ in PATH_FORMS)]:
        assert vhir.defang_iocs(text, ["evil.com"]) == _defang_iocs(
            text, ["evil.com"]
        ), text
