"""A defanged indicator (evil[.]com, bad(dot)example.com, hxxp://..., 185[.]220[.]101[.]45)
is read as the live indicator in the report's IOC section, taken from what an
examiner or the AI wrote. hxxp is a scheme only before its ://, never in a host
name or a path. vhir-cli reads them by the same notation list (a copy; neither
package depends on the other). A finding's own IOCs are still stored by the rule
they are signed under (forensic-mcp's _refang_ioc), unchanged."""

from __future__ import annotations

import inspect

import pytest
from report_mcp.server import _extract_all_iocs
from sift_common import defang

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
    assert {i["value"] for i in got["Domain"]} == {"evil.com", "bad.example.com"}
    assert {i["value"] for i in got["IPv4"]} == {"185.220.101.45"}


@pytest.mark.parametrize(
    ("text", "kind", "value"),
    [
        ("C2 at hxxp://hxxp[.]example[.]com", "Domain", "hxxp.example.com"),
        (r"dropped C:\Tools\hxxp\payload.exe", "File", r"C:\Tools\hxxp\payload.exe"),
    ],
)
def test_the_report_refangs_hxxp_only_as_a_scheme(text, kind, value):
    got = _extract_all_iocs([{"id": "F-1", "observation": text, "interpretation": ""}])
    assert value in {i["value"] for i in got[kind]}
    assert not any("http" in i["value"] for i in got[kind])


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


def test_a_typed_domain_with_its_root_dot_counts_without_it():
    from report_mcp.server import _defang_iocs, _network_ioc

    assert _network_ioc("evil.com.", True) == "evil.com"
    got = _defang_iocs("evil.com. and https://evil.com./x", ["evil.com"])
    assert got == "evil[.]com. and https://evil[.]com./x"
