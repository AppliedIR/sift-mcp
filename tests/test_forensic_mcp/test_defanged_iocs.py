"""A defanged indicator (evil[.]com, bad(dot)example.com, hxxp://..., 185[.]220[.]101[.]45)
is read as the live indicator wherever one is taken from what an examiner or the
AI wrote: the IOCs a finding records, and the report's IOC section. hxxp is a
scheme only before its ://, never in a host name or a path. vhir-cli reads them
by the same notation list (a copy; neither package depends on the other)."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest
from report_mcp.server import _extract_all_iocs
from sift_common import defang

from test_forensic_mcp.test_case_lock import FINDING  # noqa: F401
from test_forensic_mcp.test_case_manager import active_case, manager  # noqa: F401

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


def test_a_findings_defanged_iocs_are_stored_live_and_typed(manager, active_case):  # noqa: F811
    iocs = ["bad(dot)example.com", "evil{.}org", "185(.)220(.)101(.)46", "hxxps[://]x[.]com/p",
            "mail[@]evil.com", r"C:\Tools\hxxp\a.exe"]  # fmt: skip
    manager.record_finding({**FINDING, "iocs": iocs})
    stored = json.loads((Path(active_case["path"]) / "iocs.json").read_text())
    assert sorted((i["type"], i["value"]) for i in stored) == sorted([
        ("domain-name", "bad.example.com"), ("domain-name", "evil.org"),
        ("ipv4-addr", "185.220.101.46"), ("url", "https://x.com/p"),
        ("email-addr", "mail@evil.com"), ("file:path", r"C:\Tools\hxxp\a.exe"),
    ])  # fmt: skip


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
