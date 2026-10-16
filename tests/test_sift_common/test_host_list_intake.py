"""A host list in the forms inventories come in: a header row names the host
column and the FQDN column wherever they sit, quoted CSV and TSV read as
such, and each row it can't use is skipped with a reason. A plain list reads
as it always has. An AI-prepared draft is kept for the examiner to review and
confirms nothing. Names are synthetic (RFC 2606 domains)."""

from __future__ import annotations

import json

import pytest
from sift_common import host_gate as hg
from sift_common import host_identity as hi
from sift_common import host_proposal as hp


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: c\n")
    hi.ensure_host_files(d)
    return d


# The inventories measured on the shipped parser, each with two hosts
INVENTORIES = [
    "IP,Hostname,OS\n10.0.0.5,WKS01,Win10\n10.0.0.6,WKS02,Win11\n",
    "AssetTag,Hostname,Owner\nA-1001,WKS01,alice\nA-1002,WKS02,bob\n",
    '"Hostname","FQDN"\n"WKS01","wks01.corp.example"\n"WKS02","wks02.corp.example"\n',
    "ComputerName,DNSHostName\nWKS01,wks01.corp.example\nWKS02,wks02.corp.example\n",
]
WANT = [
    [{"name": "WKS01"}, {"name": "WKS02"}],
    [{"name": "WKS01"}, {"name": "WKS02"}],
    [{"name": "WKS01", "fqdn": "wks01.corp.example"},
     {"name": "WKS02", "fqdn": "wks02.corp.example"}],
    [{"name": "WKS01", "fqdn": "wks01.corp.example"},
     {"name": "WKS02", "fqdn": "wks02.corp.example"}],
]  # fmt: skip


@pytest.mark.parametrize("text,want", list(zip(INVENTORIES, WANT, strict=True)))
def test_an_inventory_with_a_header_row_lists_its_hosts_and_not_its_header(
    case, text, want
):
    assert hp.parse_host_list(text) == want
    hp.upload_host_list(case, text, "ex1")
    assert hi.load(case).host_list["entries"] == want


@pytest.mark.parametrize("header", ["Host Name", "Host_Name", "host-name", "DEVICE NAME",
                                    "Computer", "Machine", "Name"])  # fmt: skip
def test_a_host_column_is_found_by_its_header_however_it_is_spelled(header):
    text = f"Owner,{header},IP\nalice,WKS01,10.0.0.5\n"
    assert hp.parse_host_list(text) == [{"name": "WKS01"}]


def test_the_best_ranked_host_column_wins_over_a_plain_name_column():
    text = "Name,ComputerName\nAlice Smith,WKS01\n"
    assert hp.parse_host_list(text) == [{"name": "WKS01"}]


def test_a_tab_separated_export_reads_by_its_columns():
    text = "DeviceName\tOSPlatform\nwks01.corp.example\tWindows10\n"
    assert hp.parse_host_list(text) == [{"name": "wks01.corp.example"}]


def test_a_header_row_with_only_an_fqdn_column_names_hosts_by_it():
    text = "Owner,DNSHostName\nalice,wks01.corp.example\n"
    assert hp.parse_host_list(text) == [
        {"name": "wks01.corp.example", "fqdn": "wks01.corp.example"}
    ]


def test_each_row_it_cannot_use_is_skipped_with_a_reason():
    text = "IP,Hostname\n10.0.0.5,WKS01\n10.0.0.6,\n10.0.0.7,10.0.0.7\n"
    entries, skipped = hp.read_host_list(text)
    assert entries == [{"name": "WKS01"}]
    assert skipped == [
        {"line": 3, "value": "", "reason": "no name in the host column"},
        {"line": 4, "value": "10.0.0.7", "reason": "an IP address, not a host name"},
    ]


def test_a_row_the_csv_reader_refuses_is_skipped_not_raised():
    text = "Hostname,FQDN\nWKS01,wks01.corp.example\n" + "x" * 200_000 + "\n"
    entries, skipped = hp.read_host_list(text)
    assert entries == [{"name": "WKS01", "fqdn": "wks01.corp.example"}]
    assert [s["line"] for s in skipped] == [3]


# A plain list reads as it always has


@pytest.mark.parametrize("text,want", [
    ("WKS01\nWKS02\n", [{"name": "WKS01"}, {"name": "WKS02"}]),
    ("# hosts\n\nWKS01 wks01.corp.example\n",
     [{"name": "WKS01", "fqdn": "wks01.corp.example"}]),
    ("name,fqdn\nWKS01,wks01.corp.example\n",
     [{"name": "WKS01", "fqdn": "wks01.corp.example"}]),
    ("Hostname\nWKS01 wks01.corp.example\nWKS02\n",
     [{"name": "WKS01", "fqdn": "wks01.corp.example"}, {"name": "WKS02"}]),
    ("WKS01,10.0.0.1\n10.0.0.2\n", [{"name": "WKS01"}]),
    ("name,fqdn\nWKS01\nDC01 dc01.corp.example\n",
     [{"name": "WKS01"}, {"name": "DC01", "fqdn": "dc01.corp.example"}]),
    ("WKS01\nWKS01\n", [{"name": "WKS01"}, {"name": "WKS01"}]),
])  # fmt: skip
def test_a_plain_list_reads_as_before(text, want):
    assert hp.parse_host_list(text) == want


def test_without_a_header_a_second_word_is_an_fqdn_only_with_a_dot():
    assert hp.parse_host_list("WKS01\tWindows10\nWKS02 wks02.corp.example\n") == [
        {"name": "WKS01"},
        {"name": "WKS02", "fqdn": "wks02.corp.example"},
    ]


def test_an_upload_returns_the_rows_it_skipped(case):
    out = hp.upload_host_list(case, "IP,Hostname\n10.0.0.5,WKS01\n10.0.0.6,\n", "ex1")
    assert out["entries"] == 1
    assert out["skipped"] == [
        {"line": 3, "value": "", "reason": "no name in the host column"}
    ]


# The AI-prepared draft


def _host_files(case) -> dict:
    return {n: (case / n).read_bytes() for n in hi.HOST_FILES}


def test_a_draft_is_kept_for_review_and_changes_no_host_state(case):
    before = _host_files(case)
    out = hp.stage_host_list_draft(case, "Hostname\nWKS01\n10.0.0.5\n", "inventory.pdf")
    assert out["entries"] == [{"name": "WKS01"}]
    assert out["skipped"] == [
        {"line": 3, "value": "10.0.0.5", "reason": "an IP address, not a host name"}
    ]
    assert _host_files(case) == before
    draft = hp.read_host_list_draft(case)
    assert draft["text"] == "Hostname\nWKS01\n10.0.0.5\n"
    assert draft["source"] == "inventory.pdf" and draft["entries"] == 1
    assert hi.load(case).host_list is None


def test_a_new_draft_replaces_the_last_and_clearing_drops_it(case):
    hp.stage_host_list_draft(case, "WKS01\n", "a.txt")
    hp.stage_host_list_draft(case, "WKS02\n", "b.txt")
    assert hp.read_host_list_draft(case)["text"] == "WKS02\n"
    assert hp.clear_host_list_draft(case) is True
    assert hp.read_host_list_draft(case) is None
    assert hp.clear_host_list_draft(case) is False


def test_a_draft_over_the_list_cap_is_refused(case):
    with pytest.raises(ValueError, match="larger than"):
        hp.stage_host_list_draft(case, "W" * (hp.LIST_MAX + 1), "")
    assert hp.read_host_list_draft(case) is None


@pytest.mark.parametrize("content", [b"[]", b"{}", b'{"text": 1}', b"not json"])
def test_a_draft_file_of_another_shape_reads_as_unreadable(case, content):
    (case / hp.DRAFT).write_bytes(content)
    with pytest.raises(hi.HostLogError, match=hp.DRAFT):
        hp.read_host_list_draft(case)


def test_a_draft_file_that_is_a_link_is_refused(case, tmp_path):
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"text": "WKS01\n", "source": "", "entries": 1}))
    (case / hp.DRAFT).symlink_to(other)
    with pytest.raises(hi.HostLogError, match=hp.DRAFT):
        hp.read_host_list_draft(case)


# What a waiting ingest says


def test_the_wait_message_says_where_to_confirm_and_what_confirming_does():
    msg = hg.WAIT_MESSAGE
    assert "Examiner Portal's Hosts tab" in msg and "vhir portal" in msg
    assert "Start now" in msg and "Confirming a host accepts" in msg
    assert "ask the examiner" not in msg and not msg.endswith(".")


# A folder name the run was given that agrees with the evidence


@pytest.mark.parametrize("raw,artifacts,agrees", [
    ("wks01", ["WKS01"], True),
    ("wks01", ["wks01.corp.example"], True),  # the evidence's short name
    ("WKS01.corp.example.", ["wks01.corp.example"], True),
    ("wks01.corp.example", ["WKS01"], False),  # one way: never full to short
    ("wks01.corp.example", ["wks01.other.example"], False),
    ("dc01", ["WKS05", "wks05.corp.example"], False),
    ("wks01", [], False),
    ("", ["WKS01"], False),
])  # fmt: skip
def test_an_argument_agrees_only_with_an_artifact_name_it_spells(
    raw, artifacts, agrees
):
    assert hp.argument_agrees({"argument"}, raw, artifacts) is agrees


@pytest.mark.parametrize("origins", [
    {"ai"}, {"unregistered"}, {"file-name"}, {"argument", "file-name"}, set(),
])  # fmt: skip
def test_no_other_origin_agrees(origins):
    assert hp.argument_agrees(origins, "wks01", ["WKS01"]) is False
