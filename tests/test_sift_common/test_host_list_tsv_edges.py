"""A TSV host list's row with an empty first or last cell reads its own host
column, while blank lines, # lines, spaces and CSV rows read as before. Names
are synthetic (RFC 2606 domains)."""

from __future__ import annotations

from sift_common import host_proposal as hp

NO_NAME = hp.SKIP_NO_NAME


def _read(text):
    entries, skipped = hp.read_host_list(text)
    return (
        [(e["name"], e.get("fqdn", "")) for e in entries],
        [(s["line"], s["reason"]) for s in skipped],
    )


def test_a_tsv_rows_empty_edge_cell_keeps_the_columns_in_place():
    got = {
        "empty first cell": _read("Owner\tHostname\tOS\n\tWKS01\tWindows10\n"),
        "empty last cell": _read("AssetTag\tHostname\nA-1001\t\n"),
        "empty header corner": _read("\tHostname\tOS\n1\tWKS01\tWin\n"),
        "last cell spaces": _read("AssetTag\tHostname\nA-1001\t  \n"),
    }
    assert got == {
        "empty first cell": ([("WKS01", "")], []),
        "empty last cell": ([], [(2, NO_NAME)]),
        "empty header corner": ([("WKS01", "")], []),
        "last cell spaces": ([], [(2, NO_NAME)]),
    }


def test_other_rows_blank_lines_and_spaces_read_as_before():
    got = {
        "tsv": _read("Owner\tHostname\tOS\nbob\tWKS01\tWindows10\n"),
        "csv empty first cell": _read("Owner,Hostname,OS\n,WKS01,Windows10\n"),
        "tsv empty middle cell": _read("Hostname\tOwner\tOS\nWKS02\t\tWindows10\n"),
        "plain list spaces": _read("  WKS01  \n  WKS02 wks02.corp.example  \n"),
        "indented #": _read("WKS01\n   # a note\n\t# a note\nWKS02\n"),
        "tab-only line": _read("Owner\tHostname\n\t\nbob\tWKS01\n"),
        "csv quoted indented": _read('Hostname,OS\n  "WKS01","Win"\n'),
        "csv header trailing tab": _read("Owner,Hostname\t\nbob,WKS01\n"),
    }
    assert got == {
        "tsv": ([("WKS01", "")], []),
        "csv empty first cell": ([("WKS01", "")], []),
        "tsv empty middle cell": ([("WKS02", "")], []),
        "plain list spaces": ([("WKS01", ""), ("WKS02", "wks02.corp.example")], []),
        "indented #": ([("WKS01", ""), ("WKS02", "")], []),
        "tab-only line": ([("WKS01", "")], []),
        "csv quoted indented": ([("WKS01", "")], []),
        "csv header trailing tab": ([("WKS01", "")], []),
    }
