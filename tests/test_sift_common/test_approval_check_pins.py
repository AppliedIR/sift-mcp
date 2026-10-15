"""vhir's approval checks read the trail and hash a root on their own (vhir
doesn't depend on the sift stack). These pin them to the library the chain
was resolved with: the same audit lines by id, the same entry hash, the same
file hash and limit, and the same refusal of a file that isn't regular."""

from __future__ import annotations

import json
import os

import pytest
from sift_common import file_identity, provenance
from vhir_cli import approval_checks


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "C-1"
    (d / "audit").mkdir(parents=True)
    lines = [
        json.dumps({"audit_id": "sift-a-001", "tool": "run_command"}),
        json.dumps({"audit_id": "sift-a-002", "note": "ünïcode ✓"}, ensure_ascii=False),
        "not json",
        json.dumps({"audit_id": 7}),
        json.dumps({"audit_id": "sift-a-001", "again": True}),
    ]
    (d / "audit" / "sift-mcp.jsonl").write_bytes("\n".join(lines).encode() + b"\n")
    (d / "audit" / "case-mcp.jsonl").write_bytes(
        json.dumps({"audit_id": "case-a-001"}).encode() + b"\r\n"
    )
    return d


def test_the_trail_is_read_as_the_chain_library_reads_it(case):
    ours = approval_checks.audit_lines(case)
    theirs = {
        k: [provenance.entry_sha256(line) for _, line in v]
        for k, v in provenance.load_case(case).by_id.items()
    }
    assert ours == theirs
    assert len(ours["sift-a-001"]) == 2


def test_an_entry_hash_is_the_chain_library_s(case):
    for items in provenance.load_case(case).by_id.values():
        for _, line in items:
            assert approval_checks.entry_sha256(line) == provenance.entry_sha256(line)


def test_a_root_is_hashed_as_the_registry_hashes_it(tmp_path):
    f = tmp_path / "mem.raw"
    f.write_bytes(os.urandom(3 << 20) + b"tail")
    assert approval_checks.file_sha256(f) == file_identity.hash_file(f).sha256
    assert approval_checks.INLINE_LIMIT == file_identity.INLINE_LIMIT


def test_a_file_that_isn_t_regular_is_refused_unread_by_both(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        approval_checks.file_sha256(fifo)
    with pytest.raises(ValueError):
        file_identity.hash_file(fifo)
