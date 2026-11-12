"""The one read of sources_state.json tells an absent file, one that cannot be
parsed and a well-formed one apart, so status can say "no state yet" for the
first and "unreadable" for the second from the same read.

Unit-level: the reader is called in this process on a scratch data dir.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

sources = pytest.importorskip("rag_mcp.sources")

EMPTY = {"version": 1, "sources": {}}
WELL_FORMED = {
    "version": 1,
    "sources": {"sigma": {"version": "abcdef012345", "records": 3}},
}
CASES = {
    "absent": (None, ("absent", EMPTY)),
    "truncated": (b'{"version": 1, "sources": {"sigma": {"vers', ("unreadable", EMPTY)),
    "not_an_object": (b"[]", ("unreadable", EMPTY)),
    "well_formed": (json.dumps(WELL_FORMED).encode(), ("readable", WELL_FORMED)),
}


def plant(data_dir: Path, body: bytes | None) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    if body is not None:
        (data_dir / "sources_state.json").write_bytes(body)


@pytest.mark.parametrize("case", sorted(CASES))
def test_state_read_names_what_it_found(tmp_path, case):
    body, want = CASES[case]
    plant(tmp_path, body)
    reader = getattr(sources, "read_sources_state", None)
    assert reader is not None and tuple(reader(tmp_path)) == want


@pytest.mark.parametrize("case", sorted(CASES))
def test_loaded_state_is_the_reads_state(tmp_path, case):
    body, want = CASES[case]
    plant(tmp_path, body)
    assert sources.load_sources_state(tmp_path) == want[1]
