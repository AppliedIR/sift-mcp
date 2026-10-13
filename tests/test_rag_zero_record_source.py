"""A release build stops when a source syncs successfully with 0 records,
as it does when a sync fails: an empty source would ship as an empty index
part. A source with records goes on, and a non-strict build keeps the old
behaviour (a warning). ATLAS is the source here, synced as build() syncs it,
with the atlas-v6 tests' stand-ins.
"""

from __future__ import annotations

import json

import pytest
from test_rag_atlas_v6 import ReachedEmbedding, _atlas, _upstream, rag  # noqa: F401


def _only_atlas(rag, monkeypatch, doc):  # noqa: F811
    s = rag.sources
    others = [n for n in s.SOURCES if n != "mitre_atlas"]
    s.SOURCES_CONFIG_FILE.write_text(json.dumps({"disabled_sources": others}))
    monkeypatch.setattr(
        s, "clone_repo", lambda repo, branch, dest: _upstream(dest, doc, True) or True
    )


def _empty():
    doc = _atlas()
    doc["techniques"], doc["case-studies"], doc["relationships"] = {}, {}, {}
    return doc


def test_a_source_that_syncs_0_records_fails_a_strict_build(rag, monkeypatch):  # noqa: F811
    _only_atlas(rag, monkeypatch, _empty())
    result = rag.build.build(force_fetch=True, data_dir=rag.data, strict_sources=True)
    assert result.status == "error"
    assert result.errors == ["mitre_atlas: 0 records"]


def test_a_source_with_records_goes_on_to_index(rag, monkeypatch):  # noqa: F811
    _only_atlas(rag, monkeypatch, _atlas())
    with pytest.raises(ReachedEmbedding):
        rag.build.build(force_fetch=True, data_dir=rag.data, strict_sources=True)


def test_a_non_strict_build_goes_on_with_0_records(rag, monkeypatch):  # noqa: F811
    _only_atlas(rag, monkeypatch, _empty())
    with pytest.raises(ReachedEmbedding):
        rag.build.build(force_fetch=True, data_dir=rag.data)
