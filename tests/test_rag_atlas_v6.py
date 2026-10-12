"""The knowledge build reads MITRE ATLAS from dist/ATLAS-latest.yaml (format
6.x) into technique and case-study records, refuses another layout or format
major, and a release build stops before indexing when any source fails.

ATLAS syncs as build() syncs it (sync_source with force), with the clone
served from a scratch tree. The release legs run build_release's main() with
every other source disabled; the embedding model and chromadb are stand-ins,
so reaching the model means the build went on to index. rag_mcp is loaded
from the source tree. Values are synthetic, in the v6 shape.
"""

from __future__ import annotations

import contextlib
import importlib
import importlib.util
import io
import json
import sys
import types
from pathlib import Path

import pytest
import yaml

SRC = Path(__file__).resolve().parents[1] / "packages/forensic-rag/src"


class ReachedEmbedding(Exception):
    pass


def _model(name, *a, **k):
    raise ReachedEmbedding(name)


@pytest.fixture
def rag(monkeypatch, tmp_path):
    """rag_mcp.sources, .build and .scripts.build_release: the package
    __init__ skipped, the embedding model and chromadb stand-ins, toml and
    zstandard stubbed where they aren't installed. Writes go to tmp_path.
    Modules imported here are dropped again afterwards."""
    for name in [k for k in sys.modules if k == "rag_mcp" or k.startswith("rag_mcp.")]:
        monkeypatch.delitem(sys.modules, name)
    pkg = types.ModuleType("rag_mcp")
    pkg.__path__ = [str(SRC / "rag_mcp")]
    monkeypatch.setitem(sys.modules, "rag_mcp", pkg)
    for name in ("toml", "zstandard"):
        if importlib.util.find_spec(name) is None:
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    st = types.SimpleNamespace(SentenceTransformer=_model)
    monkeypatch.setitem(sys.modules, "sentence_transformers", st)
    monkeypatch.setitem(
        sys.modules, "chromadb", types.SimpleNamespace(__version__="stand-in")
    )
    s = importlib.import_module("rag_mcp.sources")
    b = importlib.import_module("rag_mcp.build")
    br = importlib.import_module("rag_mcp.scripts.build_release")
    data = tmp_path / "data"
    for mod in (s, b):
        monkeypatch.setattr(mod, "SOURCES_DIR", data / "sources", raising=False)
    monkeypatch.setattr(s, "SOURCES_STATE_FILE", tmp_path / "sources_state.json")
    monkeypatch.setattr(s, "SOURCES_CONFIG_FILE", tmp_path / "sources_config.json")
    monkeypatch.setattr(s, "get_latest_version", lambda source: "test")
    monkeypatch.setenv("RAG_INDEX_DIR", str(data))
    yield types.SimpleNamespace(sources=s, build=b, build_release=br, data=data)
    for name in [k for k in sys.modules if k.startswith("rag_mcp.")]:
        del sys.modules[name]


def _edge(source, kind, target, **extra):
    return {"source": source, "target": target, "relationship-type": kind, **extra}


def _atlas(fmt="6.0.0"):
    """A v6 file: dicts keyed by id; relationships[<source>][<kind>] edges."""
    rel = {
        "AML.T0001": {"achieves": [_edge("AML.T0001", "achieves", "AML.TA0002")]},
        "AML.T0001.000": {
            "achieves": [_edge("AML.T0001.000", "achieves", "AML.TA0002")],
            "specializes": [_edge("AML.T0001.000", "specializes", "AML.T0001")],
        },
        "AML.T0002": {"achieves": [_edge("AML.T0002", "achieves", "AML.TA0005")]},
        "AML.M0001": {"mitigates": [_edge("AML.M0001", "mitigates", "AML.T0001")]},
        "AML.CS0001": {
            "employs": [  # listed out of step order
                _edge("AML.CS0001", "employs", "AML.T0002", description="Second step", **{"step-id": "S01"}),
                _edge("AML.CS0001", "employs", "AML.T0001.000", description="First step", **{"step-id": "S00"}),
            ]
        },
    }  # fmt: skip
    return {
        "format-version": fmt,
        "tactics": {
            "AML.TA0002": {"id": "AML.TA0002", "name": "Reconnaissance"},
            "AML.TA0005": {"id": "AML.TA0005", "name": "Execution"},
        },
        "techniques": {
            "AML.T0001": {
                "id": "AML.T0001",
                "name": "Gather Data",
                "description": "d1",
            },
            "AML.T0001.000": {
                "id": "AML.T0001.000",
                "name": "From Papers",
                "description": "d2",
            },
            "AML.T0002": {
                "id": "AML.T0002",
                "name": "Inject Prompt",
                "description": "d3",
            },
        },
        "mitigations": {"AML.M0001": {"id": "AML.M0001", "name": "Limit Disclosure"}},
        "case-studies": {
            "AML.CS0001": {
                "id": "AML.CS0001",
                "name": "Evaded Detector",
                "description": "s1",
                "date": "2020-01-01",
                "reporter": "A Lab",
                "references": [{"title": "Report", "url": "https://example.invalid/r"}],
            }
        },
        "relationships": rel,
    }


def _upstream(dest, doc, latest=True):
    """The repo layout: dist/v6/ATLAS-<release>.yaml, and ATLAS-latest.yaml a
    link to it; dist/ATLAS.yaml is the frozen v5 file."""
    (dest / "dist/v6").mkdir(parents=True)
    (dest / "dist/ATLAS.yaml").write_text(
        "id: ATLAS\nversion: 5.6.0\n", encoding="utf-8"
    )
    if doc is not None:
        (dest / "dist/v6/ATLAS-2026.09.yaml").write_text(
            yaml.safe_dump(doc), encoding="utf-8"
        )
    if latest:
        (dest / "dist/ATLAS-latest.yaml").symlink_to("v6/ATLAS-2026.09.yaml")


def _sync(rag, monkeypatch, doc, latest=True):
    def clone(repo, branch, dest):
        _upstream(dest, doc, latest)
        return True

    monkeypatch.setattr(rag.sources, "clone_repo", clone)
    result = rag.sources.sync_source("mitre_atlas", force=True)
    cache = rag.data / "sources" / "mitre_atlas.jsonl"
    lines = cache.read_text(encoding="utf-8").splitlines() if cache.exists() else []
    return result, [json.loads(x) for x in lines]


@pytest.mark.parametrize("fmt", ["6.0.0", "6.1.0"])
def test_atlas_v6_gives_technique_and_case_study_records(rag, monkeypatch, fmt):
    result, records = _sync(rag, monkeypatch, _atlas(fmt))
    assert (result.status, len(records)) == ("success", 4)
    by_id = {r["metadata"]["atlas_id"]: r for r in records}
    sub = by_id["AML.T0001.000"]["metadata"]
    assert (sub["type"], sub["title"], sub["tactics"], sub["parent"]) == (
        "technique", "From Papers", "Reconnaissance", "AML.T0001"
    )  # fmt: skip
    assert by_id["AML.T0001"]["metadata"]["parent"] == ""
    assert "Sub-technique of: AML.T0001" in by_id["AML.T0001.000"]["text"]
    assert "Procedure Examples:\n- First step\n" in by_id["AML.T0001.000"]["text"]
    assert "Mitigations:\n- Limit Disclosure\n" in by_id["AML.T0001"]["text"]
    case = by_id["AML.CS0001"]
    assert case["metadata"]["type"] == "case_study"
    assert (
        case["metadata"]["atlas_techniques"] == "AML.T0001.000, AML.T0002"
    )  # step order
    assert "References:\n- Report: https://example.invalid/r" in case["text"]


def test_a_one_edge_mapping_counts_and_an_edge_without_a_target_is_skipped(
    rag, monkeypatch
):
    doc = _atlas()
    rel = doc["relationships"]
    rel["AML.T0002"]["achieves"] = _edge(
        "AML.T0002", "achieves", "AML.TA0005"
    )  # not a list
    rel["AML.CS0001"]["employs"].append(
        {"relationship-type": "employs", "step-id": "S02"}
    )
    result, records = _sync(rag, monkeypatch, doc)
    by_id = {r["metadata"]["atlas_id"]: r for r in records}
    assert by_id["AML.T0002"]["metadata"]["tactics"] == "Execution"
    case = by_id["AML.CS0001"]["metadata"]["atlas_techniques"]
    assert case == "AML.T0001.000, AML.T0002"
    assert not [r for r in records if "None" in r["text"]]


@pytest.mark.parametrize(
    "doc, latest, message",
    [
        (_atlas("7.0.0"), True, "ATLAS: dist/ATLAS-latest.yaml format-version 7.0.0; "
                                "this parser reads 6.x"),
        (None, False, "ATLAS: dist/ATLAS-latest.yaml not found; the upstream layout changed"),
    ],
    ids=["format-7", "no-file"],
)  # fmt: skip
def test_another_layout_or_format_major_fails_the_source(
    rag, monkeypatch, doc, latest, message
):
    result, records = _sync(rag, monkeypatch, doc, latest)
    assert (result.status, result.message, records) == ("error", message, [])


@pytest.mark.parametrize("stale_cache", [True, False], ids=["old-cache", "no-cache"])
@pytest.mark.parametrize("doc, latest", [(_atlas("7.0.0"), True), (None, False)])
def test_a_release_build_stops_before_indexing_when_a_source_fails(
    rag, monkeypatch, tmp_path, stale_cache, doc, latest
):
    s = rag.sources
    others = [n for n in s.SOURCES if n != "mitre_atlas"]
    s.SOURCES_CONFIG_FILE.write_text(json.dumps({"disabled_sources": others}))
    (rag.data / "sources").mkdir(parents=True)
    old = rag.data / "sources" / "mitre_atlas.jsonl"
    if stale_cache:  # what an earlier build left: it must not ship
        old.write_text(
            json.dumps({"text": "old", "metadata": {"source": "mitre_atlas"}}) + "\n"
        )
    monkeypatch.setattr(
        s, "clone_repo", lambda repo, branch, dest: _upstream(dest, doc, latest) or True
    )
    loaded = []
    real_load = rag.build.load_jsonl_records
    monkeypatch.setattr(
        rag.build,
        "load_jsonl_records",
        lambda p: loaded.append(Path(p).name) or real_load(p),
    )
    monkeypatch.setattr(
        sys, "argv", ["build_release", "--output-dir", str(tmp_path / "out")]
    )
    out = io.StringIO()
    with contextlib.redirect_stdout(out), pytest.raises(SystemExit) as exit_:
        rag.build_release.main()
    assert exit_.value.code == 1
    failed = [x for x in out.getvalue().splitlines() if x.startswith("Build failed")]
    assert (
        len(failed) == 1
        and "['mitre_atlas: ATLAS: dist/ATLAS-latest.yaml " in failed[0]
    )
    assert ("format-version 7.0.0" if doc else "not found") in failed[0]
    assert "mitre_atlas.jsonl" not in loaded  # no old records reach an index
