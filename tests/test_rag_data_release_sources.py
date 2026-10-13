"""The knowledge build reads Splunk's default branch with its ATT&CK ids, and
every LOLBAS category the triage importer reads.

Each source syncs as build() syncs it (sync_source with force), with the
clone served from a scratch tree by the branch asked for; a branch that
isn't there fails, as git does. rag_mcp.sources is loaded from the source
tree without the index's dependencies. Values are synthetic, in the upstream
YAML shapes.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "packages/forensic-rag/src"


@pytest.fixture
def sources(monkeypatch, tmp_path):
    """rag_mcp.sources, its package __init__ (chromadb) skipped; toml, which
    one other parser uses, stubbed where it isn't installed. Writes go to
    tmp_path. Modules imported here are dropped again afterwards."""
    before = {k for k in sys.modules if k == "rag_mcp" or k.startswith("rag_mcp.")}
    for name in before:
        monkeypatch.delitem(sys.modules, name)
    pkg = types.ModuleType("rag_mcp")
    pkg.__path__ = [str(SRC / "rag_mcp")]
    monkeypatch.setitem(sys.modules, "rag_mcp", pkg)
    if importlib.util.find_spec("toml") is None:
        monkeypatch.setitem(sys.modules, "toml", types.ModuleType("toml"))
    s = importlib.import_module("rag_mcp.sources")
    monkeypatch.setattr(s, "SOURCES_DIR", tmp_path / "sources")
    monkeypatch.setattr(s, "SOURCES_STATE_FILE", tmp_path / "sources_state.json")
    monkeypatch.setattr(s, "SOURCES_CONFIG_FILE", tmp_path / "sources_config.json")
    monkeypatch.setattr(s, "get_latest_version", lambda source: "test")
    yield s
    for name in [k for k in sys.modules if k.startswith("rag_mcp.")]:
        del sys.modules[name]


def _sync(s, monkeypatch, tmp_path, name, branches):
    """Sync `name` with its upstream as {branch: {path: text}}; returns the
    result, the records and the branches asked for."""
    asked = []

    def clone(repo, branch, dest):
        asked.append(branch)
        if branch not in branches:
            return False
        for rel, text in branches[branch].items():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            (dest / rel).write_text(text, encoding="utf-8")
        return True

    monkeypatch.setattr(s, "clone_repo", clone)
    result = s.sync_source(name, force=True)
    cache = tmp_path / "sources" / f"{name}.jsonl"
    lines = cache.read_text(encoding="utf-8").splitlines() if cache.exists() else []
    return result, [json.loads(x) for x in lines], asked


def _detection(name, ids, status="production"):
    return (
        f"name: {name}\nstatus: {status}\ntype: TTP\ndescription: d.\ndata_source: []\n"
        f"search: '| x'\nhow_to_implement: x.\nknown_false_positives: x.\nreferences: []\n{ids}"
    )


SPLUNK = {
    "develop": {  # today's default branch: the ids at the top level, no tags
        "detections/endpoint/a.yml": _detection(
            "Endpoint", "mitre_attack_id:\n- T1105\n"
        ),
        "detections/cloud/b.yml": _detection(
            "Cloud", "mitre_attack_id:\n- T1059.001\n- T1027\n"
        ),
        "detections/endpoint/c.yml": _detection(
            "Scalar", "mitre_attack_id: T1078.004\n"
        ),
        "detections/deprecated/d.yml": _detection("Old", "", status="deprecated"),
    },
    "main": {  # frozen in 2022: the ids under tags
        "detections/endpoint/a.yml": _detection(
            "Main", "tags:\n  mitre_attack_id:\n  - T1105\n"
        ),
    },
}


def test_splunk_reads_develop_and_its_top_level_attack_ids(
    sources, monkeypatch, tmp_path
):
    result, records, asked = _sync(
        sources, monkeypatch, tmp_path, "splunk_security", SPLUNK
    )
    assert (result.status, asked) == ("success", ["develop"])
    ids = {r["metadata"]["title"]: r["metadata"]["mitre_techniques"] for r in records}
    assert ids == {
        "Endpoint": "T1105",
        "Cloud": "T1059.001,T1027",
        "Scalar": "T1078.004",
        "Old": "",
    }


def _lolbin(name):
    return f"Name: {name}\nDescription: d\nCommands:\n  - Command: {name.lower()} x\n"


LOLBAS = {
    "master": {
        "yml/OSBinaries/Certutil.yml": _lolbin("Certutil.exe"),
        "yml/OSLibraries/Advpack.yml": _lolbin("Advpack.dll"),
        "yml/OSScripts/Pubprn.yml": _lolbin("Pubprn.vbs"),
        "yml/OtherMSBinaries/Copilot_proxy.yml": _lolbin("Copilot_proxy.exe"),
        "yml/HonorableMentions/Mention.yml": _lolbin("Mention.exe"),
    }
}


def test_lolbas_reads_the_four_categories_triage_reads(sources, monkeypatch, tmp_path):
    branch = sources.SOURCES["lolbas"].branch
    upstream = {branch: LOLBAS["master"]}
    result, records, _ = _sync(sources, monkeypatch, tmp_path, "lolbas", upstream)
    assert result.status == "success"
    titles = sorted(r["metadata"]["title"] for r in records)
    assert titles == ["Advpack.dll", "Certutil.exe", "Copilot_proxy.exe", "Pubprn.vbs"]
    certutil = next(r for r in records if r["metadata"]["title"] == "Certutil.exe")
    assert "certutil.exe x" in certutil["text"]
