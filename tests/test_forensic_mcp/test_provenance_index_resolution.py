"""An idx_* query artifact is graded FULL only when its source is determined.

The indirect path traced a query to the first resolvable ingest in audit
order, and a directory resolved to its first registered file, so a finding
could be graded FULL with another ingest's evidence as its source. Each row
runs the real record_finding on a scratch case whose audit log uses the
shapes opensearch-mcp and case-mcp write, in both audit orders.
"""

from __future__ import annotations

import json
from pathlib import Path

import forensic_mcp.case.manager as manager_module
import pytest
from forensic_mcp.case.manager import CaseManager

CID = "rowcase-20261002"
RUN1 = "da4898b2-9060-4955-95ca-3a8dfd008ef5"
RUN2 = "11111111-2222-3333-4444-555555555555"


def _entry(mcp, tool, aid, params, inputs=None, result=None):
    e = {
        "ts": "2026-10-02T07:34:00+00:00",
        "mcp": mcp,
        "tool": tool,
        "audit_id": aid,
        "examiner": "examiner",
        "case_id": CID,
        "source": "mcp_server",
        "params": params,
        "result_summary": result or {"value": "x"},
    }
    if inputs is not None:
        e["input_files"] = [str(p) for p in inputs]
        e["input_sha256s"] = []
    return e


def _query(n, index):
    return _entry(
        "opensearch-mcp",
        "idx_search",
        f"opensearch-examiner-20261002-{n}",
        {"query": "x", "index": index},
    )


class Evidence:
    def __init__(self, case: Path):
        ev = case / "evidence"
        self.img = ev / "rd01-memory.img"
        self.img2 = ev / "rd02-memory.img"
        self.json_dir = ev / "C.1/artifacts/Windows.Sysinternals.Autoruns"
        self.json_file = self.json_dir / "F.AAA.json"
        self.kansa = ev / "Output/Autorunsc"
        self.kansa_files = [
            self.kansa / f"{h}.shieldbase.com-Autorunsc.csv"
            for h in ("rd01", "rd08", "wkstn05")
        ]
        self.triage = ev / "triage"
        logs = "C/Windows/System32/winevt/Logs"
        self.security = {
            h: self.triage / h / logs / "Security.evtx" for h in ("rd01", "rd08")
        }
        self.application = {
            h: self.triage / h / logs / "Application.evtx" for h in ("rd01", "rd08")
        }
        self.evtx_dir = ev / "evtx_dir"
        self.derivative = case / "extractions" / "Security_parsed.csv"


def _memory(image, host, run, n):
    """idx_ingest_memory's MCP entry, the worker's per-plugin and completion entries."""
    out = [
        _entry(
            "opensearch-mcp",
            "idx_ingest_memory",
            f"opensearch-examiner-20261002-{n:03d}",
            {"path": str(image), "tier": 2, "pid": 1, "run_id": run},
            [image],
        )
    ]
    for p in ("pstree", "netscan", "cmdline"):
        out.append(
            _entry(
                f"opensearch-ingest-{n}",
                f"ingest_vol3_vol-{p}",
                f"opensearchingest{n}-examiner-20261002-001",
                {
                    "plugin": f"windows.{p}",
                    "image": str(image),
                    "hostname": host,
                    "index_name": f"case-{CID}-vol-{p}-{host}",
                    "run_id": run,
                },
                [image],
            )
        )
    out.append(
        _entry(
            f"opensearch-ingest-{n}",
            "idx_ingest_memory",
            f"opensearchingest{n}-examiner-20261002-001",
            {"path": str(image), "hostname": host, "run_id": run},
            [image],
        )
    )
    return out


def _json_ingest(ev):
    return [
        _entry(
            "opensearch-mcp",
            "idx_ingest_json",
            "opensearch-examiner-20261002-002",
            {"path": str(ev.json_dir), "hostname": "rd01"},
            [ev.json_dir],
        ),
        _entry(
            "opensearch-ingest-2",
            "idx_ingest_json",
            "opensearchingest2-examiner-20261002-001",
            {"path": str(ev.json_dir), "hostname": "rd01"},
            [ev.json_dir],
        ),
    ]


def _kansa_ingest(ev):
    return [
        _entry(
            "opensearch-mcp",
            "idx_ingest_delimited",
            "opensearch-examiner-20261002-012",
            {"path": str(ev.kansa), "hostname": "kansa-fleet"},
            [ev.kansa],
        )
    ]


def _triage_ingest(ev, hosts):
    out = [
        _entry(
            "opensearch-mcp",
            "idx_ingest",
            "opensearch-examiner-20261002-020",
            {"path": str(ev.triage), "hosts": hosts, "pid": 2, "run_id": RUN2},
            [ev.triage],
        )
    ]
    for h in hosts:
        out.append(
            _entry(
                "opensearch-ingest-77",
                "ingest_evtx",
                "opensearchingest77-examiner-20261002-001",
                {
                    "hostname": h,
                    "index_name": f"case-{CID}-evtx-{h}",
                    "file": str(ev.security[h]),
                    "run_id": RUN2,
                },
                [ev.security[h]],
            )
        )
    return out


def _scenario(name, ev):
    """(audit entries, registered evidence, [(query audit id, declared source, expectation)])."""
    vol = f"case-{CID}-vol-pstree-"
    evtx = f"case-{CID}-evtx-"
    s = {
        # No FULL with the wrong source
        "twoimg": (
            _memory(ev.img, "rd01", RUN1, 1)
            + _memory(ev.img2, "rd02", RUN2, 2)
            + [_query("302", f"{vol}rd01,{vol}rd02")],
            [ev.img, ev.img2],
            [("302", ev.img, "not_wrong")],
        ),
        "onehost2": (
            _triage_ingest(ev, ["rd01"]) + [_query("202", f"{evtx}rd01")],
            [ev.security["rd01"], ev.application["rd01"]],
            [
                ("202", ev.security["rd01"], "not_wrong"),
                ("202", ev.application["rd01"], "not_wrong"),
            ],
        ),
        "hostslist": (
            _triage_ingest(ev, ["rd01", "rd08"])
            + [_query("201", f"{evtx}rd08"), _query("202", f"{evtx}rd01")],
            [ev.security["rd01"], ev.security["rd08"]],
            [
                ("201", ev.security["rd08"], "not_wrong"),
                ("202", ev.security["rd01"], "not_wrong"),
            ],
        ),
        "hostslist4": (
            _triage_ingest(ev, ["rd01", "rd08"])
            + [_query("201", f"{evtx}rd08"), _query("202", f"{evtx}rd01")],
            [
                ev.security["rd01"],
                ev.security["rd08"],
                ev.application["rd01"],
                ev.application["rd08"],
            ],
            [
                ("201", ev.security["rd08"], "not_wrong"),
                ("201", ev.application["rd08"], "not_wrong"),
                ("202", ev.security["rd01"], "not_wrong"),
            ],
        ),
        "hostscomma": (
            _triage_ingest(ev, ["rd01", "rd08"])
            + [_query("203", f"{evtx}rd01,{evtx}rd08")],
            [ev.security["rd01"], ev.security["rd08"]],
            [
                ("203", ev.security["rd08"], "not_wrong"),
                ("203", ev.security["rd01"], "not_wrong"),
            ],
        ),
        "directdir": (
            [
                _entry(
                    "sift-mcp",
                    "run_command",
                    "sift-examiner-20261002-050",
                    {"tool": "EvtxECmd", "args": ["-d", str(ev.evtx_dir)]},
                    [ev.evtx_dir],
                ),
            ],
            [ev.evtx_dir / "Application.evtx", ev.evtx_dir / "Security.evtx"],
            [
                ("sift-050", ev.evtx_dir / "Security.evtx", "not_wrong"),
                ("sift-050", ev.evtx_dir / "Application.evtx", "not_wrong"),
            ],
        ),
        "mixed": (
            _json_ingest(ev)
            + _memory(ev.img, "rd01", RUN1, 1)
            + [
                _query(
                    "101",
                    ",".join(
                        f"case-{CID}-vol-{p}-rd01"
                        for p in ("netscan", "cmdline", "pstree")
                    ),
                ),
                _query("102", f"{vol}rd01"),
            ],
            [ev.img, ev.json_file],
            [("101", ev.img, "not_wrong"), ("102", ev.img, "not_wrong")],
        ),
        "kansa3": (
            _kansa_ingest(ev)
            + [_query("104", f"case-{CID}-delim-kansa-autorunsc-kansa-fleet")],
            ev.kansa_files,
            [("104", ev.kansa_files[1], "not_wrong")],
        ),
        # Anchors: one ingest, one file — still FULL with the right source
        "memonly": (
            _memory(ev.img, "rd01", RUN1, 1) + [_query("102", f"{vol}rd01")],
            [ev.img],
            [("102", ev.img, "full")],
        ),
        "jsononly": (
            _json_ingest(ev) + [_query("103", f"case-{CID}-json-vr-autoruns-rd01")],
            [ev.json_file],
            [("103", ev.json_file, "full")],
        ),
        "kansa1": (
            _kansa_ingest(ev)
            + [_query("104", f"case-{CID}-delim-kansa-autorunsc-kansa-fleet")],
            ev.kansa_files[:1],
            [("104", ev.kansa_files[0], "full")],
        ),
        "wildcard1": (
            _memory(ev.img, "rd01", RUN1, 1) + [_query("105", f"case-{CID}-*")],
            [ev.img],
            [("105", ev.img, "full")],
        ),
    }
    # The gate: a wildcard query over two ingests declaring a derivative.
    bridge = _entry(
        "case-mcp",
        "log_external_action",
        "case-examiner-20261002-009",
        {"command": "EvtxECmd -f Security.evtx --csv extractions"},
        [ev.security["rd01"]],
        {"status": "logged", "output_files": [str(ev.derivative)]},
    )
    two_ingests = (
        _json_ingest(ev)
        + _memory(ev.img, "rd01", RUN1, 1)
        + [_query("106", f"case-{CID}-*")]
    )
    s["bridged"] = (
        two_ingests + [bridge],
        [ev.img, ev.json_file, ev.security["rd01"]],
        [("106", ev.derivative, "staged")],
    )
    s["unbridged"] = (
        two_ingests,
        [ev.img, ev.json_file, ev.security["rd01"]],
        [("106", ev.derivative, "rejected")],
    )
    s["bridge_unregistered"] = (
        two_ingests + [bridge],
        [ev.img, ev.json_file],
        [("106", ev.derivative, "rejected")],
    )
    return s[name]


ROWS = sorted(
    [
        "twoimg",
        "onehost2",
        "hostslist",
        "hostslist4",
        "hostscomma",
        "directdir",
        "mixed",
        "kansa3",
    ]
    + ["memonly", "jsononly", "kansa1", "wildcard1"]
    + ["bridged", "unbridged", "bridge_unregistered"]
)


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("VHIR_EXAMINER", "examiner")
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    pointer = tmp_path / ".vhir" / "active_case"
    pointer.parent.mkdir()
    monkeypatch.setattr(manager_module, "_ACTIVE_CASE_FILE", pointer)
    case = tmp_path / "cases" / CID
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {CID}\nstatus: open\n")
    (case / "findings.json").write_text("[]")
    pointer.write_text(str(case))
    return case


@pytest.mark.parametrize("order", ["normal", "reverse"])
@pytest.mark.parametrize("name", ROWS)
def test_a_query_artifact_is_full_only_with_its_own_source(case, name, order):
    ev = Evidence(case)
    entries, registered, plan = _scenario(name, ev)
    if order == "reverse":
        entries = list(reversed(entries))
    (case / "audit" / "all.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in entries)
    )
    (case / "evidence.json").write_text(
        json.dumps({"files": [{"path": str(p), "sha256": ""} for p in registered]})
    )
    cm = CaseManager()
    finding = {
        "title": "row",
        "observation": "o",
        "interpretation": "i",
        "confidence": "LOW",
        "confidence_justification": "row test",
        "type": "finding",
    }
    for n, declared, expect in plan:
        aid = (
            f"sift-examiner-20261002-{n[5:]}"
            if n.startswith("sift-")
            else f"opensearch-examiner-20261002-{n}"
        )
        artifact = {
            "source": str(declared),
            "extraction": "x",
            "content": "row",
            "audit_id": aid,
        }
        result = cm.record_finding(
            dict(finding), artifacts=[artifact], examiner_override="examiner"
        )
        where = f"{name}/{order}/{n}/{declared.name}"
        if expect == "rejected":
            assert result["status"] == "REJECTED", (where, result)
            continue
        assert result["status"] == "STAGED", (where, result)
        stored = [
            f
            for f in json.loads((case / "findings.json").read_text())
            if f["id"] == result["finding_id"]
        ]
        art = stored[0]["artifacts"][0]
        source = art.get("source_evidence") or ""
        if art.get("provenance_grade") == "FULL":
            assert Path(source).resolve() == declared.resolve(), (
                where,
                "FULL with",
                source,
            )
        if expect == "full":
            assert art.get("provenance_grade") == "FULL", (
                where,
                art.get("provenance_grade"),
            )
        # The finding's own source and its auto-timeline event carry no wrong source.
        if stored[0].get("source_evidence"):
            assert Path(stored[0]["source_evidence"]).resolve() == declared.resolve(), (
                where
            )
