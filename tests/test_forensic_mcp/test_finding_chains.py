"""A finding's chain: each artifact traced from what it cites to the registered
evidence it came from, through recorded links only, with its quote checked.

Each case writes the audit entries and registry the platform writes (run
outputs, ingest steps with their inputs and outputs, mounts and unmounts,
queries with the records they returned and their saved response, reference
lookups), then records a finding and reads back its grade and chain: FULL,
DECLARED, AMBIGUOUS, BROKEN (with the kind of break) or CITED-UNVERIFIED.
Another host's resolvable ingest is often logged first: the old resolver
picked it, a recorded chain never does.
"""

import hashlib
import json
from pathlib import Path

import forensic_mcp.case.manager as _mgr
import pytest
import yaml
from forensic_mcp.case.manager import CaseManager
from sift_common import provenance as pv

EMPTY = hashlib.sha256(b"").hexdigest()
CASE_ID = "INC-2026-1009000000"


def sha(p) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


class C:
    def __init__(self, m: CaseManager, d: Path):
        self.m, self.d = m, d

    def file(self, rel: str, data: bytes | str) -> str:
        p = self.d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)
        return str(p)

    def register(self, path: str, manifest=None, **extra) -> None:
        """As vhir registers: a file with its hash; a folder (kind "folder")
        with a manifest file of case-relative rows and its hash."""
        ev = json.loads((self.d / "evidence.json").read_text())
        row = {"path": path, "registered_by": "tester", **extra}
        if Path(path).is_file():
            row["sha256"] = sha(path)
        if manifest is not None:
            base = Path(path).resolve().relative_to(self.d.resolve())
            data = json.dumps(
                {
                    "folder": path,
                    "skipped": [],
                    "unreadable": [],
                    "files": [
                        {"path": str(base / m["relpath"]), "sha256": m["sha256"]}
                        for m in manifest
                    ],
                }
            ).encode()
            n = len(list((self.d / "evidence-manifests").glob("*.json"))) + 1
            (self.d / "evidence-manifests").mkdir(exist_ok=True)
            (self.d / "evidence-manifests" / f"{n}.json").write_bytes(data)
            row.update(
                manifest_path=f"evidence-manifests/{n}.json",
                manifest_sha256=hashlib.sha256(data).hexdigest(),
                file_count=len(manifest),
            )
        ev["files"].append(row)
        (self.d / "evidence.json").write_text(json.dumps(ev))

    def op(self, log: str, aid: str, legacy: bool = False, **fields) -> None:
        entry = {
            "audit_id": aid,
            "ts": "2026-10-09T00:00:00Z",
            "case_id": CASE_ID,
            "examiner": "tester",
            **fields,
        }
        with open(self.d / "audit" / f"{log}.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")

    def run(self, aid, cmd, inputs, out_text, method="parsed", **extra):
        out = self.file(f"extractions/{aid}.txt", out_text)
        self.op(
            "sift-mcp",
            aid,
            tool="run_command",
            params={"command": cmd, "purpose": "p"},
            result_summary={
                "exit_code": 0,
                "output_file": out,
                "output_sha256": sha(out),
            },
            input_files=inputs,
            input_sha256s=[sha(i) if Path(i).is_file() else "" for i in inputs],
            input_detection_method=method,
            **extra,
        )
        return out

    def find(self, arts, finding_extra=None):
        finding = {
            "title": "t",
            "observation": "o",
            "interpretation": "i",
            "confidence": "MEDIUM",
            "confidence_justification": "j",
            "type": "finding",
            "audit_ids": [a["audit_id"] for a in arts],
            **(finding_extra or {}),
        }
        arts = [
            {
                "source": a.get("source", "x"),
                "extraction": "e",
                "content": a["content"],
                "audit_id": a["audit_id"],
            }
            for a in arts
        ]
        res = self.m.record_finding(finding, artifacts=arts)
        staged = None
        if res.get("status") == "STAGED":
            fs = json.loads((self.d / "findings.json").read_text())
            staged = next(f for f in fs if f["id"] == res["finding_id"])
        return res, staged


def g(res, staged, i=0):
    """The artifact's grade and break kind, or the refusal."""
    if staged is None:
        return ("NOT-STAGED", res.get("status"), res.get("error", "")[:80])
    a = staged["artifacts"][i]
    return (
        a.get("provenance_grade"),
        (a.get("provenance_break") or {}).get("kind"),
        a.get("source_evidence", ""),
    )


@pytest.fixture
def c(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "ledger").mkdir()
    monkeypatch.setattr(_mgr, "LEDGER_DIR", tmp_path / "ledger")
    monkeypatch.setattr(_mgr, "_ACTIVE_CASE_FILE", tmp_path / ".vhir" / "active_case")
    m = CaseManager()
    d = tmp_path / CASE_ID
    for sub in ("evidence", "extractions", "reports", "audit"):
        (d / sub).mkdir(parents=True)
    (d / "CASE.yaml").write_text(
        yaml.dump(
            {"case_id": CASE_ID, "name": "n", "status": "open", "examiner": "tester"}
        )
    )
    for n in ("findings.json", "timeline.json", "todos.json"):
        (d / n).write_text("[]")
    (d / "evidence.json").write_text('{"files": []}')
    m._active_case_id = CASE_ID
    m._active_case_path = d
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("VHIR_ACTIVE_CASE", CASE_ID)
    return C(m, d)


def two_images(c):
    a = c.file("evidence/imgA.raw", "image A bytes")
    b = c.file("evidence/imgB.raw", "image B bytes")
    c.register(a)
    c.register(b)
    return a, b


def _point(mp, st_dev, mnt_id, offset=None):
    """A mount point as recorded: mount {image, points: [{target, realpath,
    st_dev, mnt_id}]}; an ingest's mount adds an offset per point."""
    pt = {"target": str(mp), "realpath": str(mp), "st_dev": st_dev, "mnt_id": mnt_id}
    if offset is not None:
        pt["offset"] = offset
    return pt


def _umount(c, aid, mp, mnt_id, log="sift-mcp"):
    c.op(
        log,
        aid,
        tool="run_command",
        params={"command": ["umount", str(mp)], "purpose": "p"},
        result_summary={"exit_code": 0},
        umount={"realpath": str(mp), "mnt_id": mnt_id},
    )


def _mount(c, img, mp, st_dev, aid, unmounted=False):
    c.op(
        "sift-mcp",
        aid,
        tool="run_command",
        params={"command": ["mount", "-o", "ro,loop", img, mp], "purpose": "p"},
        result_summary={"exit_code": 0},
        input_files=[img],
        input_sha256s=[sha(img)],
        input_detection_method="parsed",
        mount={"image": img, "points": [_point(mp, st_dev, 7001)]},
    )


def _search(
    c,
    docs,
    aid="opensearch-tester-20261009-003",
    with_results=True,
    tool="idx_search",
    index="",
    groups=None,
    result_ingests=None,
    text=None,
):
    """A query entry as it's written: params.result_docs (each returned record's
    index, id, ingest, content hash, original, enrichment op ids),
    params.result_ingests, and the response as returned, saved under
    extractions/<audit id>/response.json with its hash on the entry."""
    body = text if text is not None else json.dumps({"results": docs, "audit_id": aid})
    resp = c.file(f"extractions/{aid}/response.json", body)
    params = {
        "query": "4624",
        "index": index,
        "scope": index or "case-x-*",
        "limit": 10,
    }
    if with_results:
        params["result_docs"] = [
            {
                "_index": d["_index"],
                "_id": d["_id"],
                "ingest_audit_id": d["vhir.ingest_audit_id"],
                "content_hash": hashlib.sha256(
                    json.dumps(d, sort_keys=True).encode()
                ).hexdigest(),
                "original_sha256": d.get("vhir.original", ""),
                **({"enrichment": groups} if groups else {}),
            }
            for d in docs
        ]
        params["result_ingests"] = sorted({d["vhir.ingest_audit_id"] for d in docs})
        if tool == "idx_list_detections":
            params["result_findings"] = [
                {"id": "f1", "index": d["_index"], "related_doc_ids": [d["_id"]]}
                for d in docs
            ]
    if result_ingests is not None:
        params["result_ingests"] = result_ingests
    c.op(
        "opensearch-mcp",
        aid,
        tool=tool,
        params=params,
        result_summary=f"{len(docs)} total",
        response={"path": resp, "sha256": sha(resp)},
    )
    return aid


DEV = "opensearch-tester-20261009-090"
ALLOWED = ("registered-path", "manifest", "hash+place", "recorded-id", "recorded-mount")


def _chain(st, i=0):
    return json.dumps(st["artifacts"][i].get("provenance_chain", []))


def _methods_ok(st, i=0):
    links = st["artifacts"][i].get("provenance_chain", [])
    return bool(links) and all(l.get("method") in ALLOWED for l in links), links


def _dev01_first(c):
    """Another host's resolvable ingest, logged first (the old resolver picks it)."""
    dev = c.file("evidence/dev01/Security.evtx", "dev01 evtx")
    c.register(dev)
    c.op(
        "opensearch-mcp",
        DEV,
        tool="idx_ingest",
        params={"path": dev, "hostname": "dev01", "run_id": "run-z"},
        input_files=[dev],
        input_sha256s=[sha(dev)],
        result_summary="ok",
    )


def _doc(i, ingest, **fields):
    return {"_id": i, "_index": "case-x-vol", **fields, "vhir.ingest_audit_id": ingest}


def _seven_zip(c):
    z = c.file("evidence/mem.7z", "7z bytes")
    c.register(z)
    return z


def _extract(c, aid, z, log="sift-mcp", tool="run_command", **extra):
    """A recorded 7z extraction: the 7z is the registered file itself, so its input
    carries no fresh hash (linked by registered path + registry hash)."""
    s1 = c.file(f"extractions/{aid}/sample1.raw", "sample one")
    s2 = c.file(f"extractions/{aid}/sample2.raw", "sample two")
    c.op(
        log,
        aid,
        tool=tool,
        params={"command": ["7z", "x", z], "purpose": "p"},
        input_files=[z],
        input_sha256s=[""],
        input_detection_method="parsed",
        result_summary={
            "exit_code": 0,
            "output_files": [s1, s2],
            "output_sha256s": [sha(s1), sha(s2)],
        },
        **extra,
    )
    return s1, s2


# --- a 7z of two memory samples --------------------------------------------------


def test_vol_on_sample_two_after_a_run_command_extraction_traces_to_the_7z(c):
    z = _seven_zip(c)
    s1, s2 = _extract(c, "sift-tester-20261009-001", z)
    c.run(
        "sift-tester-20261009-002",
        ["vol", "-f", s2, "windows.pslist"],
        [s2],
        "PID 4 System\n",
    )
    res, st = c.find(
        [{"content": "PID 4 System", "audit_id": "sift-tester-20261009-002"}]
    )
    assert g(res, st)[0] == "FULL" and st["source_evidence"] == z, g(res, st)
    ok, links = _methods_ok(st)
    assert ok, links
    assert links[0]["method"] == "registered-path" and links[0]["to"]["sha256"] == sha(
        z
    ), links[0]
    assert sha(s2) in _chain(st) and "sample1" not in _chain(st)


def test_an_ingested_sample_two_traces_through_the_extraction_to_the_7z(c):
    _dev01_first(c)
    z = _seven_zip(c)
    x = "opensearch-ingest-7-20261009-010"
    s1, s2 = _extract(c, x, z, log="opensearch-ingest-7", tool="extract_archive")
    for n, s in ((11, s1), (12, s2)):
        c.op(
            "opensearch-ingest-7",
            f"opensearch-ingest-7-20261009-0{n}",
            tool="ingest_vol3_pslist",
            params={"run_id": "run-m", "image": s},
            input_files=[s],
            input_sha256s=[sha(s)],
            input_detection_method="parsed",
        )
    aid = _search(
        c,
        [
            _doc(
                "d2", "opensearch-ingest-7-20261009-012", **{"process.name": "evil.exe"}
            )
        ],
    )
    res, st = c.find([{"content": "evil.exe", "audit_id": aid}])
    assert g(res, st)[0] == "FULL" and st["source_evidence"] == z, g(res, st)
    ch = _chain(st)
    assert sha(s2) in ch and x in ch and "sample1" not in ch and DEV not in ch


def test_a_bash_extraction_with_its_hook_entry_declared_is_declared(c):
    """Anything the AI's Bash creates is DECLARED. The hook
    records the command only; the output reaches the trail through log_external_action."""
    z = _seven_zip(c)
    s2 = c.file("extractions/bash/sample2.raw", "sample two")
    c.op(
        "claude-code",
        "hook-tester-20261009-001",
        tool="Bash",
        source="claude-code-hook",
        params={"command": f"7z x {z} -oextractions/bash"},
    )
    c.op(
        "case-mcp",
        "case-tester-20261009-001",
        tool="log_external_action",
        params={
            "command": f"7z x {z} -oextractions/bash",
            "purpose": "p",
            "hook_audit_id": "hook-tester-20261009-001",
        },
        result_summary={
            "status": "logged",
            "source": "orchestrator_verified",
            "output_files": [s2],
            "output_sha256s": [sha(s2)],
        },
        source="orchestrator_verified",
        input_files=[z],
        declared=True,
    )
    c.run(
        "sift-tester-20261009-002",
        ["vol", "-f", s2, "windows.pslist"],
        [s2],
        "PID 4 System\n",
    )
    res, st = c.find(
        [{"content": "PID 4 System", "audit_id": "sift-tester-20261009-002"}]
    )
    assert g(res, st)[0] == "DECLARED", g(res, st)


def test_a_bash_extraction_declared_with_log_external_action_is_declared(c):
    z = _seven_zip(c)
    mem2 = c.file("extractions/s/sample2.raw", "sample two")
    c.op(
        "case-mcp",
        "case-tester-20261009-001",
        tool="log_external_action",
        params={"command": f"7z x {z} -oextractions/s", "purpose": "p"},
        result_summary={
            "status": "logged",
            "source": "orchestrator_voluntary",
            "output_files": [mem2],
            "output_sha256s": [sha(mem2)],
        },
        source="orchestrator_voluntary",
        input_files=[z],
        declared=True,
    )
    c.run(
        "sift-tester-20261009-002",
        ["vol", "-f", mem2, "windows.pslist"],
        [mem2],
        "PID 4 System\n",
    )
    res, st = c.find(
        [{"content": "PID 4 System", "audit_id": "sift-tester-20261009-002"}]
    )
    assert g(res, st)[0] == "DECLARED", g(res, st)


def test_an_unlogged_bash_made_sample_breaks_with_the_named_reason(c):
    """A Bash-made file, unlogged → a named BROKEN; logged via log_external_action → DECLARED."""
    z = _seven_zip(c)
    c.op(
        "claude-code",
        "hook-tester-20261009-001",
        tool="Bash",
        source="claude-code-hook",
        params={"command": f"7z x {z} -oextractions/loose"},
    )
    s2 = c.file("extractions/loose/sample2.raw", "sample two")
    c.run(
        "sift-tester-20261009-002",
        ["vol", "-f", s2, "windows.pslist"],
        [s2],
        "PID 4 System\n",
    )
    res, st = c.find(
        [
            {
                "content": "PID 4 System",
                "audit_id": "sift-tester-20261009-002",
                "source": s2,
            }
        ]
    )
    assert "evidence_register" not in json.dumps(res), res
    assert g(res, st)[:2] == ("BROKEN", "no-recorded-origin"), g(res, st)
    assert (
        st["artifacts"][0].get("provenance_reason")
        == "no recorded origin: made outside recorded tools"
    ), st["artifacts"][0]


def test_an_unrecorded_copy_of_the_7z_doesnt_link_by_hash_alone(c):
    z = _seven_zip(c)
    copy = c.file("extractions/work/copy-of-mem.7z", "7z bytes")
    c.op(
        "sift-mcp",
        "sift-tester-20261009-001",
        tool="run_command",
        params={"command": ["7z", "x", copy], "purpose": "p"},
        input_files=[copy],
        input_sha256s=[sha(copy)],
        input_detection_method="parsed",
        result_summary={
            "exit_code": 0,
            "output_file": c.file("extractions/l.txt", "sample2.raw\n"),
            "output_sha256": sha(c.d / "extractions/l.txt"),
        },
    )
    res, st = c.find(
        [{"content": "sample2.raw", "audit_id": "sift-tester-20261009-001"}]
    )
    assert g(res, st)[:2] == ("BROKEN", "no-recorded-origin"), g(res, st)


def test_sample_two_extracted_twice_to_one_path_is_ambiguous(c):
    z = _seven_zip(c)
    s2 = c.file("extractions/shared/sample2.raw", "sample two")
    for aid in ("sift-tester-20261009-001", "sift-tester-20261009-002"):
        c.op(
            "sift-mcp",
            aid,
            tool="run_command",
            params={"command": ["7z", "x", z, "-oextractions/shared"], "purpose": "p"},
            input_files=[z],
            input_sha256s=[""],
            input_detection_method="parsed",
            result_summary={
                "exit_code": 0,
                "output_files": [s2],
                "output_sha256s": [sha(s2)],
            },
        )
    c.run(
        "sift-tester-20261009-003",
        ["vol", "-f", s2, "windows.pslist"],
        [s2],
        "PID 4 System\n",
    )
    res, st = c.find(
        [{"content": "PID 4 System", "audit_id": "sift-tester-20261009-003"}]
    )
    assert g(res, st)[0] == "AMBIGUOUS", g(res, st)
    ids = {
        x.get("audit_id") for x in st["artifacts"][0].get("provenance_candidates", [])
    }
    assert ids == {"sift-tester-20261009-001", "sift-tester-20261009-002"}, ids


def test_a_search_over_both_samples_follows_only_the_quoted_sample(c):
    _dev01_first(c)
    z = _seven_zip(c)
    x = "opensearch-ingest-7-20261009-010"
    s1, s2 = _extract(c, x, z, log="opensearch-ingest-7", tool="extract_archive")
    for n, s in ((11, s1), (12, s2)):
        c.op(
            "opensearch-ingest-7",
            f"opensearch-ingest-7-20261009-0{n}",
            tool="ingest_vol3_pslist",
            params={"run_id": "run-m", "image": s},
            input_files=[s],
            input_sha256s=[sha(s)],
            input_detection_method="parsed",
        )
    aid = _search(
        c,
        [
            _doc("d1", "opensearch-ingest-7-20261009-011", **{"process.name": "a.exe"}),
            _doc(
                "d2", "opensearch-ingest-7-20261009-012", **{"process.name": "evil.exe"}
            ),
        ],
    )
    res, st = c.find([{"content": "evil.exe", "audit_id": aid}])
    assert g(res, st)[0] == "FULL" and st["source_evidence"] == z, g(res, st)
    ch = _chain(st)
    assert sha(s2) in ch and sha(s1) not in ch and DEV not in ch


def test_a_search_that_records_no_results_is_never_full(c):
    _dev01_first(c)
    _seven_zip(c)
    aid = _search(c, [], with_results=False)
    res, st = c.find([{"content": "evil.exe", "audit_id": aid}])
    assert g(res, st)[:2] == ("BROKEN", "no-results-recorded"), g(res, st)


def test_each_link_carries_its_entry_line_hash_and_the_root_hash(c):
    """What an approval signs: each link's line hash, and the root's hash."""
    z = _seven_zip(c)
    _extract(c, "sift-tester-20261009-001", z)
    s2 = str(c.d / "extractions/sift-tester-20261009-001/sample2.raw")
    c.run(
        "sift-tester-20261009-002",
        ["vol", "-f", s2, "windows.pslist"],
        [s2],
        "PID 4 System\n",
    )
    lines = (c.d / "audit" / "sift-mcp.jsonl").read_bytes().splitlines()
    res, st = c.find(
        [{"content": "PID 4 System", "audit_id": "sift-tester-20261009-002"}]
    )
    links = {l.get("audit_id"): l for l in st["artifacts"][0]["provenance_chain"]}
    assert (
        links.get("sift-tester-20261009-001", {}).get("entry_sha256")
        == hashlib.sha256(lines[0]).hexdigest()
    )
    assert (
        links.get("sift-tester-20261009-002", {}).get("entry_sha256")
        == hashlib.sha256(lines[1]).hexdigest()
    )
    root = st["artifacts"][0].get("provenance_root", {})
    assert root.get("sha256") == sha(z) and root.get("label"), root


# --- stamps, folders, reference data, grades, mounts -----------------------------


def test_a_record_stamped_with_another_root_is_a_stamp_mismatch(c):
    z = _seven_zip(c)
    other = c.file("evidence/other.7z", "other bytes")
    c.register(other)
    x = "opensearch-ingest-7-20261009-010"
    s1, s2 = _extract(c, x, z, log="opensearch-ingest-7", tool="extract_archive")
    c.op(
        "opensearch-ingest-7",
        "opensearch-ingest-7-20261009-012",
        tool="ingest_vol3_pslist",
        params={"run_id": "run-m"},
        input_files=[s2],
        input_sha256s=[sha(s2)],
        input_detection_method="parsed",
    )
    aid = _search(
        c,
        [
            _doc(
                "d2",
                "opensearch-ingest-7-20261009-012",
                **{"process.name": "evil.exe", "vhir.original": sha(other)},
            )
        ],
    )
    res, st = c.find([{"content": "evil.exe", "audit_id": aid}])
    assert g(res, st)[:2] == ("BROKEN", "stamp-mismatch"), g(res, st)


def test_a_file_in_a_registered_folder_links_by_its_manifest(c):
    f1 = c.file(
        "evidence/kape/C/Windows/System32/winevt/Logs/System.evtx", "kape system evtx"
    )
    folder = str(c.d / "evidence/kape")
    c.register(
        folder,
        kind="folder",
        manifest=[
            {"relpath": "C/Windows/System32/winevt/Logs/System.evtx", "sha256": sha(f1)}
        ],
    )
    c.run(
        "sift-tester-20261009-001", ["EvtxECmd", "-f", f1], [f1], "7045 svc installed\n"
    )
    res, st = c.find(
        [{"content": "7045 svc installed", "audit_id": "sift-tester-20261009-001"}]
    )
    assert g(res, st)[0] == "FULL", g(res, st)
    assert st["artifacts"][0]["provenance_root"]["sha256"] == sha(f1)


def test_threat_intel_is_kept_out_of_the_findings_grade(c):
    z = _seven_zip(c)
    s1, s2 = _extract(c, "sift-tester-20261009-001", z)
    c.run("sift-tester-20261009-002", ["strings", s2], [s2], "evil.example.com\n")
    resp = c.file(
        "extractions/opencti-1.json", '{"ioc": "evil.example.com", "labels": ["c2"]}'
    )
    c.op(
        "opencti-mcp",
        "opencti-tester-20261009-001",
        tool="lookup_ioc",
        params={"ioc": "evil.example.com"},
        result_summary="found",
        reference={
            "source": "opencti",
            "source_version": "6.4",
            "response": {"path": resp, "sha256": sha(resp)},
        },
    )
    res, st = c.find(
        [
            {"content": "evil.example.com", "audit_id": "sift-tester-20261009-002"},
            {
                "content": "c2",  # a value as returned, never the JSON text
                "audit_id": "opencti-tester-20261009-001",
                "source": "OpenCTI",
            },
        ]
    )
    assert st is not None, g(res, st)
    assert st["artifacts"][1]["provenance_chain"][-1].get("method") == "reference"
    assert st["artifacts"][1]["provenance_grade"] != "FULL"
    assert st["provenance_grade"] == "FULL"


def test_a_finding_with_no_artifacts_is_declared_never_partial(c):
    res = c.m.record_finding(
        {
            "title": "t",
            "observation": "o",
            "interpretation": "i",
            "confidence": "LOW",
            "confidence_justification": "j",
            "type": "finding",
        },
        supporting_commands=[
            {"command": "grep x y", "purpose": "p", "output_excerpt": "x"}
        ],
    )
    fs = json.loads((c.d / "findings.json").read_text())
    f = next((f for f in fs if f["id"] == res.get("finding_id")), {})
    assert f.get("provenance_grade") == "DECLARED", (
        res.get("status"),
        f.get("provenance_grade"),
    )


def test_a_read_under_a_recorded_mount_links_by_the_mount(c):
    a, _ = two_images(c)
    mp = c.d / "mnt"
    sec = c.file("mnt/Windows/System32/winevt/Logs/Security.evtx", "evtx inside A")
    _mount(c, a, str(mp), 2049, "sift-tester-20261009-001")
    c.run(
        "sift-tester-20261009-002",
        ["EvtxECmd", "-f", sec],
        [sec],
        "4624 alice\n",
        input_realpaths=[sec],
        input_st_devs=[2049],
    )
    res, st = c.find(
        [
            {
                "content": "4624 alice",
                "audit_id": "sift-tester-20261009-002",
                "source": sec,
            }
        ]
    )
    assert g(res, st)[0] == "FULL" and st["source_evidence"] == a, g(res, st)
    assert any(
        l.get("method") == "recorded-mount"
        for l in st["artifacts"][0]["provenance_chain"]
    )


def test_another_filesystem_under_the_mount_point_breaks(c):
    a, _ = two_images(c)
    mp = c.d / "mnt"
    sec = c.file("mnt/Windows/System32/winevt/Logs/Security.evtx", "not from A")
    _mount(c, a, str(mp), 2049, "sift-tester-20261009-001")
    c.run(
        "sift-tester-20261009-002",
        ["EvtxECmd", "-f", sec],
        [sec],
        "4624 alice\n",
        input_realpaths=[sec],
        input_st_devs=[64768],
    )
    res, st = c.find(
        [
            {
                "content": "4624 alice",
                "audit_id": "sift-tester-20261009-002",
                "source": sec,
            }
        ]
    )
    assert g(res, st)[:2] == ("BROKEN", "mount-mismatch"), g(res, st)


# --- the quote check: the cited operation must have produced the quote ----------


def _ingested_samples(c):
    _dev01_first(c)
    z = _seven_zip(c)
    x = "opensearch-ingest-7-20261009-010"
    s1, s2 = _extract(c, x, z, log="opensearch-ingest-7", tool="extract_archive")
    for n, s in ((11, s1), (12, s2)):
        c.op(
            "opensearch-ingest-7",
            f"opensearch-ingest-7-20261009-0{n}",
            tool="ingest_vol3_pslist",
            params={"run_id": "run-m", "image": s},
            input_files=[s],
            input_sha256s=[sha(s)],
            input_detection_method="parsed",
        )
    return z, s1, s2


def test_sample_one_content_citing_the_run_on_sample_two_is_cited_unverified(c):
    z = _seven_zip(c)
    s1, s2 = _extract(c, "sift-tester-20261009-001", z)
    c.run(
        "sift-tester-20261009-002",
        ["vol", "-f", s1, "windows.pslist"],
        [s1],
        "PID 111 alpha.exe\n",
    )
    c.run(
        "sift-tester-20261009-003",
        ["vol", "-f", s2, "windows.pslist"],
        [s2],
        "PID 4 System\n",
    )
    res, st = c.find(
        [{"content": "PID 111 alpha.exe", "audit_id": "sift-tester-20261009-003"}]
    )
    assert g(res, st)[0] == "CITED-UNVERIFIED", g(res, st)


def test_a_quote_in_no_returned_document_is_cited_unverified(c):
    z, s1, s2 = _ingested_samples(c)
    aid = _search(
        c,
        [
            _doc("d1", "opensearch-ingest-7-20261009-011", **{"process.name": "a.exe"}),
            _doc(
                "d2", "opensearch-ingest-7-20261009-012", **{"process.name": "evil.exe"}
            ),
        ],
    )
    res, st = c.find([{"content": "mallory.exe", "audit_id": aid}])
    assert g(res, st)[0] == "CITED-UNVERIFIED", g(res, st)


def _enrich(c, aid="opensearch-tester-20261009-050"):
    """Enrichment: a reference step (enrich_triage, {source, source_version})."""
    c.op(
        "opensearch-mcp",
        aid,
        tool="enrich_triage",
        params={"index": "case-x-*"},
        result_summary="started",
        reference={"source": "windows-triage", "source_version": "2026.10"},
    )


def _triaged(op):
    doc = _doc(
        "d2",
        "opensearch-ingest-7-20261009-012",
        **{"process.name": "evil.exe", "triage.verdict": "SUSPICIOUS"},
    )
    return [doc], {"triage": op}


def test_a_quoted_enrichment_field_is_graded_by_its_records_evidence(c):
    """The returned record names its enrichment step in result_docs[].enrichment:
    the quote links to that step as reference data, and the record is followed
    to its evidence as usual."""
    z, s1, s2 = _ingested_samples(c)
    _enrich(c)
    docs, groups = _triaged("opensearch-tester-20261009-050")
    aid = _search(c, docs, groups=groups)
    res, st = c.find([{"content": "SUSPICIOUS", "audit_id": aid}])
    assert g(res, st) == ("FULL", None, z), g(res, st)
    a = st["artifacts"][0]
    last = a["provenance_chain"][-1]
    assert last.get("method") == "reference", last
    assert last.get("audit_id") == "opensearch-tester-20261009-050"
    assert last.get("reference") == {
        "source": "windows-triage",
        "source_version": "2026.10",
    }
    assert sha(s2) in _chain(st) and sha(s1) not in _chain(st)
    assert (
        "reference: windows-triage, 2026.10, op opensearch-tester-20261009-050"
        in a["provenance_reason"]
    )
    assert st["provenance_grade"] == "FULL"


def test_enrichment_whose_step_isnt_recorded_is_a_named_break(c):
    z, s1, s2 = _ingested_samples(c)
    docs, groups = _triaged("opensearch-tester-20261009-051")  # never logged
    aid = _search(c, docs, groups=groups)
    res, st = c.find([{"content": "SUSPICIOUS", "audit_id": aid}])
    assert g(res, st)[:2] == ("BROKEN", "reference-not-recorded"), g(res, st)
    assert "opensearch-tester-20261009-051" in st["artifacts"][0]["provenance_reason"]
    assert st["provenance_grade"] == "BROKEN"


def test_a_query_logged_before_0_6_4_is_labelled_so_not_cited_unverified(c):
    """Before 0.6.4 a query recorded neither its results nor its response."""
    _ingested_samples(c)
    aid = "opensearch-tester-20261009-060"
    c.op(
        "opensearch-mcp",
        aid,
        tool="idx_search",
        params={"query": "evil.exe", "index": "case-x-*", "limit": 10},
        result_summary="1 total, 1 returned",
    )
    res, st = c.find([{"content": "evil.exe", "audit_id": aid}])
    assert g(res, st)[:2] == ("BROKEN", "recorded-before-0.6.4"), g(res, st)
    assert st["artifacts"][0]["provenance_reason"].startswith("recorded before 0.6.4")


def test_a_query_with_recorded_results_but_no_saved_response_is_cited_unverified(c):
    """It recorded what it returned, but not the response the quote is checked
    against."""
    _ingested_samples(c)
    aid = "opensearch-tester-20261009-061"
    c.op(
        "opensearch-mcp",
        aid,
        tool="idx_search",
        params={
            "query": "evil.exe",
            "result_docs": [
                {
                    "_index": "case-x-vol",
                    "_id": "d2",
                    "ingest_audit_id": "opensearch-ingest-7-20261009-012",
                    "content_hash": "",
                    "original_sha256": "",
                }
            ],
            "result_ingests": ["opensearch-ingest-7-20261009-012"],
        },
        result_summary="1 total, 1 returned",
    )
    res, st = c.find([{"content": "evil.exe", "audit_id": aid}])
    assert g(res, st)[:2] == ("CITED-UNVERIFIED", "cited-unverified"), g(res, st)


def test_one_id_on_two_entries_is_ambiguous_never_the_last_copy(c):
    """Ids can repeat in today's trail; never the last copy."""
    z = _seven_zip(c)
    s1, s2 = _extract(c, "sift-tester-20261009-001", z)
    c.run(
        "sift-tester-20261009-002",
        ["vol", "-f", s1, "windows.pslist"],
        [s1],
        "PID 4 System\n",
    )
    c.run(
        "sift-tester-20261009-002",
        ["vol", "-f", s2, "windows.pslist"],
        [s2],
        "PID 4 System\n",
    )
    res, st = c.find(
        [{"content": "PID 4 System", "audit_id": "sift-tester-20261009-002"}]
    )
    assert g(res, st)[0] == "AMBIGUOUS", g(res, st)


# --- other routes: tool CSVs, mounts, detections, wintools, folders, acquisitions


def _evtx_csv_run(
    c, ev, aid="sift-tester-20261009-001", csv_text="EventId,User\n4624,bob\n", **extra
):
    out_dir = c.d / "extractions" / aid
    csv = c.file(f"extractions/{aid}/out.csv", csv_text)
    stdout = c.file(f"extractions/{aid}/stdout.txt", "Processed 1 file\n")
    c.op(
        "sift-mcp",
        aid,
        tool="run_command",
        params={
            "command": ["EvtxECmd", "-f", ev, "--csv", str(out_dir)],
            "purpose": "p",
        },
        input_files=[ev],
        input_sha256s=[""],
        input_detection_method="catalog",
        result_summary={
            "exit_code": 0,
            "output_file": stdout,
            "output_sha256": sha(stdout),
            "output_files": [csv],
            "output_sha256s": [sha(csv)],
        },
        **extra,
    )
    return csv


def test_a_quote_from_the_tools_own_csv_is_full(c):
    """The quoted line is in the tool's recorded CSV, not in its stdout."""
    ev = c.file("evidence/Security.evtx", "evtx")
    c.register(ev)
    _evtx_csv_run(c, ev)
    res, st = c.find([{"content": "4624,bob", "audit_id": "sift-tester-20261009-001"}])
    assert g(res, st)[0] == "FULL" and st["source_evidence"] == ev, g(res, st)
    ok, links = _methods_ok(st)
    assert ok and links[0]["method"] == "registered-path", links


def test_a_quote_from_a_csv_edited_after_the_run_is_cited_unverified(c):
    ev = c.file("evidence/Security.evtx", "evtx")
    c.register(ev)
    csv = _evtx_csv_run(c, ev)
    Path(csv).write_text("EventId,User\n4624,bob\n4624,mallory\n")
    res, st = c.find(
        [{"content": "4624,mallory", "audit_id": "sift-tester-20261009-001"}]
    )
    assert g(res, st)[0] == "CITED-UNVERIFIED", g(res, st)


def test_evtxecmd_under_a_recorded_mount_then_csv_ingest_then_query(c):
    """Image → run_command mount → EvtxECmd --csv → idx_ingest_delimited → search."""
    _dev01_first(c)
    image = c.file("evidence/rd01.E01", "e01 bytes")
    c.register(image)
    mp = c.d / "mnt"
    sec = c.file("mnt/Windows/System32/winevt/Logs/Security.evtx", "sec")
    c.op(
        "sift-mcp",
        "sift-tester-20261009-001",
        tool="run_command",
        params={"command": ["mount", "-o", "ro,loop", image, str(mp)], "purpose": "p"},
        input_files=[image],
        input_sha256s=[""],
        input_detection_method="parsed",
        result_summary={"exit_code": 0},
        mount={"image": image, "points": [_point(mp, 2051, 7002)]},
    )
    csv = _evtx_csv_run(
        c,
        sec,
        aid="sift-tester-20261009-002",
        input_realpaths=[sec],
        input_st_devs=[2051],
    )
    c.op(
        "opensearch-ingest-7",
        "opensearch-ingest-7-20261009-030",
        tool="ingest_delimited",
        params={"run_id": "run-d", "file": csv},
        input_files=[csv],
        input_sha256s=[sha(csv)],
        input_detection_method="parsed",
    )
    aid = _search(
        c, [_doc("e1", "opensearch-ingest-7-20261009-030", **{"User": "bob"})]
    )
    res, st = c.find([{"content": "bob", "audit_id": aid}])
    assert g(res, st)[0] == "FULL" and st["source_evidence"] == image, g(res, st)
    methods = [l.get("method") for l in st["artifacts"][0]["provenance_chain"]]
    assert (
        "recorded-mount" in methods
        and "hash+place" in methods
        and DEV not in _chain(st)
    )


def _hayabusa_on_image(c):
    _dev01_first(c)
    image = c.file("evidence/rd01.E01", "e01 bytes")
    c.register(image)
    mp = c.d / "work-mnt"
    sec = c.file("work-mnt/Windows/System32/winevt/Logs/Security.evtx", "sec")
    sysl = c.file("work-mnt/Windows/System32/winevt/Logs/System.evtx", "sys")
    c.op(
        "opensearch-ingest-7",
        "opensearch-ingest-7-20261009-020",
        tool="mount",
        params={"run_id": "run-h"},
        input_files=[image],
        input_sha256s=[""],
        input_detection_method="parsed",
        mount={"image": image, "points": [_point(mp, 2050, 7003, offset=1048576)]},
    )
    c.op(
        "opensearch-ingest-7",
        "opensearch-ingest-7-20261009-031",
        tool="ingest_hayabusa",
        params={"run_id": "run-h"},
        input_files=[sec, sysl],
        input_sha256s=[sha(sec), sha(sysl)],
        input_detection_method="parsed",
        input_realpaths=[sec, sysl],
        input_st_devs=[2050, 2050],
    )
    return image


def test_a_detection_traces_through_hayabusa_to_the_image(c):
    """Via idx_list_detections and the documents its findings matched."""
    image = _hayabusa_on_image(c)
    aid = _search(
        c,
        [
            _doc(
                "h1",
                "opensearch-ingest-7-20261009-031",
                **{"RuleTitle": "Mimikatz Use"},
            )
        ],
        tool="idx_list_detections",
    )
    res, st = c.find([{"content": "Mimikatz Use", "audit_id": aid}])
    assert g(res, st)[0] == "FULL" and st["source_evidence"] == image, g(res, st)
    ch = _chain(st)
    assert (
        "opensearch-ingest-7-20261009-031" in ch
        and "recorded-mount" in ch
        and DEV not in ch
    )


def test_the_same_detection_via_a_search_traces_to_the_image(c):
    image = _hayabusa_on_image(c)
    aid = _search(
        c,
        [
            _doc(
                "h1",
                "opensearch-ingest-7-20261009-031",
                **{"RuleTitle": "Mimikatz Use"},
            )
        ],
    )
    res, st = c.find([{"content": "Mimikatz Use", "audit_id": aid}])
    assert g(res, st)[0] == "FULL" and st["source_evidence"] == image, g(res, st)
    assert "recorded-mount" in _chain(st)


def test_a_wintools_csv_traces_through_its_sift_path(c):
    """wintools RECmd on a registered hive → CSV (its SIFT path) → ingest → search."""
    _dev01_first(c)
    hive = c.file("evidence/rd01/NTUSER.DAT", "hive bytes")
    c.register(hive)
    csv = c.file(
        "extractions/wt-tester-20261009-001/RECmd.csv", "Key,Value\nRun,evil.exe\n"
    )
    c.op(
        "wintools-mcp",
        "wt-tester-20261009-001",
        tool="run_windows_command",
        params={
            "command": ["RECmd.exe", "-f", r"\\sift\case\evidence\rd01\NTUSER.DAT"]
        },
        result_summary={"exit_code": 0},
        inputs=[
            {
                "path": r"\\sift\case\evidence\rd01\NTUSER.DAT",
                "sift_path": "evidence/rd01/NTUSER.DAT",
            }
        ],
        outputs=[
            {
                "path": r"\\sift\case\extractions\wt-tester-20261009-001\RECmd.csv",
                "sift_path": "extractions/wt-tester-20261009-001/RECmd.csv",
                "sha256": sha(csv),
            }
        ],
    )
    c.op(
        "opensearch-ingest-7",
        "opensearch-ingest-7-20261009-040",
        tool="ingest_delimited",
        params={"run_id": "run-w", "file": csv},
        input_files=[csv],
        input_sha256s=[sha(csv)],
        input_detection_method="parsed",
    )
    aid = _search(
        c, [_doc("w1", "opensearch-ingest-7-20261009-040", **{"Value": "evil.exe"})]
    )
    res, st = c.find([{"content": "evil.exe", "audit_id": aid}])
    assert g(res, st)[0] == "FULL" and st["source_evidence"] == hive, g(res, st)
    assert "wt-tester-20261009-001" in _chain(st) and DEV not in _chain(st)


def test_an_input_that_is_the_registered_folder_itself_traces_to_the_folder(c):
    """A run on a registered folder root's own path → root = the folder, FULL."""
    f1 = c.file(
        "evidence/kape/C/Windows/System32/winevt/Logs/System.evtx", "kape system evtx"
    )
    folder = str(c.d / "evidence/kape")
    c.register(
        folder,
        kind="folder",
        manifest=[
            {"relpath": "C/Windows/System32/winevt/Logs/System.evtx", "sha256": sha(f1)}
        ],
    )
    c.op(
        "sift-mcp",
        "sift-tester-20261009-001",
        tool="run_command",
        params={"command": ["EvtxECmd", "-d", folder], "purpose": "p"},
        input_files=[folder],
        input_sha256s=[""],
        input_detection_method="catalog",
        result_summary={
            "exit_code": 0,
            "output_file": c.file("extractions/k.txt", "7045 svc installed\n"),
            "output_sha256": sha(c.d / "extractions/k.txt"),
        },
    )
    res, st = c.find(
        [{"content": "7045 svc installed", "audit_id": "sift-tester-20261009-001"}]
    )
    assert g(res, st)[0] == "FULL", g(res, st)
    root = st["artifacts"][0].get("provenance_root", {})
    assert root.get("path") == folder, root
    assert st["artifacts"][0]["provenance_chain"][0].get("method") == "registered-path"


def test_a_directly_registered_memory_image_ingested_traces_to_it(c):
    """A registered raw image → idx_ingest_memory (vol3 per plugin) → search."""
    _dev01_first(c)
    mem = c.file("evidence/rd01-memory.raw", "raw memory")
    c.register(mem)
    c.op(
        "opensearch-ingest-7",
        "opensearch-ingest-7-20261009-050",
        tool="ingest_vol3_pslist",
        params={"run_id": "run-r", "image": mem},
        input_files=[mem],
        input_sha256s=[""],
        input_detection_method="parsed",
    )
    aid = _search(
        c,
        [
            _doc(
                "m1", "opensearch-ingest-7-20261009-050", **{"process.name": "evil.exe"}
            )
        ],
    )
    res, st = c.find([{"content": "evil.exe", "audit_id": aid}])
    assert g(res, st)[0] == "FULL" and st["source_evidence"] == mem, g(res, st)
    links = st["artifacts"][0]["provenance_chain"]
    assert (
        links and links[0].get("method") == "registered-path" and DEV not in _chain(st)
    )


def test_an_acquired_root_is_labelled_with_its_acquisition(c):
    """winpmem output registered as a root (`acquired_by`)."""
    mem = c.file("evidence/acquired/mem.raw", "acquired memory")
    c.op(
        "wintools-mcp",
        "wt-tester-20261009-005",
        tool="run_windows_command",
        params={"command": ["winpmem.exe", "mem.raw"]},
        result_summary={
            "exit_code": 0,
            "output_files": [mem],
            "output_sha256s": [sha(mem)],
        },
    )
    c.register(mem, acquired_by="wt-tester-20261009-005")
    c.run(
        "sift-tester-20261009-001",
        ["vol", "-f", mem, "windows.pslist"],
        [mem],
        "PID 4 System\n",
    )
    res, st = c.find(
        [{"content": "PID 4 System", "audit_id": "sift-tester-20261009-001"}]
    )
    assert g(res, st)[0] == "FULL" and st["source_evidence"] == mem, g(res, st)
    label = st["artifacts"][0].get("provenance_root", {}).get("label", "")
    assert label == "acquired by wt-tester-20261009-005", label


def test_a_read_after_the_recorded_unmount_breaks(c):
    """The point's life comes from realpath + mnt_id pairing with its umount entry."""
    a, _ = two_images(c)
    mp = c.d / "mnt"
    sec = c.file("mnt/Windows/System32/winevt/Logs/Security.evtx", "evtx inside A")
    _mount(c, a, str(mp), 2049, "sift-tester-20261009-001")
    _umount(c, "sift-tester-20261009-002", mp, 7001)
    c.run(
        "sift-tester-20261009-003",
        ["EvtxECmd", "-f", sec],
        [sec],
        "4624 alice\n",
        input_realpaths=[sec],
        input_st_devs=[2049],
    )
    res, st = c.find(
        [
            {
                "content": "4624 alice",
                "audit_id": "sift-tester-20261009-003",
                "source": sec,
            }
        ]
    )
    assert g(res, st)[:2] == ("BROKEN", "mount-mismatch"), g(res, st)


def test_an_input_carrying_another_mount_id_breaks(c):
    """The mount id is required only where the input carries one; here it does, and it differs."""
    a, _ = two_images(c)
    mp = c.d / "mnt"
    sec = c.file("mnt/Windows/System32/winevt/Logs/Security.evtx", "evtx inside A")
    _mount(c, a, str(mp), 2049, "sift-tester-20261009-001")
    c.run(
        "sift-tester-20261009-002",
        ["EvtxECmd", "-f", sec],
        [sec],
        "4624 alice\n",
        input_realpaths=[sec],
        input_st_devs=[2049],
        input_mnt_ids=[7999],
    )
    res, st = c.find(
        [
            {
                "content": "4624 alice",
                "audit_id": "sift-tester-20261009-002",
                "source": sec,
            }
        ]
    )
    assert g(res, st)[:2] == ("BROKEN", "mount-mismatch"), g(res, st)


# --- roots, producers and hashes, as recorded ------------------------------------


def test_an_op_whose_inputs_reach_two_roots_is_full_listing_both(c):
    """Sample 2 from the 7z and a separately registered image, compared."""
    z = _seven_zip(c)
    _s1, s2 = _extract(c, "sift-tester-20261009-001", z)
    other = c.file("evidence/rd01-memory.raw", "raw memory")
    c.register(other)
    c.run(
        "sift-tester-20261009-002", ["cmp", s2, other], [s2, other], "differ: byte 1\n"
    )
    res, st = c.find(
        [{"content": "differ: byte 1", "audit_id": "sift-tester-20261009-002"}]
    )
    assert g(res, st)[0] == "FULL", g(res, st)
    roots = {r["path"] for r in st["artifacts"][0].get("provenance_roots", [])}
    assert roots == {z, other}, roots


def test_a_producer_recorded_after_its_consumer_doesnt_link(c):
    z = _seven_zip(c)
    s2 = c.file("extractions/late/sample2.raw", "sample two")
    c.run(
        "sift-tester-20261009-002",
        ["vol", "-f", s2, "windows.pslist"],
        [s2],
        "PID 4 System\n",
    )
    c.op("sift-mcp", "sift-tester-20261009-003", ts="2026-10-09T05:00:00Z",
         tool="run_command",
         params={"command": ["7z", "x", z, "-oextractions/late"], "purpose": "p"},
         input_files=[z], input_sha256s=[""], input_detection_method="parsed",
         result_summary={"exit_code": 0, "output_files": [s2],
                         "output_sha256s": [sha(s2)]})  # fmt: skip
    res, st = c.find(
        [{"content": "PID 4 System", "audit_id": "sift-tester-20261009-002"}]
    )
    assert g(res, st)[:2] == ("BROKEN", "no-recorded-origin"), g(res, st)


def test_a_recorded_hash_differing_from_the_registered_one_is_a_hash_mismatch(c):
    z = _seven_zip(c)
    out = c.file("extractions/l.txt", "sample2.raw\n")
    c.op("sift-mcp", "sift-tester-20261009-001", tool="run_command",
         params={"command": ["7z", "l", z], "purpose": "p"},
         input_files=[z], input_sha256s=["ab" * 32], input_detection_method="parsed",
         result_summary={"exit_code": 0, "output_file": out,
                         "output_sha256": sha(out)})  # fmt: skip
    res, st = c.find(
        [{"content": "sample2.raw", "audit_id": "sift-tester-20261009-001"}]
    )
    assert g(res, st)[:2] == ("BROKEN", "hash-mismatch"), g(res, st)


# --- a summary's counts, the decoded response, size caps, placeholders -----------


def _summary(c, aid, body, **counts):
    """A summary query (idx_count) as opensearch-mcp records it: result_ingests, and the
    counts of records with no ingest or past the cap, with its saved response."""
    resp = c.file(f"extractions/{aid}/response.json", json.dumps(body))
    c.op("opensearch-mcp", aid, tool="idx_count",
         params={"query": "4624", "result_ingests": ["opensearch-ingest-7-20261009-012"],
                 **counts},
         result_summary="counted", response={"path": resp, "sha256": sha(resp)})  # fmt: skip
    return aid


@pytest.mark.parametrize(
    "counts, kind, said",
    [
        ({"result_ingests_missing": 100}, "ingests-unrecorded",
         "100 documents with no recorded ingest"),
        ({"result_ingests_overflow": 7, "result_ingests_cap": 1000},
         "ingests-unrecorded", "ingests not fully listed (7)"),
    ],
    ids=["records with no ingest", "ingests past the cap"],
)  # fmt: skip
def test_a_summary_with_records_it_cant_trace_is_never_full(c, counts, kind, said):
    _ingested_samples(c)
    aid = _summary(c, "opensearch-tester-20261009-070", {"count": 120}, **counts)
    res, st = c.find([{"content": "120", "audit_id": aid}])
    assert g(res, st)[:2] == ("BROKEN", kind), g(res, st)
    assert said in st["artifacts"][0]["provenance_reason"]


@pytest.mark.parametrize(
    "value",
    [r"C:\Windows\System32\evil.exe", 'cmd /c "whoami /all"'],
    ids=["a Windows path", "a quote mark in a value"],
)
def test_a_quote_is_matched_against_the_decoded_response(c, value):
    """JSON escapes backslashes and quote marks: the quote is checked against
    the values as returned, never the escaped text."""
    _ingested_samples(c)
    doc = _doc("d2", "opensearch-ingest-7-20261009-012", **{"process.cmd": value})
    aid = _search(c, [doc])
    res, st = c.find([{"content": value, "audit_id": aid}])
    assert g(res, st)[0] == "FULL", g(res, st)


def test_a_summarys_quote_is_matched_against_its_decoded_response(c):
    _ingested_samples(c)
    aid = _summary(c, "opensearch-tester-20261009-071",
                   {"top": [{"key": r"C:\Windows\evil.exe", "count": 3}]})  # fmt: skip
    res, st = c.find([{"content": r"C:\Windows\evil.exe", "audit_id": aid}])
    assert g(res, st)[0] == "FULL", g(res, st)


def test_a_reference_responses_quote_is_matched_decoded(c):
    resp = c.file("extractions/opencti-2.json",
                  json.dumps({"ioc": r"C:\Users\Public\evil.exe", "labels": ["c2"]}))  # fmt: skip
    c.op("opencti-mcp", "opencti-tester-20261009-002", tool="lookup_ioc",
         params={"ioc": "evil.exe"}, result_summary="found",
         reference={"source": "opencti", "source_version": "6.4",
                    "response": {"path": resp, "sha256": sha(resp)}})  # fmt: skip
    res, st = c.find([{"content": r"C:\Users\Public\evil.exe",
                       "audit_id": "opencti-tester-20261009-002"}])  # fmt: skip
    assert g(res, st)[:2] == ("BROKEN", "reference"), g(res, st)


BACKEND_ID, GATEWAY_ID = (
    "opencti-tester-20261010-001",
    "sift-gateway-tester-20261010-001",
)


def _lookup(c, gateways=1, own=True, indent=None):
    """A lookup as the gateway records it: the backend's own entry (its id is
    the one its reply gives the client), and the gateway's reference entry for
    the call, under its own id, naming the backend's. The saved reply."""
    resp = c.file("extractions/opencti-4.json", json.dumps(
        {"ioc": "203.0.113.10", "found": True, "labels": ["c2"],
         "providers": {"opencti": {"outcome": "MATCH"}}, "audit_id": BACKEND_ID},
        indent=indent))  # fmt: skip
    if own:  # a backend with no case to write in writes no entry of its own
        c.op("opencti-mcp", BACKEND_ID, tool="lookup_ioc", params={"ioc": "203.0.113.10"},
             result_summary={"found": True})  # fmt: skip
    for n in range(gateways):
        c.op("sift-gateway", GATEWAY_ID[:-1] + str(n + 1), tool="lookup_ioc",
             params={"ioc": "203.0.113.10"}, result_summary="reference response saved",
             backend="opencti-mcp", backend_audit_id=BACKEND_ID,
             reference={"source": "opencti-mcp", "source_version": "1.30.0",
                        "response": {"path": resp, "sha256": sha(resp)}})  # fmt: skip
    return Path(resp).read_text()


@pytest.mark.parametrize("cited", [BACKEND_ID, GATEWAY_ID])
@pytest.mark.parametrize("quote", ["MATCH", '"outcome": "MATCH"', '"found": true',
                                   '"ioc":  "203.0.113.10"'])  # fmt: skip
def test_a_lookups_quote_is_reference_data_by_either_id(c, cited, quote):
    """Cited by the id its reply gave, or by the gateway's: a value, or a
    `"field": value` line as the reply shows it, is reference data."""
    _lookup(c)
    res, st = c.find([{"content": quote, "audit_id": cited}])
    assert g(res, st)[:2] == ("BROKEN", "reference"), g(res, st)
    assert st["artifacts"][0]["provenance_chain"][-1]["audit_id"] == GATEWAY_ID


@pytest.mark.parametrize("cited", [BACKEND_ID, GATEWAY_ID])
@pytest.mark.parametrize("field", ['"ioc"', '"found"', '"outcome"'])
def test_a_line_copied_from_the_indented_reply_is_reference_data(c, cited, field):
    """The sources reply with indent=2: a line copied as it is, its comma too
    when it isn't the last in its object."""
    text = _lookup(c, indent=2)
    (line,) = [x for x in text.splitlines() if x.strip().startswith(field)]
    res, st = c.find([{"content": line, "audit_id": cited}])
    assert g(res, st)[:2] == ("BROKEN", "reference"), (line, g(res, st))


@pytest.mark.parametrize("quote", ['"found": true,,', '"found",', '"MATCH",',
                                   '"found": "true",'])  # fmt: skip
def test_only_one_comma_after_a_whole_pair_is_taken(c, quote):
    _lookup(c, indent=2)
    res, st = c.find([{"content": quote, "audit_id": BACKEND_ID}])
    assert g(res, st)[:2] == ("CITED-UNVERIFIED", "cited-unverified"), g(res, st)


@pytest.mark.parametrize("cited", [BACKEND_ID, GATEWAY_ID])
@pytest.mark.parametrize("quote", ["NO_MATCH", '"outcome": "NO_MATCH"', "outcome",
                                   '"labels": "c2"', '"opencti": "MATCH"',
                                   '"found": "true"'])  # fmt: skip
def test_a_quote_the_lookup_didnt_return_is_unverified(c, cited, quote):
    _lookup(c)
    res, st = c.find([{"content": quote, "audit_id": cited}])
    assert g(res, st)[:2] == ("CITED-UNVERIFIED", "cited-unverified"), g(res, st)


def test_a_backend_id_with_no_entry_of_its_own_reaches_the_lookup(c):
    """The resolver follows it; record_finding still refuses an id with no
    entry in the trail, before any grading, as it did."""
    _lookup(c, own=False)
    t = pv.trace_artifact(pv.load_case(c.d), BACKEND_ID, '"outcome": "MATCH"')
    assert (t.grade, t.break_["kind"]) == ("BROKEN", "reference"), t
    res, st = c.find([{"content": '"outcome": "MATCH"', "audit_id": BACKEND_ID}])
    assert g(res, st)[:2] == ("NOT-STAGED", "REJECTED"), g(res, st)


def test_a_backend_id_on_two_gateway_entries_is_never_followed(c):
    """Two reference entries name the same backend id: neither is picked; the
    backend's own entry is checked, as before."""
    _lookup(c, gateways=2)
    res, st = c.find([{"content": "MATCH", "audit_id": BACKEND_ID}])
    assert g(res, st)[:2] == ("CITED-UNVERIFIED", "cited-unverified"), g(res, st)


def _run_with_big_output(c, size):
    """A run whose stdout says one thing and whose recorded output file (a raw
    image, sparse) is `size` bytes."""
    ev = c.file("evidence/Security.evtx", "evtx")
    c.register(ev)
    big = c.d / "extractions" / "sift-tester-20261009-001" / "image.raw"
    big.parent.mkdir(parents=True, exist_ok=True)
    with open(big, "wb") as f:
        f.truncate(size)
    h = hashlib.sha256()
    with open(big, "rb") as f:  # the recorded hash of the zeros, streamed
        for chunk in iter(lambda: f.read(1 << 24), b""):
            h.update(chunk)
    out = c.file("extractions/sift-tester-20261009-001/stdout.txt", "4 GiB copied\n")
    c.op("sift-mcp", "sift-tester-20261009-001", tool="run_command",
         params={"command": ["dd", f"if={ev}", f"of={big}"], "purpose": "p"},
         input_files=[ev], input_sha256s=[""], input_detection_method="parsed",
         result_summary={"exit_code": 0, "output_file": out, "output_sha256": sha(out),
                         "output_files": [str(big)],
                         "output_sha256s": [h.hexdigest()]})  # fmt: skip
    return big


def test_a_quote_in_stdout_never_reads_a_multi_gb_output(c):
    """Bounded memory and time: the quote is found in stdout first, and a
    recorded output past the size cap is never read."""
    import time
    import tracemalloc

    _run_with_big_output(c, 4 << 30)
    tracemalloc.start()
    t0 = time.monotonic()
    res, st = c.find(
        [{"content": "4 GiB copied", "audit_id": "sift-tester-20261009-001"}]
    )
    elapsed = time.monotonic() - t0
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert g(res, st)[0] == "FULL", g(res, st)
    assert elapsed < 5 and peak < 64 << 20, (elapsed, peak)


def test_a_quote_only_in_an_output_past_the_cap_is_unverified_saying_why(
    c, monkeypatch
):
    monkeypatch.setattr(pv, "_QUOTE_FILE_CAP", 64, raising=False)
    ev = c.file("evidence/Security.evtx", "evtx")
    c.register(ev)
    _evtx_csv_run(c, ev, csv_text="EventId,User\n" + "4624,bob\n" * 20)
    res, st = c.find([{"content": "4624,bob", "audit_id": "sift-tester-20261009-001"}])
    assert g(res, st)[0] == "CITED-UNVERIFIED", g(res, st)
    assert "output too large to check" in st["artifacts"][0]["provenance_reason"]


@pytest.mark.parametrize("content", ["...", "   ", "…\n...", "-- -- --", ""])
def test_an_artifact_with_nothing_quotable_is_rejected_asking_for_the_output(
    c, content
):
    z = _seven_zip(c)
    s1, s2 = _extract(c, "sift-tester-20261009-001", z)
    c.run("sift-tester-20261009-002", ["vol", "-f", s2, "windows.pslist"], [s2],
          "PID 4 System\n")  # fmt: skip
    res, st = c.find([{"content": content, "audit_id": "sift-tester-20261009-002"}])
    assert st is None and res["status"] == "REJECTED", res
    assert "paste the actual output" in res["error"].lower(), res


@pytest.mark.parametrize("op", ["run", "query"])
def test_the_library_never_crashes_on_a_placeholder_quote(c, op):
    """Called directly (an ingest check, a re-grade): no quotable line is
    CITED-UNVERIFIED, for a run and for a query."""
    _ingested_samples(c)
    if op == "run":
        z = c.file("evidence/other.7z", "other")
        c.register(z)
        c.run("sift-tester-20261009-002", ["7z", "l", z], [z], "PID 4 System\n")
        aid = "sift-tester-20261009-002"
    else:
        aid = _search(c, [_doc("d2", "opensearch-ingest-7-20261009-012",
                               **{"process.name": "evil.exe"})])  # fmt: skip
    t = pv.trace_artifact(pv.load_case(c.d), aid, "...")
    assert t.grade == "CITED-UNVERIFIED", t.as_dict()


# --- an enrichment step is the one its record names, for the group matched -----


def _enriched_search(c, records):
    """records: [(doc, {"triage": op} / {"threat_intel": [ops]})]: each returned
    record with the enrichment steps its own result_docs entry names."""
    aid = "opensearch-tester-20261009-080"
    resp = c.file(f"extractions/{aid}/response.json",
                  json.dumps({"results": [d for d, _g in records]}))  # fmt: skip
    c.op("opensearch-mcp", aid, tool="idx_search",
         params={"query": "x", "result_ingests": ["opensearch-ingest-7-20261009-012"],
                 "result_docs": [{"_index": d["_index"], "_id": d["_id"],
                                  "ingest_audit_id": d["vhir.ingest_audit_id"],
                                  "content_hash": "", "original_sha256": "",
                                  **({"enrichment": g} if g else {})}
                                 for d, g in records]},
         result_summary="2", response={"path": resp, "sha256": sha(resp)})  # fmt: skip
    return aid


def test_a_triage_quote_isnt_satisfied_by_a_threat_intel_step(c):
    _ingested_samples(c)
    _enrich(c, "opensearch-tester-20261009-051")  # a threat-intel step, recorded
    doc = _doc("d2", "opensearch-ingest-7-20261009-012",
               **{"triage.verdict": "SUSPICIOUS", "threat_intel.hits": 0})  # fmt: skip
    aid = _enriched_search(
        c, [(doc, {"threat_intel": ["opensearch-tester-20261009-051"]})]
    )
    res, st = c.find([{"content": "SUSPICIOUS", "audit_id": aid}])
    assert g(res, st)[:2] == ("BROKEN", "reference-not-recorded"), g(res, st)


def test_one_records_step_never_covers_anothers_missing_one(c):
    _ingested_samples(c)
    _enrich(c)  # opensearch-tester-20261009-050
    a = _doc(
        "d1", "opensearch-ingest-7-20261009-012", **{"triage.verdict": "SUSPICIOUS"}
    )
    b = _doc(
        "d2", "opensearch-ingest-7-20261009-012", **{"triage.verdict": "MALICIOUS"}
    )
    aid = _enriched_search(c, [(a, {"triage": "opensearch-tester-20261009-050"}),
                               (b, None)])  # fmt: skip
    res, st = c.find([{"content": "SUSPICIOUS\nMALICIOUS", "audit_id": aid}])
    assert g(res, st)[:2] == ("BROKEN", "reference-not-recorded"), g(res, st)
    assert "d2" in st["artifacts"][0]["provenance_reason"]


def test_an_enrichment_step_whose_id_is_on_two_entries_is_ambiguous(c):
    _ingested_samples(c)
    _enrich(c)
    c.op("sift-mcp", "opensearch-tester-20261009-050", tool="run_command")  # same id
    docs, groups = _triaged("opensearch-tester-20261009-050")
    aid = _search(c, docs, groups=groups)
    res, st = c.find([{"content": "SUSPICIOUS", "audit_id": aid}])
    assert g(res, st)[0] == "AMBIGUOUS", g(res, st)


def test_a_quote_from_an_output_recorded_pending_is_checked_through_its_job(c):
    """The tool's CSV was hashed in the background: its recorded hash is
    pending:<job> until the job closes, and the check takes the job's hash."""
    ev = c.file("evidence/Security.evtx", "evtx")
    c.register(ev)
    csv = _evtx_csv_run(c, ev)
    lines = (c.d / "audit" / "sift-mcp.jsonl").read_text().splitlines()
    entry = json.loads(lines[-1])
    entry["result_summary"]["output_sha256s"] = ["pending:hash-csv"]
    (c.d / "audit" / "sift-mcp.jsonl").write_text(
        "\n".join(lines[:-1] + [json.dumps(entry)]) + "\n"
    )
    c.op("file-identity", "fileidentity-tester-20261009-001", tool="hash_complete",
         job_id="hash-csv", path=csv, sha256=sha(csv))  # fmt: skip
    res, st = c.find([{"content": "4624,bob", "audit_id": "sift-tester-20261009-001"}])
    assert g(res, st)[0] == "FULL", g(res, st)


@pytest.mark.parametrize(
    "value, quoted", [(True, "true"), (None, "null"), (False, "false")]
)
def test_a_json_literal_is_quoted_as_json_spells_it(c, value, quoted):
    resp = c.file(
        "extractions/opencti-3.json", json.dumps({"ioc": "x", "malicious": value})
    )
    c.op("opencti-mcp", "opencti-tester-20261009-003", tool="lookup_ioc",
         params={"ioc": "x"}, result_summary="found",
         reference={"source": "opencti", "source_version": "6.4",
                    "response": {"path": resp, "sha256": sha(resp)}})  # fmt: skip
    res, st = c.find([{"content": f"malicious {quoted}",
                       "audit_id": "opencti-tester-20261009-003"}])  # fmt: skip
    assert g(res, st)[:2] == ("CITED-UNVERIFIED", "cited-unverified"), g(res, st)
    res, st = c.find([{"content": quoted, "audit_id": "opencti-tester-20261009-003"}])
    assert g(res, st)[:2] == ("BROKEN", "reference"), g(res, st)


def test_a_duplicate_enrichment_step_never_hides_a_worse_evidence_grade(c):
    """The record's ingest isn't recorded (BROKEN) and its step's id is on two
    entries (AMBIGUOUS): the worse grade stands, with its links."""
    _ingested_samples(c)
    _enrich(c)
    c.op("sift-mcp", "opensearch-tester-20261009-050", tool="run_command")  # same id
    doc = _doc("d2", "opensearch-ingest-7-20261009-099",  # an ingest never recorded
               **{"process.name": "evil.exe", "triage.verdict": "SUSPICIOUS"})  # fmt: skip
    aid = _search(c, [doc], groups={"triage": "opensearch-tester-20261009-050"})
    res, st = c.find([{"content": "SUSPICIOUS", "audit_id": aid}])
    assert g(res, st)[0] == "BROKEN", g(res, st)
    assert st["artifacts"][0]["provenance_chain"], st["artifacts"][0]


def test_a_response_over_the_cap_says_its_too_large(c, monkeypatch):
    monkeypatch.setattr(pv, "_QUOTE_FILE_CAP", 16)
    _ingested_samples(c)
    aid = _summary(c, "opensearch-tester-20261009-072", {"count": 120, "pad": "x" * 64})
    res, st = c.find([{"content": "120", "audit_id": aid}])
    assert g(res, st)[0] == "CITED-UNVERIFIED", g(res, st)
    assert "too large to check" in st["artifacts"][0]["provenance_reason"]
