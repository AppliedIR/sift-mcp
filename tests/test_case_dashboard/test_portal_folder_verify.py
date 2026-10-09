"""The Evidence tab's Verify on a folder root: verified as `vhir evidence
verify` does, file by file against the manifest registered with it, never
"Error" because the root isn't a file."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import quote

import pytest
from vhir_cli.commands.evidence import register_evidence_data

PAGE = (
    Path(__import__("case_dashboard").__file__).parent / "static" / "v2" / "index.html"
)


@pytest.fixture
def kape(portal):
    folder = portal.dir / "evidence" / "kape"
    folder.mkdir(parents=True)
    (folder / "Security.evtx").write_bytes(b"ElfFile security " * 40)
    (folder / "System.evtx").write_bytes(b"ElfFile system " * 40)
    portal.write("findings.json", [])
    return register_evidence_data(portal.dir, str(folder), "steve")


def verify(portal, path):
    return portal.post("/api/evidence/" + quote(path) + "/verify", {})


def test_an_unchanged_folder_root_is_verified_file_by_file(portal, kape):
    r = verify(portal, kape["path"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["kind"], body["status"], body["files"]) == ("folder", "verified", 2)
    assert body["counts"] == {"OK": 2} and body["not_ok"] == []


def test_a_changed_file_in_a_folder_root_fails_and_is_named(portal, kape):
    with open(Path(kape["path"]) / "System.evtx", "ab") as f:
        f.write(b"tampered")
    body = verify(portal, kape["path"]).json()
    assert body["status"] == "failed"
    assert [(Path(r["path"]).name, r["status"]) for r in body["not_ok"]] == [
        ("System.evtx", "MODIFIED")
    ]


def test_a_changed_manifest_fails_the_folder_root(portal, kape):
    manifest = portal.dir / kape["manifest_path"]
    manifest.write_text(manifest.read_text().replace("Security", "Securitx"))
    body = verify(portal, kape["path"]).json()
    assert body["status"] == "failed"
    assert body["not_ok"][0]["status"] == "ERROR"
    assert "manifest" in body["not_ok"][0]["error"]


def test_a_file_root_is_verified_as_before(portal, kape):
    f = portal.dir / "evidence" / "mem.raw"
    f.write_bytes(b"memory " * 50)
    entry = register_evidence_data(portal.dir, str(f), "steve")
    assert verify(portal, entry["path"]).json()["status"] == "verified"


def test_the_page_shows_a_folder_s_result_with_its_count():
    node = shutil.which("node") or pytest.skip("node isn't installed")
    page = PAGE.read_text()

    def fn(name):
        start = page.index(f"function {name}(")
        if page[start - 6 : start] == "async ":
            start -= 6
        return page[start : page.index("\n}\n", start) + 3]

    shown = {}
    for result in (
        {"kind": "folder", "status": "verified", "files": 2, "counts": {"OK": 2}},
        {
            "kind": "folder",
            "status": "failed",
            "files": 2,
            "counts": {"MODIFIED": 1, "PENDING": 1},
        },
        {"kind": "folder", "status": "pending", "files": 2, "counts": {"PENDING": 2}},
        {
            "kind": "folder",
            "status": "verified",
            "files": 0,
            "counts": {},
            "note": "registered with no files",
        },
    ):
        script = (
            "var cell = {innerHTML: ''}; var evidenceData = [{path: '/e/kape'}];"
            "var document = {getElementById: function() { return cell; },"
            " createElement: function() { return {set textContent(s) { this.innerHTML = String(s); }}; }};"
            f"async function apiFetch() {{ return {json.dumps(result)}; }}\n"
            + fn("escapeHtml")
            + fn("verifyEvidence")
            + "\nverifyEvidence(0).then(function() { process.stdout.write(cell.innerHTML); });"
        )
        out = subprocess.run(
            [node, "-e", script], capture_output=True, text=True, timeout=60
        )
        assert out.returncode == 0, out.stderr[-500:]
        shown[result["status"] + str(result["files"])] = out.stdout
    assert ">Verified (2 files)<" in shown["verified2"]
    assert ">FAILED (2 files, 1 not OK, 1 still hashing)<" in shown["failed2"]
    assert (
        "Hashing (2 files, 2 still hashing); verify again shortly" in shown["pending2"]
    )
    assert ">Verified (0 files: registered with no files)<" in shown["verified0"]
    assert "Error" not in "".join(shown.values())


# --- Large members: hashed in the background, as case-mcp's verify does -------


def _wait(case_dir, job_id):
    import time

    log = case_dir / "audit" / "file-identity.jsonl"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if log.exists() and job_id in log.read_text():
            return
        time.sleep(0.05)
    raise AssertionError(f"{job_id} never closed")


@pytest.fixture
def large(portal, kape, monkeypatch):
    from sift_common import file_identity as fi

    monkeypatch.setattr(fi, "INLINE_LIMIT", 100)  # both members are "large"
    return fi


def test_a_large_member_is_pending_then_its_recorded_hash_is_taken(
    portal, kape, large, monkeypatch
):
    first = verify(portal, kape["path"]).json()
    assert first["status"] == "pending"
    (job,) = {r["job_id"] for r in first["not_ok"]}
    _wait(portal.dir, job)
    monkeypatch.setattr(
        large, "hash_file", None
    )  # taken from the job, never read again
    assert verify(portal, kape["path"]).json()["status"] == "verified"


def test_a_failed_member_is_reported_once_then_asked_for_again(
    portal, kape, large, monkeypatch
):
    real, failed = large.hash_file, []

    def flaky(path):
        if str(path).endswith("System.evtx") and not failed:
            failed.append(path)
            raise OSError(5, "Input/output error", str(path))
        return real(path)

    monkeypatch.setattr(large, "hash_file", flaky)
    first = verify(portal, kape["path"]).json()
    _wait(portal.dir, first["not_ok"][0]["job_id"])
    second = verify(portal, kape["path"]).json()  # the failure, taken: no new job
    assert second["status"] == "failed"
    assert [(Path(r["path"]).name, r["status"]) for r in second["not_ok"]] == [
        ("System.evtx", "ERROR")
    ]
    assert "Input/output error" in second["not_ok"][0]["error"]
    third = verify(portal, kape["path"]).json()  # asked again, never retried forever
    assert third["status"] == "pending"
    _wait(portal.dir, third["not_ok"][0]["job_id"])
    assert verify(portal, kape["path"]).json()["status"] == "verified"


def test_a_verify_reads_the_job_log_once_for_all_its_files(
    portal, kape, large, monkeypatch
):
    reads = []
    real = large._completed_rows

    def counted(case_dir):
        reads.append(case_dir)
        return real(case_dir)

    monkeypatch.setattr(large, "_completed_rows", counted)
    verify(portal, kape["path"])
    assert len(reads) == 1  # not once per file


def test_a_change_found_is_never_hidden_behind_files_still_hashing(
    portal, kape, large, monkeypatch
):
    """One member changed (hashed now), another still hashing: failed, with
    the change named and the pending count shown."""
    small = Path(kape["path"]) / "Security.evtx"
    with open(small, "ab") as f:
        f.write(b"tampered")
    monkeypatch.setattr(large, "INLINE_LIMIT", small.stat().st_size)  # only it, now
    body = verify(portal, kape["path"]).json()
    assert body["status"] == "failed"
    assert body["counts"] == {"MODIFIED": 1, "PENDING": 1}
    assert [(Path(r["path"]).name, r["status"]) for r in body["not_ok"]] == [
        ("Security.evtx", "MODIFIED"),
        ("System.evtx", "PENDING"),
    ]


def test_an_empty_folder_root_verifies_with_a_note(portal):
    empty = portal.dir / "evidence" / "empty"
    empty.mkdir(parents=True)
    portal.write("findings.json", [])
    entry = register_evidence_data(portal.dir, str(empty), "steve")
    body = verify(portal, entry["path"]).json()
    assert (body["status"], body["files"], body["note"]) == (
        "verified", 0, "registered with no files",
    )  # fmt: skip
