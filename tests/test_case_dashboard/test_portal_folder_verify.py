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
        {"kind": "folder", "status": "verified", "files": 2},
        {"kind": "folder", "status": "failed", "files": 2, "not_ok": [{}]},
        {"kind": "folder", "status": "pending", "files": 2},
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
        shown[result["status"]] = out.stdout
    assert ">Verified (2 files)<" in shown["verified"]
    assert ">FAILED (2 files, 1 not OK)<" in shown["failed"]
    assert "Hashing (2 files); verify again shortly" in shown["pending"]
    assert "Error" not in "".join(shown.values())
