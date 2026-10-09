"""The Overview's Hosts tile counts the case's machines, as the Hosts tab
does (host identity), not the distinct host texts its findings carry."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from sift_common import host_identity as hi

PAGE = (
    Path(__import__("case_dashboard").__file__).parent / "static" / "v2" / "index.html"
)
SPELLINGS = ["SRV01", "srv01.corp.local", "SRV01.CORP.LOCAL"]


@pytest.fixture
def one_machine(portal):
    findings = [
        {"id": f"F-steve-00{i}", "title": "t", "status": "DRAFT", "host": h}
        for i, h in enumerate(SPELLINGS, 1)
    ]
    portal.write("findings.json", findings)
    portal.write("timeline.json", [])
    hi.ensure_host_files(portal.dir)
    u = hi.unit_key("evidence/SRV01")
    hi.append_observations(portal.dir, [
        {"kind": "unit", "unit": u, "locator": "evidence/SRV01"},
        {"kind": "name", "unit": u, "raw": "SRV01", "evidence": "folder name", "origin": "folder"},
        {"kind": "name", "unit": u, "raw": "SRV01", "evidence": "SYSTEM", "origin": "artifact"},
    ])  # fmt: skip
    page = portal.get("/api/hosts").json()
    (group,) = page["proposed"]
    r = portal.post("/api/hosts/decisions", {
        "action": "confirm", "seen_offset": page["obs_offset"],
        "args": {"groups": [{**group, "canonical": "SRV01"}]}})  # fmt: skip
    assert r.status_code == 200, r.text
    assert portal.get("/api/hosts").json()["total"] == 1
    return findings


def test_the_summary_counts_the_case_s_machines(portal, one_machine):
    assert portal.get("/api/summary").json()["hosts"] == {"machines": 1}


def test_a_case_with_no_host_files_has_no_machines(portal):
    portal.write("findings.json", [{"id": "F-1", "status": "DRAFT", "host": "X"}])
    portal.write("timeline.json", [])
    assert portal.get("/api/summary").json()["hosts"] == {"machines": 0}


def test_the_hosts_tile_shows_machines_not_host_texts(portal, one_machine):
    node = shutil.which("node") or pytest.skip("node isn't installed")
    summary = portal.get("/api/summary").json()
    page = PAGE.read_text()
    start = page.index("function renderDashboard(summary) {")
    fn = page[start : page.index("\n}\n", start) + 3]
    script = (
        f"var findings = {json.dumps(one_machine)}; var caseMeta = {{}}; var delta = {{items: []}};"
        " var timelineEvents = []; function escapeHtml(s) { return String(s); }"
        " function escapeJsString(s) { return String(s); } function formatTime(s) { return s; }"
        " function renderWithdrawnList() { return ''; } var out = '';"
        " var document = {getElementById: function() { return {set innerHTML(v) { out += v; }, style: {}}; }};\n"
        + fn
        + f"\nrenderDashboard({json.dumps(summary)});"
        " var m = out.match(/Hosts<\\/h3><div[^>]*>(\\d+)<\\/div><div[^>]*>([^<]*)/);"
        " process.stdout.write(JSON.stringify(m && [m[1], m[2]]));"
    )
    out = subprocess.run(
        [node, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr[-800:]
    assert json.loads(out.stdout) == ["1", "machines in the case"]
