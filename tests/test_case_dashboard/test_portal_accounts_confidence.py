"""The Accounts tab's Highest Confidence names the account's highest
finding confidence, HIGH included."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = (
    Path(__import__("case_dashboard").__file__).parent / "static" / "v2" / "index.html"
)


def _badges(findings):
    """Run the page's renderAccounts on findings: {account: badge class}."""
    node = shutil.which("node") or pytest.skip("node isn't installed")
    page = PAGE.read_text()
    start = page.index("function renderAccounts() {")
    fn = page[start : page.index("\n}\n", start) + 3]
    script = (
        f"var findings = {json.dumps(findings)};"
        " function escapeHtml(s) { return String(s); }"
        " function escapeJsString(s) { return String(s); } function formatTimeShort(s) { return s; }"
        " function setBadge() {} var out = '';"
        " var document = {getElementById: function() { return {set innerHTML(v) { out += v; }}; }};\n"
        + fn
        + "\nrenderAccounts();"
        " var rows = {}; out.split('</tr>').forEach(function(r) {"
        ' var m = r.match(/<strong>([^<]*)<\\/strong>[\\s\\S]*class="badge (conf-[a-z]+)"/);'
        " if (m) rows[m[1]] = m[2]; });"
        " process.stdout.write(JSON.stringify(rows));"
    )
    out = subprocess.run(
        [node, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr[-800:]
    return json.loads(out.stdout)


def test_highest_confidence_shows_high():
    findings = [
        {"id": "F-1", "affected_account": "alice", "confidence": "HIGH"},
        {"id": "F-2", "affected_account": "bob", "confidence": "MEDIUM"},
        {"id": "F-3", "affected_account": "bob", "confidence": "HIGH"},
        {"id": "F-4", "affected_account": "carol", "confidence": "LOW"},
        {"id": "F-5", "affected_account": "carol", "confidence": "MEDIUM"},
    ]
    assert _badges(findings) == {
        "alice": "conf-high",
        "bob": "conf-high",
        "carol": "conf-medium",
    }
