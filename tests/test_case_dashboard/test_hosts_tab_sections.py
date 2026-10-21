"""The Hosts tab's three sections in the page, run under node: the Host list
with its upload result, Impacted hosts from the findings, and the one search
box that pages both server tables from the start. Names are synthetic."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = (
    Path(__import__("case_dashboard").__file__).parent / "static" / "v2" / "index.html"
).read_text()


def _fn(name):
    m = re.search(r"\n(async )?function " + name + r"\(", PAGE)
    return PAGE[m.start() + 1 : PAGE.index("\n}\n", m.start()) + 3]


def _listener(kind):
    start = PAGE.index(f"document.addEventListener('{kind}', ")
    return PAGE[start : PAGE.index("\n});\n", start) + 5]


def _run(body, hosts=None, findings=()):
    """Run `body` (async) against the page's Hosts code; it prints its result."""
    node = shutil.which("node") or pytest.skip("node isn't installed")
    fns = "".join(_fn(n) for n in (
        "safeStr", "escapeHtml", "escapeAttr", "hostsHeaderHtml", "hostListSubText", "hostListRowsHtml",
        "hostListPagerHtml", "hostRowsHtml", "hostPagerHtml", "hostDraftHtml", "renderHosts",
        "hostDecide", "impactedHosts", "impactedHostsHtml", "renderImpactedHosts",
        "formatTimeShort"))  # fmt: skip
    script = (
        "var listeners = {}, asked = [], server = {list: null}, calls = [];\n"
        f"var hostsPage = {json.dumps(hosts or {})};\n"
        f"var findings = {json.dumps(list(findings))};\n"
        "var filterHost = '';\n"
        "var file = {files: [], set value(v) { if (v === '' || v === null)"
        " this.files = []; else throw new Error('InvalidStateError'); }};\n"
        "var els = {hostsPanel: {contains: function() { return false; }},"
        " hostListText: {value: ''}, hostListPanel: {open: false}, hostListFile: file};\n"
        "var document = {activeElement: null,"
        " getElementById: function(id) { return els[id] || (els[id] = {}); },"
        " createElement: function() { return {set textContent(s) { this.innerHTML ="
        " String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }}; },"
        " addEventListener: function(t, f) { listeners[t] = f; }};\n"
        "var hostsView = {page: 1, ppage: 1, lpage: 1, state: '', q: '', data: null,"
        " runs: [], result: null, impacted: []};\n"
        "var HOST_DECISION_ACTS = ['list'];\n"
        "function hostOpUnfinished() { return false; }\n"
        "function hostRunsHtml() { return ''; } function hostProposedHtml() { return ''; }"
        " function hostPivotsHtml() { return ''; } function hostNamesHtml() { return ''; }"
        " function setBadge() {} function hostDecisionsFixed() {} function renderHostOps() {}"
        " function showToast() {}\n"
        "function setFilter(v) { calls.push('setFilter:' + v); }"
        " function switchTab(t) { calls.push('switchTab:' + t); }"
        " function renderSidebar() { calls.push('renderSidebar'); }"
        " function showEmptyOrFirst() { calls.push('showEmptyOrFirst'); }\n"
        "async function apiFetch(path, opts) { asked.push(path);"
        " if (path.indexOf('/api/hosts?') === 0) return Object.assign({machines: [],"
        " proposed: [], obs_offset: 0, listed: [], listed_total: 0}, hostsPage);"
        " if (path === '/api/hosts/runs') return {runs: []};"
        " if (server.list instanceof Error) throw server.list; return server.list; }\n"
        "function click(act, i) { return listeners.click({target: {closest: function() {"
        " return {getAttribute: function(a) { return a === 'data-host-act' ? act"
        " : a === 'data-i' ? String(i) : null; }}; }}, preventDefault: function() {}}); }\n"
        + fns
        + _listener("click")
        + _listener("input")
        + "\n(async function() {\n"
        + body
        + "\n})().catch(function(e) { process.stdout.write(JSON.stringify("
        "'THROW: ' + e.name + ': ' + e.message)); });"
    )
    out = subprocess.run(
        [node, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr[-800:]
    return json.loads(out.stdout)


LISTED = {
    "host_list": {"entries": 2, "sha256": "ab" * 32, "examiner": "ex1"},
    "listed": [
        {"name": "WKS01", "fqdn": "wks01.corp.example.test", "proposed": False,
         "machines": [{"canonical": "WKS01", "state": "confirmed"}]},
        {"name": "DC01", "fqdn": "", "proposed": False, "machines": []},
    ],
    "listed_total": 2, "listed_page": 1, "per_page": 50,
}  # fmt: skip


def test_the_host_list_shows_each_entry_and_what_evidence_holds_for_it():
    got = _run(
        "await renderHosts();"
        " process.stdout.write(JSON.stringify([els.hostsListTable.hidden,"
        " els.hostsListSub.textContent, els.hostsListBody.innerHTML,"
        " els.hostsListPager.innerHTML, els.hostsHeader.innerHTML]));",
        LISTED,
    )
    hidden, sub, body, pager, header = got
    assert hidden is False and pager == ""
    assert sub == "2 entries, sha256 abababababab, uploaded by ex1"
    assert body.count("<tr>") == 2
    assert "<strong>WKS01</strong>" in body and "(confirmed)" in body
    assert "no data yet" in body and "Listed, no data yet" not in header


def test_with_no_list_the_hint_shows_and_the_table_does_not():
    got = _run(
        "await renderHosts();"
        " process.stdout.write(JSON.stringify([els.hostsListTable.hidden,"
        " els.hostsListBody.innerHTML, els.hostsHeader.innerHTML, els.hostsBody.innerHTML]));",
        {"host_list": None, "host_list_hint": "Upload a host list"},
    )
    hidden, body, header, machines = got
    assert hidden is True and body == ""
    assert '<div class="notice">Upload a host list</div>' in header
    assert "Machines appear when evidence is ingested" in machines


def test_a_long_list_pages_and_a_search_starts_both_tables_on_page_one():
    page = {**LISTED, "listed_total": 120, "listed_page": 2}
    got = _run(
        "await renderHosts(); var pager = els.hostsListPager.innerHTML;"
        " hostsView.page = 2;"
        " listeners.input({target: {id: 'hostsQuery', value: 'wks', blur: function() {},"
        " focus: function() {}}});"
        " var after = [hostsView.q, hostsView.page, hostsView.lpage];"
        " await renderHosts();"
        " process.stdout.write(JSON.stringify([pager, after, asked[asked.length - 2],"
        " els.hostsBody.innerHTML]));",
        page,
    )
    pager, after, path, machines = got
    assert "Host list page 2 of 3 (120 entries)" in pager
    assert 'data-host-act="lpage" data-i="1"' in pager
    assert 'data-host-act="lpage" data-i="3"' in pager
    assert after == ["wks", 1, 1]
    assert "page=1&" in path and "listed_page=1&" in path and "q=wks" in path
    assert "No machine matches the filter" in machines


def test_the_pager_asks_for_the_list_page_it_names():
    got = _run(
        "hostsView.lpage = 1; await click('lpage', 3); await new Promise(setImmediate);"
        " process.stdout.write(JSON.stringify([hostsView.lpage, asked[0]]));",
        LISTED,
    )
    assert got[0] == 3 and "listed_page=3&" in got[1]


UPLOAD = (
    "await renderHosts(); hostsView.lpage = 3; els.hostListText.value = 'TYPED\\n';"
    " await click('list'); await new Promise(setImmediate);"
    " var first = [els.hostListResult.innerHTML, els.hostListText.value, file.files.length,"
    " hostsView.lpage];"
    " await renderHosts();"
    " process.stdout.write(JSON.stringify([first, els.hostListResult.innerHTML]));"
)


def test_an_upload_s_result_stays_and_the_box_is_cleared():
    body = (
        "file.files = [{name: 'h.csv', text: async function() { return 'WKS01\\n'; }}];"
        " server.list = {summary: '2 listed, 0 confirmed, 1 skipped',"
        " skipped: [{canonical: '10.0.0.1', reason: 'an IP address, not a host name'}]};"
        + UPLOAD
    )
    (result, text, files, lpage), redrawn = _run(body, LISTED)
    assert "var(--green)" in result
    assert (
        "2 listed, 0 confirmed, 1 skipped — skipped 10.0.0.1: an IP address" in result
    )
    assert text == "" and files == 0 and lpage == 1  # the new list from its start
    assert redrawn == result  # the refresh draws it again


def test_a_refused_upload_shows_why_and_keeps_the_text():
    body = (
        "server.list = new Error('the host list names no hosts, so the current list is"
        " kept: 2 skipped (an IP address, not a host name)');" + UPLOAD
    )
    (result, text, _files, lpage), redrawn = _run(body, LISTED)
    assert "var(--red)" in result
    assert "names no hosts, so the current list is kept: 2 skipped" in result
    assert text == "TYPED\n" and lpage == 3 and redrawn == result


FINDINGS = [
    {"id": "F-1", "host": "rd01", "affected_account": "alice", "status": "DRAFT",
     "confidence": "LOW", "event_timestamp": "2026-01-02T03:04:00Z"},
    {"id": "F-2", "host": "rd01", "affected_account": "bob", "status": "APPROVED",
     "confidence": "HIGH", "event_timestamp": "2026-01-01T00:00:00Z"},
    {"id": "F-3", "host": "RD01", "status": "DRAFT"},
    {"id": "F-4", "host": ""},
    {"id": "F-5"},
]  # fmt: skip


def test_impacted_hosts_group_findings_by_their_exact_host_text():
    got = _run(
        "renderImpactedHosts(); process.stdout.write(JSON.stringify([hostsView.impacted.map("
        "function(h) { return [h.host, h.findings, Array.from(h.accounts), h.bestConf,"
        " h.earliest, h.latest]; }), els.impactedHostsBody.innerHTML]));",
        findings=FINDINGS,
    )
    rows, html = got
    assert rows == [
        ["rd01", ["F-1", "F-2"], ["alice", "bob"], "HIGH",
         "2026-01-01T00:00:00Z", "2026-01-02T03:04:00Z"],
        ["RD01", ["F-3"], [], "SPECULATIVE", "", ""],
    ]  # fmt: skip
    assert html.count('data-host-act="impacted"') == 2
    assert "1 draft, 1 approved" in html


def test_no_finding_naming_a_host_has_its_own_empty_state():
    got = _run(
        "renderImpactedHosts(); process.stdout.write(JSON.stringify("
        "els.impactedHostsBody.innerHTML));",
        findings=[{"id": "F-1"}],
    )
    assert "No finding names a host yet" in got


def test_an_impacted_host_opens_its_findings():
    got = _run(
        "renderImpactedHosts(); await click('impacted', 1);"
        " process.stdout.write(JSON.stringify([filterHost, els.filterHost.value, calls]));",
        findings=FINDINGS,
    )
    assert got == [
        "RD01",
        "RD01",
        ["setFilter:all", "switchTab:findings", "renderSidebar", "showEmptyOrFirst"],
    ]


def test_the_page_draws_impacted_hosts_with_the_accounts_on_every_load():
    start = PAGE.index("async function loadAll()")
    load = PAGE[start : PAGE.index("\n}\n", start)]
    assert "renderImpactedHosts();\n    renderAccounts();" in load
