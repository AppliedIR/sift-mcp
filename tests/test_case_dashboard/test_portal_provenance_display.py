"""The portal shows a finding's provenance as the chain resolver stored it:
the grade with its reason, each root with who registered it, each step's
method and both ends with their hashes, root first. A finding recorded
before 0.6.4, and a query logged before it, read "recorded before 0.6.4";
an import names the case its chain lives in.

The page's own script runs under node with a stand-in `document`; each row
renders a finding's card and its chain panel."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from .conftest import finding

PAGE = (
    Path(__import__("case_dashboard").__file__).parent / "static" / "v2" / "index.html"
)
H7Z, HM2, HOUT, HDOC, HIMG, HCSV = (
    "a" * 64,
    "b" * 64,
    "f" * 64,
    "9" * 64,
    "c" * 64,
    "d" * 64,
)
EV, X = "/cases/c1/evidence", "/cases/c1/extractions"
ROOT = {"path": f"{EV}/samples.7z", "sha256": H7Z, "label": "AI-registered"}
IMG = {"path": f"{EV}/disk.E01", "sha256": HIMG, "label": "examiner-registered"}
PRE = "recorded before 0.6.4"
UNLOGGED = "no recorded origin: made outside recorded tools"
QUERY_064 = f"{PRE}: opensearch-steve-009 records no results to follow"


def link(method, aid, fp, fh, tp, th, **extra):
    return {"method": method, "audit_id": aid, "entry_sha256": "e" * 64,
            "from": {"path": fp, "sha256": fh}, "to": {"path": tp, "sha256": th}, **extra}  # fmt: skip


def art(grade, reason="", chain=(), root=ROOT, brk=None, label="pslist"):
    """An artifact as the resolver stores it: `source_evidence` is the root's
    path when a root was reached."""
    a = {"source": "s", "extraction": label, "content": "PID 4242", "audit_id": "x-1",
         "provenance_grade": grade, "provenance_reason": reason,
         "provenance_chain": list(chain), "provenance_root": root,
         "provenance_break": brk}  # fmt: skip
    if root:
        a["source_evidence"] = root["path"]
    return a


def chained(fid, grade, *arts):
    return finding(
        fid, provenance_schema=2, provenance_grade=grade, artifacts=list(arts)
    )


RUN = [link("registered-path", "sift-steve-001", ROOT["path"], H7Z, f"{X}/1/mem2.raw", HM2),
       link("hash+place", "sift-steve-002", f"{X}/1/mem2.raw", HM2, f"{X}/2/stdout.bin", HOUT)]  # fmt: skip
FINDINGS = [
    finding("F-steve-000", provenance="MCP", provenance_grade="FULL",
            source_evidence=ROOT["path"]),
    chained("F-steve-001", "FULL", art("FULL", chain=RUN)),
    chained("F-steve-002", "DECLARED", art(
        "DECLARED", "declared: Bash outputs logged by log_external_action", [
            RUN[0], link("declared", "claude-code-steve-002", f"{X}/1/mem2.raw", HM2,
                         "stdout", HOUT)])),
    chained("F-steve-003", "FULL", art("FULL", chain=[
        link("registered-path", "opensearch-steve-001", ROOT["path"], H7Z, "archive", H7Z),
        link("manifest", "opensearch-steve-002", ROOT["path"], H7Z, "mem2.raw", HM2),
        link("recorded-id", "opensearch-steve-003", "mem2.raw", HM2, "doc:vol/abc", HDOC)])),
    chained("F-steve-004", "BROKEN",
            art("BROKEN", UNLOGGED, root=None, brk={"kind": "no-recorded-origin"})),
    finding("F-steve-005", provenance_grade="IMPORTED",
            imported_from={"case_id": "case-A", "examiner": "alice",
                           "exported_at": "2026-10-08T09:00:00Z"},
            artifacts=[{**art("IMPORTED", chain=RUN), "provenance_reason": ""}]),
    chained("F-steve-006", "FULL", art("FULL", root=IMG, chain=[
        link("registered-path", "sift-steve-010", IMG["path"], HIMG, "/mnt/case/disk", ""),
        link("recorded-mount", "sift-steve-011", "/mnt/case/disk/Security.evtx", "8" * 64,
             f"{X}/11/Security.csv", HCSV)])),
    chained("F-steve-007", "FULL", art(
        "FULL", "reference: lookup_ioc, opencti 6.4, op opencti-steve-001", [
            *RUN, {"method": "reference", "audit_id": "opencti-steve-001",
                   "entry_sha256": "e" * 64,
                   "reference": {"source": "lookup_ioc", "source_version": "opencti 6.4"},
                   "to": {"path": f"{X}/r/response.json", "sha256": "7" * 64}}])),
    chained("F-steve-008", "BROKEN",
            art("BROKEN", QUERY_064, root=None, brk={"kind": "recorded-before-0.6.4"})),
    chained("F-steve-009", "BROKEN",
            art("BROKEN", QUERY_064, root=None, brk={"kind": "recorded-before-0.6.4"},
                label="old query"),
            art("FULL", chain=RUN, label="the run")),
    chained("F-steve-010", "FULL", art("FULL", chain=[*RUN, link(
        "recorded-id", "sift-steve-030", f"{X}/3/big.bin", "pending:hash-0123456789abcdef",
        f"{X}/3/big.bin", HOUT)])),
    chained("F-steve-011", "AMBIGUOUS", {**art("AMBIGUOUS", "two operations wrote a.csv",
                                               root=None), "provenance_candidates": [
        {"audit_id": "sift-steve-040", "entry_sha256": "e" * 64, "path": f"{X}/4/a.csv",
         "sha256": HCSV},
        {"audit_id": "sift-steve-041", "entry_sha256": "e" * 64, "path": f"{X}/4/a.csv",
         "sha256": ""},
        {"audit_id": "sift-steve-042", "entry_sha256": "1" * 64, "tool": "run_command"},
        {"audit_id": "sift-steve-042", "entry_sha256": "2" * 64, "tool": "run_command"},
        {"audit_id": "sift-steve-043", "entry_sha256": "e" * 64, "path": "/mnt/case/disk",
         "image": IMG["path"]}]}),
]  # fmt: skip

DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const I = JSON.parse(fs.readFileSync(0, 'utf8'));
const src = fs.readFileSync(I.page, 'utf8').match(/<script>([\s\S]*?)<\/script>\s*<div id="chainTooltip"/)[1];
function el(id) {
  return { id, innerHTML: '', textContent: '', value: '', style: {}, dataset: {}, checked: false,
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    addEventListener() {}, removeEventListener() {}, setAttribute() {}, getAttribute() { return ''; },
    appendChild() {}, prepend() {}, remove() {}, focus() {}, scrollIntoView() {},
    querySelector() { return el('q'); }, querySelectorAll() { return []; }, closest() { return null; },
    getBoundingClientRect() { return { top: 0, left: 0, right: 0, bottom: 0 }; },
    parentElement: null, children: [], offsetHeight: 0 };
}
const els = {};
const document = {
  getElementById(id) { return els[id] || (els[id] = el(id)); },
  querySelector() { return el('q'); }, querySelectorAll() { return []; }, addEventListener() {},
  createElement(t) {
    const e = el(t);
    Object.defineProperty(e, 'textContent', {
      set(v) { e.innerHTML = String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); },
      get() { return e.innerHTML; } });
    return e;
  }, body: el('body'), documentElement: el('html'), cookie: '', title: '' };
const storage = { getItem() { return null; }, setItem() {}, removeItem() {} };
const ctx = { document, console, JSON, Math, Date, Promise, Object, Array, String, Number, Set, Map,
  RegExp, Error, encodeURIComponent, decodeURIComponent, parseInt, parseFloat, isNaN,
  setTimeout() { return 0; }, clearTimeout() {}, setInterval() { return 0; }, clearInterval() {},
  fetch() { return new Promise(() => {}); }, localStorage: storage, sessionStorage: storage,
  navigator: { clipboard: {} }, crypto: require('crypto').webcrypto, TextEncoder, TextDecoder,
  atob, btoa, Uint8Array, history: { replaceState() {}, pushState() {} }, alert() {},
  confirm() { return false; }, location: { pathname: '/portal/', hash: '', search: '', href: 'http://x/portal/' } };
ctx.window = ctx; ctx.window.addEventListener = function () {};
ctx.window.innerWidth = 1200; ctx.window.innerHeight = 800;
process.on('unhandledRejection', () => {});
vm.createContext(ctx);
ctx.__F = I.findings; ctx.__A = I.audit;
vm.runInContext(src + `
;(async function(){
  findings = __F; caseMeta = {}; var out = {};
  for (var i = 0; i < findings.length; i++) {
    var f = findings[i]; auditCache[f.id] = __A;
    renderFinding(f.id);
    var card = document.getElementById('findingCard').innerHTML;
    await loadToolInvocations(f);
    out[f.id] = {card: card, panel: document.getElementById('toolInvocationsList').innerHTML};
  }
  globalThis.__OUT = out;
})().catch(function(e){ globalThis.__ERR = String(e && e.stack || e); });`, ctx);
setTimeout(() => {
  if (ctx.__ERR) { process.stderr.write(ctx.__ERR); process.exit(3); }
  process.stdout.write(JSON.stringify(ctx.__OUT));
}, 200);
"""


@pytest.fixture(scope="module")
def shown() -> dict:
    node = shutil.which("node")
    if not node:
        pytest.skip("node isn't installed")
    audit = [{"audit_id": "x-1", "tool": "run_command", "_backend": "sift-mcp",
              "params": {"command": "vol -f mem2.raw windows.pslist"}}]  # fmt: skip
    r = subprocess.run([node, "-e", DRIVER], capture_output=True, text=True, timeout=120,
                       input=json.dumps({"page": str(PAGE), "findings": FINDINGS,
                                         "audit": audit}))  # fmt: skip
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout)


def text(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html).replace("&amp;", "&")


def test_the_run_command_chain_is_root_first_with_each_method_and_hash(shown):
    p = shown["F-steve-001"]["panel"]
    assert p.index("[sift-steve-001]") < p.index("[sift-steve-002]")
    assert "[registered-path]" in p and "[hash+place]" in p
    assert H7Z[:16] in p and HM2[:16] in p and HOUT[:16] in p
    assert "samples.7z" in p and "(AI-registered)" in p


def test_no_grade_is_computed_and_no_root_is_called_registered_evidence(shown):
    every = "".join(v["panel"] + v["card"] for v in shown.values())
    assert "(registered evidence)" not in every and ">PARTIAL<" not in every


def test_the_logged_bash_route_shows_declared_and_its_reason(shown):
    s = shown["F-steve-002"]
    assert "DECLARED" in s["panel"] and "log_external_action" in s["panel"]
    assert "[declared]" in s["panel"]
    assert "samples.7z (AI-registered)" in text(s["card"])
    assert "log_external_action" in s["card"]


def test_the_unlogged_bash_route_shows_broken_and_its_reason(shown):
    s = shown["F-steve-004"]
    assert ">BROKEN<" in s["card"] and UNLOGGED in s["card"]
    assert "BROKEN" in s["panel"] and UNLOGGED in s["panel"]


def test_every_method_is_shown(shown):
    every = "".join(v["panel"] for v in shown.values())
    for method in ("registered-path", "hash+place", "declared", "manifest", "recorded-id",
                   "recorded-mount", "reference"):  # fmt: skip
        assert f"[{method}]" in every, method


def test_a_finding_recorded_before_0_6_4_says_so_with_no_full_badge(shown):
    card = shown["F-steve-000"]["card"]
    assert f">{PRE}<" in card and ">FULL<" not in card


def test_an_import_names_its_case_and_lists_no_chain(shown):
    s = shown["F-steve-005"]
    both = s["card"] + s["panel"]
    assert ">IMPORTED<" in s["card"]
    assert (
        "chain lives in case case-A (imported from alice, exported 2026-10-08T09:00:00Z)"
        in both
    )
    assert PRE not in both and "[registered-path]" not in s["panel"]


def test_a_query_logged_before_0_6_4_shows_so_never_broken(shown):
    s = shown["F-steve-008"]
    assert f">{PRE}<" in s["card"] and "BROKEN" not in s["card"] + s["panel"]
    assert "opensearch-steve-009 records no results to follow" in s["panel"]


def test_a_mixed_finding_reads_before_0_6_4_and_each_artifact_its_own_grade(shown):
    s = shown["F-steve-009"]
    assert f">{PRE}<" in s["card"] and "BROKEN" not in s["card"] + s["panel"]
    blocks = s["panel"].split("border-left:3px")[1:]
    old = next(b for b in blocks if "old query" in b)
    run = next(b for b in blocks if "the run" in b)
    assert f">{PRE}<" in old and "records no results to follow" in old
    assert ">FULL<" in run and "[registered-path]" in run


def test_a_reference_link_names_its_source_and_version_and_full_keeps_its_reason(shown):
    s = shown["F-steve-007"]
    # the link's own line (the artifact's reason goes on: ", op …")
    assert "reference: lookup_ioc, opencti 6.4</span>" in s["panel"]
    assert ">FULL<" in s["card"] and "op opencti-steve-001" in s["card"]


def test_the_mount_route_shows_the_mount_and_an_examiner_registered_root(shown):
    s = shown["F-steve-006"]
    assert "[recorded-mount]" in s["panel"] and HCSV[:16] in s["panel"]
    assert "disk.E01 (examiner-registered)" in text(s["card"])


def test_case_text_in_the_chain_is_escaped():
    node = shutil.which("node") or pytest.skip("node isn't installed")
    evil = chained("F-steve-001", "FULL", art(
        "FULL", '<img src=x onerror="alert(1)">',
        [link("registered-path", "sift-steve-001", '/e/<b>x</b>.7z', H7Z, "o", HM2)],
        root={**ROOT, "label": "<script>"}))  # fmt: skip
    r = subprocess.run([node, "-e", DRIVER], capture_output=True, text=True, timeout=120,
                       input=json.dumps({"page": str(PAGE), "findings": [evil], "audit": []}))  # fmt: skip
    out = json.loads(r.stdout)["F-steve-001"]
    both = out["card"] + out["panel"]
    assert "<img" not in both and "<script>" not in both and "<b>x" not in both


# --- The Evidence tab ------------------------------------------------------------


def test_an_evidence_row_lists_the_findings_whose_chain_resolves_to_it(portal):
    portal.write("evidence.json", {"files": [
        {"path": ROOT["path"], "sha256": H7Z, "registered_by": "steve"},
        {"path": IMG["path"], "sha256": HIMG, "registered_by": "steve"}]})  # fmt: skip
    named_only = finding(
        "F-steve-020", artifacts=[{"source": ROOT["path"], "audit_id": "x"}]
    )
    second = chained("F-steve-021", "FULL", art("FULL", chain=RUN))
    second["artifacts"][0]["provenance_roots"] = [ROOT, IMG]  # an operation over both
    portal.write("findings.json", FINDINGS + [named_only, second])
    rows = {e["path"]: e for e in portal.get("/api/evidence").json()}
    assert rows[ROOT["path"]]["referenced_by"] == [
        "F-steve-001", "F-steve-002", "F-steve-003", "F-steve-005", "F-steve-007",
        "F-steve-009", "F-steve-010", "F-steve-021",
    ]  # fmt: skip
    assert rows[IMG["path"]]["referenced_by"] == ["F-steve-006", "F-steve-021"]


def test_a_hash_still_being_computed_names_its_job_never_reads_as_a_hash(shown):
    p = shown["F-steve-010"]["panel"]
    assert "pending (job hash-0123456789abcdef)" in p
    assert "pending:hash" not in p


def test_each_candidate_of_an_ambiguous_artifact_is_listed_by_the_fields_it_has(shown):
    p = text(shown["F-steve-011"]["panel"])
    assert (
        f"candidate: sift-steve-040 entry={'e' * 16} path={X}/4/a.csv sha256={HCSV[:16]}"
        in p
    )
    assert f"candidate: sift-steve-041 entry={'e' * 16} path={X}/4/a.csv no hash" in p
    for n in "12":  # one id on two entries: told apart by the entry's hash
        assert f"candidate: sift-steve-042 entry={n * 16} tool=run_command " in p
    assert (
        f"candidate: sift-steve-043 entry={'e' * 16} path=/mnt/case/disk image={IMG['path']} "
        in p
    )


def test_a_reference_step_starts_at_its_source_never_at_a_question_mark(shown):
    p = text(shown["F-steve-007"]["panel"])
    assert "lookup_ioc (opencti 6.4) → response.json" in p
    assert "? →" not in p


def test_a_folder_row_lists_the_findings_rooted_at_its_members(portal):
    kape = f"{EV}/kape"
    portal.write("evidence.json", {"files": [
        {"path": kape, "kind": "folder", "file_count": 2, "manifest_sha256": "1" * 64,
         "registered_by": "steve"}]})  # fmt: skip
    member = {"path": f"{kape}/Security.evtx", "sha256": HCSV, "folder": kape,
              "label": "examiner-registered"}  # fmt: skip
    f = chained("F-steve-030", "FULL", art("FULL", root=member, chain=[link(
        "manifest", "sift-steve-050", member["path"], HCSV, member["path"], HCSV)]))  # fmt: skip
    portal.write("findings.json", [f])
    rows = {e["path"]: e for e in portal.get("/api/evidence").json()}
    assert rows[kape]["referenced_by"] == ["F-steve-030"]


def test_a_folder_row_shows_its_file_count():
    node = shutil.which("node") or pytest.skip("node isn't installed")
    page = PAGE.read_text()
    start = page.index("function renderEvidence(")
    fn = page[start : page.index("\n}\n", start) + 3]
    esc = page.index("function escapeHtml(")
    script = (
        "var out = {innerHTML: ''}; var evidenceSortCol = 'path', evidenceSortAsc = true;"
        "var document = {getElementById: function() { return out; },"
        " querySelectorAll: function() { return []; },"
        " createElement: function() { return {set textContent(s) { this.innerHTML = String(s); }}; }};"
        "function formatTime(t) { return t || ''; } function escapeJsString(s) { return s; }"
        "var evidenceData = "
        + json.dumps(
            [
                {
                    "path": "/e/kape",
                    "kind": "folder",
                    "file_count": 12,
                    "manifest_sha256": "1" * 64,
                },
                {"path": "/e/mem.raw", "sha256": "2" * 64},
            ]
        )
        + ";\n"  # fmt: skip
        + page[esc : page.index("\n}\n", esc) + 3]
        + fn
        + "\nrenderEvidence(); process.stdout.write(out.innerHTML);"
    )
    r = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-500:]
    rows = r.stdout.split("<tr>")
    assert "folder (12 files)" in next(x for x in rows if "/e/kape" in x)
    assert "files)" not in next(x for x in rows if "/e/mem.raw" in x)
