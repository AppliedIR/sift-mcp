"""The case-data guard blocks only real damage to case records.

The PreToolUse hook gated on a TOOL_NAME env var Claude Code never sets and
read the wrong payload field, so it never blocked anything. Now it blocks
deleting or overwriting the protected case data (records, audit/, evidence
files, case and cases roots) and allows everything else: other files,
reports/, filing into evidence/, moving unprotected files into DELETE/.

The real script runs with the documented payload. The cases directory is
outside /tmp (the old guard allowed everything under /tmp/).
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

HOOK = (
    Path(__file__).parent.parent.parent
    / "claude-code"
    / "shared"
    / "hooks"
    / "case-data-guard.sh"
)
SETTINGS = (
    Path(__file__).parent.parent.parent / "claude-code" / "full" / "settings.json"
)


@pytest.fixture
def box(tmp_path):
    """A cases tree outside /tmp (VHIR_CASES_DIR) and scratch files outside it."""
    if not os.access("/var/tmp", os.W_OK):
        pytest.skip("needs a writable /var/tmp (cases must sit outside /tmp)")
    root = Path(tempfile.mkdtemp(dir="/var/tmp", prefix="guard-"))
    cases = root / "cases"
    case = cases / "INC-1"
    for d in (
        "audit",
        "evidence",
        "reports/old",
        "DELETE",
        ".outputs",
        "extractions",
        "work",
    ):
        (case / d).mkdir(parents=True)
    for f in (
        "findings.json",
        "timeline.json",
        "approvals.jsonl",
        "iocs.json",
        "evidence.json",
        "todos.json",
        "CASE.yaml",
        "notes.txt",
        "audit/forensic-mcp.jsonl",
        "evidence/disk.E01",
        "reports/draft.md",
        "reports/a.tmp",
        ".outputs/x",
        "extractions/y",
        "work/scratch.txt",
        "actions.jsonl",
        "pending-reviews.json",
        "evidence/unregistered-notes.txt",
    ):
        (case / f).write_text("x\n")
    (cases / "notes.md").write_text("x\n")
    out = tmp_path / "out"
    out.mkdir()
    (out / "x").write_text("x\n")
    (out / "new.E01").write_text("x\n")
    yield root, cases, case, out
    shutil.rmtree(root)


def run(box, cwd, cmd, timeout=30):
    root, cases, case, out = box
    payload = {
        "session_id": "s",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": cmd, "description": "d"},
        "tool_use_id": "t",
    }
    return subprocess.run(
        ["bash", str(HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=cwd,
        env={"HOME": str(root), "PATH": "/usr/bin:/bin", "VHIR_CASES_DIR": str(cases)},
        timeout=timeout,
    )


# (expected exit, label, cwd key, command template). {C} case, {CS} cases root, {O} outside.
BLOCK = [
    ("rm record", "C", "rm {C}/findings.json"),
    ("rm -f record", "C", "rm -f {C}/timeline.json"),
    ("rm -rf case root", "O", "rm -rf {C}"),
    ("rmdir cases root", "O", "rmdir {CS}"),
    ("mv record away", "C", "mv {C}/approvals.jsonl {O}/a"),
    ("mv over record", "C", "mv {O}/x {C}/findings.json"),
    ("find -delete in case", "C", "find {C} -name x -delete"),
    ("redirect > record", "C", "echo x > {C}/findings.json"),
    ("redirect >> record", "C", "echo x >> {C}/approvals.jsonl"),
    ("truncate record", "C", "truncate -s 0 {C}/iocs.json"),
    ("cp over record", "C", "cp {O}/x {C}/evidence.json"),
    ("sudo rm", "C", "sudo rm {C}/todos.json"),
    ("env prefix rm", "C", "env FOO=1 rm {C}/CASE.yaml"),
    ("assign prefix rm", "C", "FOO=1 rm {C}/CASE.yaml"),
    ("chain && 2nd seg", "C", "cd {O} && rm {C}/findings.json"),
    ("chain ; 2nd seg", "C", "true; rm {C}/findings.json"),
    ("pipe 2nd seg", "C", "echo | rm {C}/findings.json"),
    ("newline 2nd line", "C", "echo hi\nrm {C}/findings.json"),
    ("rm -rf audit/", "C", "rm -rf {C}/audit"),
    ("rm evidence file", "C", "rm {C}/evidence/disk.E01"),
    ("mv evidence rename", "C", "mv {C}/evidence/disk.E01 {C}/evidence/b.E01"),
    ("cp over evidence", "C", "cp {O}/x {C}/evidence/disk.E01"),
    ("quoted path", "C", 'rm "{C}/findings.json"'),
    ("glob in case root", "C", "rm {C}/*.json"),
    ("relative, cwd=case", "C", "rm findings.json"),
    ("cd case && rel rm", "O", "cd {C} && rm findings.json"),
    ("/bin/rm abs cmd", "C", "/bin/rm {C}/findings.json"),
    ("unlink record", "C", "unlink {C}/findings.json"),
    ("ancestor ..", "C", "rm -rf {C}/reports/.."),
    ("rm -rf case/* (glob)", "C", "rm -rf {C}/*"),
    ("rm actions.jsonl", "C", "rm {C}/actions.jsonl"),
    ("rm pending-reviews.json", "C", "rm {C}/pending-reviews.json"),
    ("rm unregistered evidence file", "C", "rm {C}/evidence/unregistered-notes.txt"),
    ("rm -rf non-empty evidence/", "C", "rm -rf {C}/evidence"),
    ("shred record", "C", "shred {C}/findings.json"),
    ("sudo -u root rm", "C", "sudo -u root rm {C}/findings.json"),
    ("nice -n 5 rm", "C", "nice -n 5 rm {C}/findings.json"),
    ("timeout 5 rm", "C", "timeout 5 rm {C}/findings.json"),
    ("if-then rm", "C", "if true; then rm {C}/findings.json; fi"),
    ("brace group rm", "C", "{{ rm {C}/findings.json; }}"),
    ("mv -t dir record", "C", "mv -t {O} {C}/findings.json"),
    ("mv --target-directory=", "C", "mv --target-directory={O} {C}/findings.json"),
    # Decision 9 (Steve: block): protected data can't be moved into DELETE/
    ("mv record into DELETE/", "C", "mv {C}/findings.json {C}/DELETE/"),
    (
        "mv audit file into DELETE/",
        "C",
        "mv {C}/audit/forensic-mcp.jsonl {C}/DELETE/",
    ),
    ("mv evidence file into DELETE/", "C", "mv {C}/evidence/disk.E01 {C}/DELETE/"),
    (
        "two-step via DELETE/",
        "C",
        "mv {C}/findings.json {C}/DELETE/ && rm {C}/DELETE/findings.json",
    ),
    ("find group -delete", "C", "find {C} \\( -name x -o -name y \\) -delete"),
    ("subshell rm", "C", "(rm {C}/findings.json)"),
    ("find with two roots", "C", "find {O} {C} -name x -delete"),
    ("backslash-newline rm", "C", "rm \\\n{C}/findings.json"),
    ("&& at a line end", "C", "true &&\nrm {C}/findings.json"),
    ("; at a line end", "C", "true;\nrm {C}/findings.json"),
    ("blank line between", "C", "echo hi\n\nrm {C}/findings.json"),
    ("quoted newline, then a redirect", "C", 'echo "a\nb" > "{C}/findings.json"'),
    ("quoted newline in an rm word", "C", 'rm -f "notes\n" {C}/findings.json'),
    ("find -L root", "O", "find -L {C} -delete"),
    ("find -O3 -D tree root", "O", "find -O3 -D tree {C} -name x -exec rm {{}} +"),
    ("rm inside $(...)", "C", "echo $(rm {C}/findings.json)"),
    ("rm inside x=$(...)", "C", "x=$( rm {C}/findings.json )"),
    ("cp -rT onto a case", "C", "cp -rT {O} {C}"),
    ("redirect onto a glob", "C", "echo x > {C}/finding?.json"),
    # Accepted, disclosed over-blocks (decision 8)
    ("over-block: find case -delete", "C", "find {C} -name '*.tmp' -delete"),
    (
        "over-block: heredoc body",
        "C",
        "cat > {C}/reports/r.md <<'EOF'\nrm {C}/findings.json\nEOF",
    ),
]
ALLOW = [
    ("glob no-match in case root", "C", "rm -f {C}/*.tmp"),
    ("cp FROM record (read)", "C", "cp {C}/findings.json {O}/f.json"),
    ("cp -r FROM evidence", "C", "cp -r {C}/evidence {O}/ev"),
    ("pipe read | jq", "C", "cat {C}/findings.json | jq ."),
    ("redirect tool out to reports", "C", "python3 x.py > {C}/reports/out.txt 2>&1"),
    ("rm -rf .outputs/*", "C", "rm -rf {C}/.outputs/*"),
    (
        "mkdir && mv into reports",
        "C",
        "mkdir -p {C}/reports/x && mv {O}/x {C}/reports/x/",
    ),
    ("rename in reports", "C", "mv {C}/reports/draft.md {C}/reports/final.md"),
    ("tar case out", "C", "tar czf {O}/c.tgz {C}"),
    ("find reports -delete", "C", "find {C}/reports -name '*.tmp' -delete"),
    ("mv into DELETE/", "C", "mv {C}/notes.txt {C}/DELETE/notes.txt"),
    ("mv report into DELETE/", "C", "mv {C}/reports/draft.md {C}/DELETE/"),
    ("file into evidence/", "C", "mv {O}/new.E01 {C}/evidence/new.E01"),
    ("cp into evidence/ dir", "C", "cp {O}/new.E01 {C}/evidence/"),
    ("rm in reports/", "C", "rm {C}/reports/draft.md"),
    ("rm -rf reports/old", "C", "rm -rf {C}/reports/old"),
    ("glob in reports/", "C", "rm -f {C}/reports/*.tmp"),
    ("redirect into reports/", "C", "echo x > {C}/reports/r.md"),
    ("rm .outputs", "C", "rm {C}/.outputs/x"),
    ("rm extractions", "C", "rm -rf {C}/extractions/y"),
    ("read record", "C", "cat {C}/findings.json"),
    ("rm outside cases", "C", "rm {O}/x"),
    ("record name outside cases", "C", "echo '{{}}' > {O}/findings.json"),
    ("rm non-record in case root", "C", "rm {C}/notes.txt"),
    ("rm in work/", "C", "rm {C}/work/scratch.txt"),
    ("rm a file beside the cases", "C", "rm {CS}/notes.md"),
    (
        "quoted arg mentioning record",
        "C",
        'grep "rm {C}/findings.json" {C}/reports/draft.md',
    ),
    ("quoted multi-line text mentioning rm", "C", 'echo "x\nrm {C}/findings.json"'),
    ("find -L elsewhere", "C", "find -L {C}/reports -name x -delete"),
    ("$(...) reading a record", "C", "echo $(cat {C}/findings.json)"),
    # Disclosed as not seen: a # comment hides the rest of the command
    (
        "not seen: a command after a comment line",
        "C",
        "# tidy up\nrm {C}/findings.json",
    ),
    (
        "not seen: an operand after $(...) in a word",
        "C",
        "rm x$(true) {C}/findings.json",
    ),
]


def _fill(box, cwd_key, template):
    root, cases, case, out = box
    cmd = template.format(C=case, CS=cases, O=out)
    return (case if cwd_key == "C" else out), cmd


@pytest.mark.parametrize("label,cwd_key,template", BLOCK, ids=[r[0] for r in BLOCK])
def test_blocks_damage_to_case_data(box, label, cwd_key, template):
    cwd, cmd = _fill(box, cwd_key, template)
    p = run(box, cwd, cmd)
    assert p.returncode == 2, (cmd, p.stdout, p.stderr)  # E: exactly 2
    assert p.stdout == "" and "BLOCKED" in p.stderr  # S: the reason on stderr only
    assert "couldn't read" not in p.stderr  # its own reason, not the fail-closed one
    assert "vhir case delete" not in p.stderr


@pytest.mark.parametrize("label,cwd_key,template", ALLOW, ids=[r[0] for r in ALLOW])
def test_allows_everything_else(box, label, cwd_key, template):
    cwd, cmd = _fill(box, cwd_key, template)
    p = run(box, cwd, cmd)
    assert p.returncode == 0 and p.stdout == "" and p.stderr == "", (cmd, p.stderr)


def test_x_the_command_is_never_executed(box):
    root, cases, case, out = box
    canary = out / "CANARY"
    for cmd in (
        f"echo $(>{canary})",
        f"rm `>{canary}` x",
        f"mv {case}/a{{,$(>{canary})}} {out}",
    ):
        run(box, case, cmd)
        assert not canary.exists(), cmd


def _wide(out):
    """A small tree whose deep globs match astronomically many paths."""
    w = out / "wide"
    w.mkdir()
    for i in range(12):
        (w / f"l{i:02d}").symlink_to(".")
    return w


def test_t_a_pathological_glob_still_blocks_within_5_seconds(box):
    root, cases, case, out = box
    w = _wide(out)
    t0 = time.monotonic()
    p = run(box, case, f"rm {w}/*/*/*/*/*/* {case}/findings.json", timeout=60)
    assert p.returncode == 2 and time.monotonic() - t0 < 5


def test_the_cap_cannot_hide_a_record(box):
    """`rm <case>/*` where the record comes after the guard's 2000-match cap
    in directory order (the order glob yields)."""
    root, cases, case, out = box
    t2 = cases / "INC-T2"
    t2.mkdir()
    (t2 / "findings.json").write_text("x\n")
    n = 0
    while [e.name for e in os.scandir(t2)].index("findings.json") <= 2000:
        if n >= 100_000:
            pytest.skip("can't place the record beyond the cap on this filesystem")
        for i in range(n, n + 5000):
            (t2 / f"note{i:06d}.txt").touch()
        n += 5000
    t0 = time.monotonic()
    p = run(box, t2, f"rm {t2}/*")
    assert p.returncode == 2 and time.monotonic() - t0 < 5


def test_anchor_a_large_glob_in_outputs_is_allowed(box):
    root, cases, case, out = box
    for i in range(5000):
        (case / ".outputs" / f"o{i:05d}").touch()
    t0 = time.monotonic()
    p = run(box, case, f"rm -rf {case}/.outputs/*")
    assert p.returncode == 0 and time.monotonic() - t0 < 5


def test_d_the_settings_entry_still_runs_this_script():
    entries = json.loads(SETTINGS.read_text())["hooks"]["PreToolUse"]
    commands = [h["command"] for e in entries for h in e.get("hooks", [])]
    assert any(c.endswith("/case-data-guard.sh") for c in commands)
    assert os.access(HOOK, os.X_OK) and "TOOL_NAME" not in HOOK.read_text()


def test_a_module_planted_in_the_cwd_is_not_imported(box):
    root, cases, case, out = box
    canary = out / "PLANTED"
    for mod in ("shlex", "json", "glob"):
        (case / f"{mod}.py").write_text(
            f"open({str(canary)!r}, 'w').close()\nraise SystemExit(1)\n"
        )
    p = run(box, case, f"rm {case}/findings.json")
    assert p.returncode == 2 and not canary.exists()


# Fail closed: input the guard can't read, or an error of its own, blocks.
def _raw(box, stdin):
    root, cases, case, out = box
    return subprocess.run(
        ["bash", str(HOOK)],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=case,
        env={"HOME": str(root), "PATH": "/usr/bin:/bin", "VHIR_CASES_DIR": str(cases)},
        timeout=30,
    )


def _payload(**kw):
    return json.dumps({"session_id": "s", "tool_name": "Bash", **kw})


UNREADABLE = [
    ("unparseable JSON", "{not json"),
    ("empty stdin", ""),
    ("a JSON list", "[]"),
    ("no tool_input", _payload()),
    ("tool_input a string", _payload(tool_input="rm findings.json")),
    ("tool_input null", _payload(tool_input=None)),
    ("no command", _payload(tool_input={"description": "d"})),
    ("command null", _payload(tool_input={"command": None})),
    ("command a number", _payload(tool_input={"command": 5})),
    ("command a list", _payload(tool_input={"command": ["rm", "findings.json"]})),
    # an error inside the check itself (os.path.join on a non-string cwd)
    ("an unexpected error", _payload(tool_input={"command": "rm x"}, cwd=5)),
]


@pytest.mark.parametrize("label,stdin", UNREADABLE, ids=[r[0] for r in UNREADABLE])
def test_input_the_guard_cannot_read_is_blocked(box, label, stdin):
    p = _raw(box, stdin)
    assert p.returncode == 2 and p.stdout == "", (label, p.stderr)
    assert "couldn't read this command, so it was blocked" in p.stderr
    assert "Traceback" not in p.stderr


def test_anchor_an_empty_command_is_read_and_allowed(box):
    p = _raw(box, _payload(tool_input={"command": ""}))
    assert p.returncode == 0 and p.stderr == ""
