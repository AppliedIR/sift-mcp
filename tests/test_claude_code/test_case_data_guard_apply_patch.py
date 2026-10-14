"""Codex's apply_patch is checked by the case-data guard as Claude Code's Edit
deny checks an edit: a patch that adds, updates, deletes or moves onto a case
record, an audit log or an evidence file is refused (exit 2, a "refused" line
in the case's audit), by the paths its headers name. The patch's lines are
never read as shell, so a context line like ` rm audit/x` refuses nothing."""

import json
import os
import subprocess
import threading
import time

import pytest

from .test_case_data_guard import HOOK, box  # noqa: F401
from .test_case_data_guard import run as shell


def patch(box, cwd, body):  # noqa: F811
    root, cases, case, out = box
    payload = {"session_id": "s", "cwd": str(cwd), "hook_event_name": "PreToolUse",
               "tool_name": "apply_patch", "tool_input": {"command": body}, "tool_use_id": "t"}  # fmt: skip
    return subprocess.run(
        ["bash", str(HOOK)], input=json.dumps(payload), capture_output=True, text=True, cwd=cwd,
        env={"HOME": str(root), "PATH": "/usr/bin:/bin", "VHIR_CASES_DIR": str(cases), "VHIR_CASE_DIR": str(case)}, timeout=30,
    )  # fmt: skip


def body(*sections):
    return "*** Begin Patch\n" + "".join(sections) + "*** End Patch\n"


def update(path, old="x", new="y"):
    return f"*** Update File: {path}\n@@\n-{old}\n+{new}\n"


BLOCKED = {
    "update a record": lambda C, O: body(update(f"{C}/findings.json")),
    "update an audit log": lambda C, O: body(update(f"{C}/audit/forensic-mcp.jsonl")),
    "update pending-reviews": lambda C, O: body(update(f"{C}/pending-reviews.json")),
    "add a host record": lambda C, O: body(
        f"*** Add File: {C}/host-observations.jsonl\n+{{}}\n"
    ),
    "delete a record": lambda C, O: body(f"*** Delete File: {C}/timeline.json\n"),
    "move onto a record": lambda C, O: body(
        update(f"{C}/notes.txt") + f"*** Move to: {C}/findings.json\n"
    ),
    "update an evidence file": lambda C, O: body(update(f"{C}/evidence/disk.E01")),
    "a relative path from the case": lambda C, O: body(update("findings.json")),
}


@pytest.mark.parametrize("label", sorted(BLOCKED))
def test_a_patch_onto_case_data_is_refused_and_recorded(box, label):  # noqa: F811
    root, cases, case, out = box
    r = patch(box, case, BLOCKED[label](case, out))
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "BLOCKED: apply_patch" in r.stderr
    lines = [
        json.loads(x)
        for x in (case / "audit" / "claude-code.jsonl").read_text().splitlines()
    ]
    assert lines[-1]["event"] == "refused" and lines[-1]["reason"].startswith(
        "apply_patch"
    )


ALLOWED = {
    "update a report": lambda C, O: body(update(f"{C}/reports/draft.md")),
    "add a new file to evidence": lambda C, O: body(
        f"*** Add File: {C}/evidence/new-notes.txt\n+n\n"
    ),
    "update a file outside the cases": lambda C, O: body(update(f"{O}/x")),
    "context lines that read like shell": lambda C, O: body(
        f"*** Update File: {C}/notes.txt\n@@\n rm audit/forensic-mcp.jsonl\n"
        " echo x > findings.json\n-x\n+y\n"
    ),
}


@pytest.mark.parametrize("label", sorted(ALLOWED))
def test_a_patch_to_ordinary_files_passes(box, label):  # noqa: F811
    root, cases, case, out = box
    r = patch(box, case, ALLOWED[label](case, out))
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert not (case / "audit" / "claude-code.jsonl").exists()


# --- every header form Codex applies is checked -------------------------------
# Measured with Codex 0.158's own parser (`codex --codex-run-as-apply-patch`) on a
# scratch file: the forms it APPLIES (True) must each be blocked onto a record; the
# forms it rejects (False) need no rule. The binary row pins the table to the parser.

KINDS = ("update", "add", "delete", "move")
CODEX_APPLIES = {  # variant -> the kinds Codex applies in that form
    "plain": KINDS,
    "leading spaces": (
        "update",
        "add",
        "delete",
    ),  # a Move to line indented too: rejected
    "leading tab": ("update", "add", "delete"),
    "trailing spaces": KINDS,
    "CRLF": KINDS,
    "Begin Patch wrapper indented": KINDS,
    "header indented, Move to at column 0": KINDS,
    "Move to indented, header at column 0": ("update", "add", "delete"),
    "extra space after ***": (),
    "lowercase": (),
    "no space after colon": (),
    "tab after colon": (),
    "space before colon": (),
    "no Begin Patch wrapper": (),
    "U+3000 at both ends": KINDS,  # any White_Space code point; Move to: at its end only
    "TAB inside the path": KINDS,  # Codex deletes TAB and CR anywhere in a header's path
    "CR inside the path": KINDS,
}


def form(kind, v, update, add, delete, move_to):
    """`kind`'s patch in variant `v`, on these paths (Update and Move start from `update`)."""
    if v in ("TAB inside the path", "CR inside the path"):  # findings.\tjson
        c = "\t" if v.startswith("TAB") else "\r"
        update, add, delete, move_to = (
            p[: p.rindex(".") + 1] + c + p[p.rindex(".") + 1 :]
            for p in (update, add, delete, move_to)
        )
    word, path = {"update": ("Update File", update), "add": ("Add File", add),
                  "delete": ("Delete File", delete), "move": ("Update File", update)}[kind]  # fmt: skip
    hunk = {"update": "@@\n-x\n+y\n", "add": "+new\n", "delete": "",
            "move": f"*** Move to: {move_to}\n@@\n-x\n+y\n"}[kind]  # fmt: skip
    header = {
        "leading spaces": f"  *** {word}: {path}", "leading tab": f"\t*** {word}: {path}",
        "trailing spaces": f"*** {word}: {path}   ", "extra space after ***": f"***  {word}: {path}",
        "lowercase": f"*** {word.lower()}: {path}", "no space after colon": f"*** {word}:{path}",
        "tab after colon": f"*** {word}:\t{path}", "space before colon": f"*** {word} : {path}",
        "header indented, Move to at column 0": f"  *** {word}: {path}",
        "U+3000 at both ends": f"\u3000*** {word}: {path}\u3000",
    }.get(v, f"*** {word}: {path}")  # fmt: skip
    if v == "U+3000 at both ends":
        hunk = hunk.replace(f"{move_to}\n", f"{move_to}\u3000\n")
    if kind == "move" and v in (
        "leading spaces",
        "leading tab",
        "Move to indented, header at column 0",
    ):
        hunk = hunk.replace(
            "*** Move to:", ("\t" if v == "leading tab" else "  ") + "*** Move to:"
        )
    begin, end = {"no Begin Patch wrapper": ("", ""),
                  "Begin Patch wrapper indented": ("  *** Begin Patch\n", "  *** End Patch\n")}.get(
        v, ("*** Begin Patch\n", "*** End Patch\n"))  # fmt: skip
    text = begin + header + "\n" + hunk + end
    return text.replace("\n", "\r\n") if v == "CRLF" else text


APPLIED = [(v, k) for v, kinds in CODEX_APPLIES.items() for k in kinds]


@pytest.mark.parametrize(("variant", "kind"), APPLIED)
def test_every_header_form_codex_applies_is_refused_onto_a_record(box, variant, kind):  # noqa: F811
    root, cases, case, out = box
    text = form(kind, variant, f"{case}/findings.json", f"{case}/host-observations.jsonl",
                f"{case}/timeline.json", f"{case}/findings.json")  # fmt: skip
    if kind == "move":  # an ordinary file moved onto a record
        text = text.replace(f"{case}/findings.json", f"{case}/notes.txt", 1)
    r = patch(box, case, text)
    assert r.returncode == 2, (variant, kind, r.stderr)


def test_the_table_is_what_codex_applies(tmp_path):
    """Codex's own parser applies exactly the table's forms (skipped without it)."""
    import shutil

    codex = shutil.which("codex")
    if not codex:
        pytest.skip("no codex binary here")
    got = {}
    for v in CODEX_APPLIES:
        for k in KINDS:
            d = tmp_path / f"{len(got)}"
            d.mkdir()
            (d / "t.txt").write_text("x\n")
            subprocess.run([codex, "--codex-run-as-apply-patch", form(k, v, "t.txt", "n.txt", "t.txt", "m.txt")],
                           cwd=d, capture_output=True, text=True, timeout=60)  # fmt: skip
            got[(v, k)] = {"update": (d / "t.txt").exists() and (d / "t.txt").read_text() == "y\n",
                           "add": (d / "n.txt").is_file(), "delete": not (d / "t.txt").exists(),
                           "move": (d / "m.txt").is_file() and not (d / "t.txt").exists()}[k]  # fmt: skip
    assert sorted(x for x, ok in got.items() if ok) == sorted(APPLIED)


def test_python_white_space_covers_what_codex_trims():
    """The guard's [^\\S\\n] matches every Unicode White_Space code point but LF, and not LF."""
    import re

    white_space = [0x09, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B),
                   0x2028, 0x2029, 0x202F, 0x205F, 0x3000]  # fmt: skip
    assert len(white_space) == 24
    assert all(re.fullmatch(r"[^\S\n]", chr(c)) for c in white_space)
    assert not re.fullmatch(r"[^\S\n]", "\n")


# --- a header's path never runs onto the next line ----------------------------
# Codex splits a patch into lines at LF only (measured: U+2028, U+2029, U+0085, a
# lone CR, VT and FF start no line), so an empty header, or a context line ending
# like one, can't take the next line's header for its path: that header is checked.

KEYWORDS = ("Add File", "Update File", "Delete File", "Move to")
TAILS = {"nothing": "", "a space": " ", "a tab": "\t", "VT": "\x0b", "FF": "\x0c",
         "NBSP": "\u00a0", "U+3000": "\u3000", "CR (a CRLF line)": "\r"}  # fmt: skip


def codex_payload(target):
    """codex review's payload: a context line ` *** Add File:` before a Delete."""
    return ("*** Begin Patch\n*** Update File: notes.txt\n@@\n-before\n+after\n *** Add File:\n"
            f"*** Delete File: {target}\n*** End Patch\n")  # fmt: skip


def test_codex_reviews_payload_is_refused(box):  # noqa: F811
    root, cases, case, out = box
    r = patch(box, case, codex_payload(f"{case}/findings.json"))
    assert r.returncode == 2, r.stderr
    assert "Delete File" in r.stderr


@pytest.mark.parametrize("keyword", KEYWORDS)
def test_an_empty_header_doesnt_take_the_next_header(box, keyword):  # noqa: F811
    root, cases, case, out = box
    r = patch(
        box, case, body(f"*** {keyword}:\n*** Delete File: {case}/findings.json\n")
    )
    assert r.returncode == 2, r.stderr


@pytest.mark.parametrize("tail", sorted(TAILS))
@pytest.mark.parametrize("keyword", KEYWORDS)
def test_a_context_line_like_a_header_doesnt_take_the_next_header(box, keyword, tail):  # noqa: F811
    root, cases, case, out = box
    context = f" *** {keyword}:{TAILS[tail]}\n"
    r = patch(box, case, body(update("notes.txt", "before", "after") + context
                              + f"*** Delete File: {case}/findings.json\n"))  # fmt: skip
    assert r.returncode == 2, (keyword, tail, r.stderr)


@pytest.mark.parametrize(
    "between, header",
    [
        ("\n", "*** Delete File: {C}/findings.json\n"),  # a blank line between
        ("  \n", "*** Delete File: {C}/findings.json\n"),  # a line of spaces between
        ("", "*** Delete File: {C}/findings.json\r\n"),  # a CRLF Delete
        ("", "*** Update File: {C}/timeline.json\n@@\n-x\n+y\n"),
    ],
    ids=["blank line", "spaces line", "CRLF Delete", "Update of a record"],
)
def test_the_header_after_an_empty_one_is_still_checked(box, between, header):  # noqa: F811
    root, cases, case, out = box
    text = update("notes.txt", "before", "after") + " *** Add File:\n" + between
    r = patch(box, case, body(text + header.format(C=case)))
    assert r.returncode == 2, r.stderr


def test_an_ordinary_delete_after_an_empty_header_passes(box):  # noqa: F811
    root, cases, case, out = box
    r = patch(box, case, codex_payload(f"{out}/x"))
    assert r.returncode == 0, r.stderr


def test_codex_splits_a_patch_at_lf_only(tmp_path):
    """Codex's own parser: codex review's payload deletes the file, and no other
    break character starts the Delete's line (skipped without the binary)."""
    import shutil

    codex = shutil.which("codex")
    if not codex:
        pytest.skip("no codex binary here")
    got = {}
    for name, sep in [("LF", "\n"), ("U+2028", "\u2028"), ("U+2029", "\u2029"), ("U+0085", "\u0085"),
                      ("lone CR", "\r"), ("VT", "\x0b"), ("FF", "\x0c")]:  # fmt: skip
        d = tmp_path / f"{len(got)}"
        d.mkdir()
        (d / "notes.txt").write_text("before\n*** Add File:\n")
        (d / "r.txt").write_text("x\n")
        text = codex_payload("r.txt").replace(
            " *** Add File:\n", " *** Add File:" + sep
        )
        subprocess.run([codex, "--codex-run-as-apply-patch", text], cwd=d, capture_output=True, text=True,
                       timeout=60)  # fmt: skip
        got[name] = not (d / "r.txt").exists()
    assert got == {"LF": True, "U+2028": False, "U+2029": False, "U+0085": False, "lone CR": False,
                   "VT": False, "FF": False}  # fmt: skip


# --- apply_patch through the shell --------------------------------------------
# Codex intercepts `apply_patch` (or `applypatch`) run in the shell and applies
# the patch natively; its hook sees only "Bash" with the shell text. The guard
# refuses that command word on any path: only the apply_patch tool is checked
# by the paths it names. Other shell text that merely names a header passes.

HEREDOC = "apply_patch <<'EOF'\n*** Begin Patch\n{headers}*** End Patch\nEOF\n"
DELETE = "*** Delete File: {path}\n"
SHELL_BLOCKED = {  # label -> (cwd, command)
    "heredoc, relative": ("case", HEREDOC.format(headers=DELETE.format(path="findings.json"))),
    "heredoc, absolute": ("out", HEREDOC.format(headers=DELETE.format(path="{C}/findings.json"))),
    "cd to the case first": ("out", "cd {C} && " + HEREDOC.format(headers=DELETE.format(path="timeline.json"))),
    "cd to the case, double-quoted": ("out", 'cd "{C}" && ' + HEREDOC.format(headers=DELETE.format(path="timeline.json"))),
    "cd to the case, single-quoted": ("out", "cd '{C}' && " + HEREDOC.format(headers=DELETE.format(path="timeline.json"))),
    "applypatch": ("case", HEREDOC.replace("apply_patch", "applypatch").format(headers=DELETE.format(path="findings.json"))),
    "a Move to into audit": ("case", HEREDOC.format(headers="*** Update File: notes.txt\n*** Move to: audit/x\n@@\n-x\n+y\n")),
    "through env": ("case", "env A=1 " + HEREDOC.format(headers=DELETE.format(path="findings.json"))),
    "by its path": ("case", "/usr/local/bin/" + HEREDOC.format(headers=DELETE.format(path="findings.json"))),
    "piped into": ("case", "cat p.patch | apply_patch"),
    "from a file": ("case", "apply_patch < p.patch"),
    "an ANSI-C quoted argument": ("case", "apply_patch $'*** Begin Patch\\n*** Delete File: findings.json\\n*** End Patch'"),
    "a quoted argument": ("case", "apply_patch '*** Begin Patch\n*** Delete File: findings.json\n*** End Patch'"),
    "codex's own patch runner": ("case", "codex --codex-run-as-apply-patch '*** Begin Patch\n*** Delete File: CASE.yaml\n*** End Patch\n'"),
    "the heredoc before the command": ("case", "<<'EOF' apply_patch\n*** Begin Patch\n*** Delete File: findings.json\n*** End Patch\nEOF\n"),
}  # fmt: skip
SHELL_ALLOWED = {
    "echo of a header": "echo '*** Delete File: findings.json'",
    "grep for the name": "grep apply_patch reports/draft.md",
    "which": "which apply_patch",
    "codex otherwise": "codex --version",
    "a heredoc body quoting a header": "cat <<'EOF' > work/notes.txt\n*** Delete File: findings.json\nEOF\n",
}


@pytest.mark.parametrize("label", sorted(SHELL_BLOCKED))
def test_apply_patch_through_the_shell_is_refused(box, label):  # noqa: F811
    root, cases, case, out = box
    where, text = SHELL_BLOCKED[label]
    r = shell(box, case if where == "case" else out, text.replace("{C}", str(case)))
    assert r.returncode == 2, (label, r.stderr)
    assert "apply_patch run through the shell" in r.stderr, r.stderr


@pytest.mark.parametrize("label", sorted(SHELL_ALLOWED))
def test_shell_text_that_only_names_a_header_passes(box, label):  # noqa: F811
    root, cases, case, out = box
    r = shell(box, case, SHELL_ALLOWED[label])
    assert r.returncode == 0, (label, r.stderr)


# --- the guard answers well inside its hook timeout ---------------------------
# Codex runs a call whose PreToolUse hook times out (10 s in requirements.toml).
# The guard ends itself at 5 s, and its wrapper then blocks: slow is refused.

WIDE = "*** Begin Patch\n*** Add File: a" + " " * 64_000 + "b\n+x\n*** End Patch\n"


def _timed(fn):
    t0 = time.monotonic()
    r = fn()
    return r, time.monotonic() - t0


def test_a_header_too_slow_to_read_is_refused_in_time_and_recorded_once(box):  # noqa: F811
    root, cases, case, out = box
    log = case / "audit" / "claude-code.jsonl"
    before = log.read_text().splitlines() if log.exists() else []
    r, took = _timed(lambda: patch(box, case, WIDE))
    assert r.returncode == 2 and took < 9.5, (r.stderr, took)
    after = log.read_text().splitlines() if log.exists() else []
    lines = [json.loads(x) for x in after[len(before) :]]
    assert [(x["event"], x["reason"]) for x in lines] == [
        ("refused", "parse timed out: the guard's check ran past 5 s")
    ], lines
    assert "couldn't check this command within 5 s" in r.stderr, r.stderr


STALLED = [
    ("block: rm", "Bash", {"command": "rm findings.json"}),
    ("block: apply_patch Delete", "apply_patch", {"command": body("*** Delete File: findings.json\n")}),
    ("unreadable", "Bash", {}),
    ("timed out", "apply_patch", {"command": WIDE}),
]  # fmt: skip


@pytest.mark.parametrize(
    "tool,tool_input", [r[1:] for r in STALLED], ids=[r[0] for r in STALLED]
)
def test_a_refusal_with_a_stalled_audit_file_is_still_refused_in_time(  # noqa: F811
    box, tool, tool_input
):
    """Every refusal's audit write (a block, an unreadable
    call, a timed-out check), to a FIFO no one reads, mustn't outlive the
    hook's timeout, which the client lets pass."""
    root, cases, case, out = box
    log = case / "audit" / "claude-code.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    if log.exists():
        log.unlink()
    os.mkfifo(log)
    payload = {"session_id": "s", "cwd": str(case), "hook_event_name": "PreToolUse",
               "tool_name": tool, "tool_input": tool_input, "tool_use_id": "t"}  # fmt: skip
    # past the deadline, a reader frees a stuck writer, so a guard without
    # the fix fails on time here rather than hanging the test
    release = threading.Timer(
        12, lambda: os.close(os.open(log, os.O_RDONLY | os.O_NONBLOCK))
    )
    release.start()
    try:
        r, took = _timed(lambda: subprocess.run(
            ["bash", str(HOOK)], input=json.dumps(payload), capture_output=True, text=True, cwd=case,
            env={"HOME": str(root), "PATH": "/usr/bin:/bin", "VHIR_CASES_DIR": str(cases), "VHIR_CASE_DIR": str(case)}, timeout=30,
        ))  # fmt: skip
    finally:
        release.cancel()
    assert r.returncode == 2 and took < 9.5, (r.stderr, took)
    assert "BLOCKED" in r.stderr, r.stderr


def test_a_megabyte_token_is_answered_in_time(box):  # noqa: F811
    root, cases, case, out = box
    r, took = _timed(
        lambda: shell(box, case, "echo '" + "a" * 1_000_000 + "'", timeout=60)
    )
    assert r.returncode == 2 and took < 9.5, (r.stderr, took)


def test_a_plain_command_is_answered_at_once(box):  # noqa: F811
    root, cases, case, out = box
    r, took = _timed(lambda: shell(box, case, "echo hi"))
    assert r.returncode == 0 and took < 1, (r.stderr, took)


def test_a_deep_glob_gets_an_answer(box):  # noqa: F811
    """Not timed: a verdict either way, never a hang."""
    root, cases, case, out = box
    r = shell(box, case, "rm /*/*/*/*/*/zzz", timeout=60)
    assert r.returncode in (0, 2), r.stderr


def test_the_guard_ends_itself_before_its_hook_times_out():
    import re

    from .test_codex_requirements import _toml

    seconds = int(re.search(r"signal\.alarm\((\d+)\)", HOOK.read_text()).group(1))
    req = _toml((HOOK.parents[3] / "codex" / "requirements.toml").read_text())
    (guard,) = [h for x in req["hooks"]["PreToolUse"] for h in x["hooks"]
                if h["command"].endswith("/case-data-guard.sh")]  # fmt: skip
    assert seconds < guard["timeout"]
