"""Codex's apply_patch is checked by the case-data guard as Claude Code's Edit
deny checks an edit: a patch that adds, updates, deletes or moves onto a case
record, an audit log or an evidence file is refused (exit 2, a "refused" line
in the case's audit), by the paths its headers name. The patch's lines are
never read as shell, so a context line like ` rm audit/x` refuses nothing."""

import json
import subprocess

import pytest

from .test_case_data_guard import HOOK, box  # noqa: F401


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
