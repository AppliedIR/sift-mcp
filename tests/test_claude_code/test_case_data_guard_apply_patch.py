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
}


def form(kind, v, update, add, delete, move_to):
    """`kind`'s patch in variant `v`, on these paths (Update and Move start from `update`)."""
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
    }.get(v, f"*** {word}: {path}")  # fmt: skip
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
