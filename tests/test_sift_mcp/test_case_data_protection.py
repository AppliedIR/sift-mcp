"""run_command refuses to delete or overwrite case records, audit/ and evidence files."""

import os
from unittest.mock import patch

import pytest
from sift_mcp.catalog import clear_catalog_cache
from sift_mcp.tools.generic import run_command


@pytest.fixture
def tree(tmp_path, monkeypatch):
    clear_catalog_cache()
    home = tmp_path / "home"
    cases = home / "cases"
    case = cases / "INC-1"
    for d in ("audit", "evidence", "reports", "DELETE", "extractions"):
        (case / d).mkdir(parents=True)
    for name, text in {
        "CASE.yaml": "case_id: INC-1\n",
        "findings.json": "[]\n",
        "timeline.json": "[]\n",
        "approvals.jsonl": "{}\n",
        "notes.txt": "n\n",
        "audit/sift-mcp.jsonl": "{}\n",
        "evidence/disk.E01": "e",
        "reports/draft.md": "d\n",
        "extractions/a.csv": "a\n",
    }.items():
        (case / name).write_text(text)
    for name in ("findings.json", "timeline.json"):
        os.chmod(case / name, 0o444)  # as forensic-mcp leaves them
    work = home / "work"
    (work / "restore").mkdir(parents=True)
    (work / "restore" / "findings.json").write_text("x\n")
    (work / "findings.json").write_text("x\n")
    (work / "new.E01").write_text("n")
    other = home / "elsewhere" / "INC-9"  # a case kept outside the cases dir
    other.mkdir(parents=True)
    (other / "CASE.yaml").write_text("case_id: INC-9\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_CASES_DIR", str(cases))
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    yield {"H": str(home), "S": str(cases), "C": str(case), "W": str(work)}
    clear_catalog_cache()


def _verdict(argv):
    ran = []

    def fake(cmd, **kw):
        ran.append(cmd)
        return {"exit_code": 0, "stdout": "", "stderr": "", "stdout_total_bytes": 0}

    with (
        patch(
            "sift_mcp.tools.generic.find_binary", side_effect=lambda b: "/usr/bin/" + b
        ),
        patch("sift_mcp.tools.generic.execute", side_effect=fake),
    ):
        try:
            run_command(argv)
        except ValueError:
            assert not ran
            return "refused"
    assert ran
    return "allowed"


REFUSED = [
    ("rm of the home dir above the cases dir", ["rm", "-rf", "{H}"]),
    ("rm of a dir above the cases dir, spelled with ..", ["rm", "-rf", "{C}/../../.."]),
    ("moving a finding record into DELETE", ["mv", "{C}/findings.json", "{C}/DELETE/"]),
    (
        "moving an audit log into DELETE",
        ["mv", "{C}/audit/sift-mcp.jsonl", "{C}/DELETE/"],
    ),
    (
        "moving an evidence file into DELETE",
        ["mv", "{C}/evidence/disk.E01", "{C}/DELETE/"],
    ),
    (
        "moving a record out with a target-directory option",
        ["mv", "--target-directory={W}", "{C}/findings.json"],
    ),
    (
        "a record as the second of several mv sources",
        ["mv", "{C}/notes.txt", "{C}/findings.json", "{C}/DELETE/"],
    ),
    ("moving a file over a record", ["mv", "{W}/findings.json", "{C}/timeline.json"]),
    ("moving a whole case away", ["mv", "{C}", "{W}/x"]),
    ("moving the cases dir away", ["mv", "{S}", "{W}/x"]),
    ("moving the home dir above the cases dir", ["mv", "{H}", "{W}/x"]),
    ("copying over a record", ["cp", "-f", "{W}/findings.json", "{C}/findings.json"]),
    (
        "copying a same-named file into the case root",
        ["cp", "-f", "{W}/findings.json", "{C}/"],
    ),
    (
        "copying into the case root with -t",
        ["cp", "-f", "-t", "{C}/", "{W}/findings.json"],
    ),
    ("copying a tree onto a case with -T", ["cp", "-rfT", "{W}/restore", "{C}"]),
    (
        "copying over an existing evidence file",
        ["cp", "-f", "{W}/new.E01", "{C}/evidence/disk.E01"],
    ),
    ("tee appending to an audit log", ["tee", "-a", "{C}/audit/sift-mcp.jsonl"]),
    ("tee over a record", ["tee", "{C}/approvals.jsonl"]),
    ("truncate of a record", ["truncate", "-s", "0", "{C}/approvals.jsonl"]),
    ("shred of a record", ["shred", "-fu", "{C}/findings.json"]),
    ("unlink of a record", ["unlink", "{C}/findings.json"]),
    (
        "a symlink over a record",
        ["ln", "-sf", "{W}/findings.json", "{C}/findings.json"],
    ),
    ("install over a record", ["install", "{W}/findings.json", "{C}/timeline.json"]),
    ("rm of a record under nice", ["nice", "-n", "5", "rm", "-f", "{C}/findings.json"]),
    ("rm of a record under timeout", ["timeout", "5", "rm", "-f", "{C}/findings.json"]),
    (
        "rm of evidence under stdbuf",
        ["stdbuf", "-o0", "rm", "-f", "{C}/evidence/disk.E01"],
    ),
    (
        "rm of a record under sudo -u",
        ["sudo", "-u", "root", "rm", "-f", "{C}/findings.json"],
    ),
    ("rm of a record under nohup", ["nohup", "rm", "-f", "{C}/findings.json"]),
    ("rm of a record under time", ["time", "rm", "-f", "{C}/findings.json"]),
]

ALLOWED = [
    ("moving notes into DELETE", ["mv", "{C}/notes.txt", "{C}/DELETE/"]),
    (
        "moving a report draft into DELETE",
        ["mv", "{C}/reports/draft.md", "{C}/DELETE/"],
    ),
    ("filing new evidence by cp", ["cp", "{W}/new.E01", "{C}/evidence/"]),
    ("filing new evidence by mv", ["mv", "{W}/new.E01", "{C}/evidence/"]),
    (
        "filing new evidence under a new name",
        ["cp", "{W}/new.E01", "{C}/evidence/new2.E01"],
    ),
    ("tee into a new evidence file", ["tee", "{C}/evidence/notes.txt"]),
    ("tee into extractions", ["tee", "{C}/extractions/out.txt"]),
    ("copying a record out to read it", ["cp", "{C}/findings.json", "{W}/copy.json"]),
    ("copying evidence out", ["cp", "{C}/evidence/disk.E01", "{W}/"]),
    (
        "hashing a record and evidence",
        ["sha256sum", "{C}/findings.json", "{C}/evidence/disk.E01"],
    ),
    ("grep for rm in a record", ["grep", "rm", "{C}/findings.json"]),
    (
        "a forensic parser writing into extractions",
        ["MFTECmd", "-f", "{C}/evidence/disk.E01", "--csv", "{C}/extractions/"],
    ),
    ("fls under timeout", ["timeout", "30", "fls", "-r", "{C}/evidence/disk.E01"]),
    (
        "renaming inside extractions",
        ["mv", "{C}/extractions/a.csv", "{C}/extractions/b.csv"],
    ),
    ("truncating an extraction", ["truncate", "-s", "0", "{C}/extractions/a.csv"]),
    ("copying a new file into the case root", ["cp", "{W}/new.E01", "{C}/"]),
    ("rm outside the cases dir", ["rm", "-rf", "{W}"]),
    (
        "echo with a literal > is not a redirection",
        ["echo", "x", ">", "{C}/findings.json"],
    ),
]

STILL_REFUSED_BY_THE_RM_RULE = [
    ("rm of a report draft", ["rm", "{C}/reports/draft.md"]),
    ("rm of notes in a case", ["rm", "-f", "{C}/notes.txt"]),
]


def _fmt(argv, t):
    return [a.format(**t) for a in argv]


@pytest.mark.parametrize("argv", [r[1] for r in REFUSED], ids=[r[0] for r in REFUSED])
def test_refused(tree, argv):
    assert _verdict(_fmt(argv, tree)) == "refused"


@pytest.mark.parametrize("argv", [r[1] for r in ALLOWED], ids=[r[0] for r in ALLOWED])
def test_allowed(tree, argv):
    assert _verdict(_fmt(argv, tree)) == "allowed"


@pytest.mark.parametrize(
    "argv",
    [r[1] for r in STILL_REFUSED_BY_THE_RM_RULE],
    ids=[r[0] for r in STILL_REFUSED_BY_THE_RM_RULE],
)
def test_rm_rule_is_unchanged(tree, argv):
    assert _verdict(_fmt(argv, tree)) == "refused"


def test_moving_a_record_into_delete_leaves_it_in_place(tree):
    with pytest.raises(ValueError, match="case data"):
        run_command(["mv", f"{tree['C']}/findings.json", f"{tree['C']}/DELETE/"])
    assert os.path.isfile(f"{tree['C']}/findings.json")


def test_moving_notes_into_delete_really_moves_them(tree):
    result = run_command(["mv", f"{tree['C']}/notes.txt", f"{tree['C']}/DELETE/"])
    assert result["exit_code"] == 0
    assert os.path.isfile(f"{tree['C']}/DELETE/notes.txt")


def test_rm_of_the_dir_holding_an_active_case_kept_elsewhere_is_refused(
    tree, monkeypatch
):
    monkeypatch.setenv("VHIR_CASE_DIR", f"{tree['H']}/elsewhere/INC-9")
    assert _verdict(["rm", "-rf", f"{tree['H']}/elsewhere"]) == "refused"


def test_a_relative_record_path_from_inside_the_case_is_refused(tree, monkeypatch):
    monkeypatch.chdir(tree["C"])
    assert _verdict(["mv", "findings.json", "DELETE/"]) == "refused"
