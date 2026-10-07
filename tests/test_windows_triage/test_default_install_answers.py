"""windows-triage says what it checked, and EXPECTED only where it was earned.

- check_file says whether a hash was compared.
- check_service compares the service's executable, not just its name, and
  works without an OS version (every build is compared). A different
  executable is flagged; a default name outside the default paths is flagged
  when it is a common masquerade target; other in-box drivers, and anything
  it can't compare, read UNKNOWN.
- check_process_tree checks full-path names by their file names and still
  checks the paths; a process with no list of expected parents reads UNKNOWN.
- Name-only matches (tasks, autoruns, pipes) say what wasn't checked.

The baselines are small synthetic DBs built with the package's own writers,
plus the shipped process_expectations.yaml.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from windows_triage.config import Config
from windows_triage.db import ContextDB, KnownGoodDB
from windows_triage.importers.process_expectations import import_process_expectations
from windows_triage.server import WindowsTriageServer

W10 = "W10_21H2_Pro_20230321_19044.1"
SRV = "WindowsServer2022_21H2_Standard_20230321_20348.1"
SHA1_SETHC = "1" * 40
SHA256 = "a" * 64
S32 = "C:\\Windows\\System32\\"
YAML = (
    Path(__file__).parents[2]
    / "packages"
    / "windows-triage"
    / "data"
    / "process_expectations.yaml"
)

SERVICES = {  # name: (ImagePath in the baseline, builds)
    "Spooler": (r"%SystemRoot%\System32\spoolsv.exe", [W10, SRV]),
    "BITS": (r"%SystemRoot%\System32\svchost.exe -k netsvcs -p", [W10]),
    "WinDefend": (r'"%ProgramFiles%\Windows Defender\MsMpEng.exe"', [W10, SRV]),
    "NoPath": (None, [W10, SRV]),
    "mmcss": (r"%windir%\system32\svchost.exe -k netsvcs", [W10]),
    "msiserver": (r"%systemroot%\system32\msiexec /V", [W10, SRV]),
    "ACPI": (r"System32\drivers\ACPI.sys", [W10, SRV]),
    "FltX": (r"\??\C:\Windows\system32\drivers\fltx.sys", [W10, SRV]),
    "storflt": (r"System32\drivers\storflt.sys", [W10, SRV]),
}


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    root = tmp_path_factory.mktemp("baseline")
    kg = KnownGoodDB(root / "kg.db")
    kg.init_schema()
    kg.add_os_version(W10, "Windows 10")
    kg.add_os_version(SRV, "Windows Server 2022")
    files = [
        {"path": S32 + name, "sha256": SHA256}
        for name in (
            "spoolsv.exe",
            "svchost.exe",
            "cmd.exe",
            "nohash.exe",
            "msiexec.exe",
        )
    ]
    files += [
        {"path": S32 + "sethc.exe", "sha1": SHA1_SETHC, "sha256": SHA256},
        {"path": S32 + "drivers\\ACPI.sys"},
        {"path": S32 + "drivers\\mmcss.sys"},
        {"path": S32 + "drivers\\vmstorfl.sys"},
        {"path": "C:\\Program Files\\Windows Defender\\MsMpEng.exe"},
        {"path": "C:\\Windows\\SysWOW64\\spoolsv.exe"},
    ]
    for build in (W10, SRV):
        kg.upsert_files_batch(files, build)
    for name, (image_path, builds) in SERVICES.items():
        for build in builds:
            kg.upsert_service(name, build, binary_path=image_path)
    kg.upsert_task(
        r"\Microsoft\Windows\Defrag\ScheduledDefrag", W10, task_name="ScheduledDefrag"
    )
    kg.upsert_autorun(
        "HKLM",
        r"Microsoft\Windows\CurrentVersion\Run",
        W10,
        value_name="SecurityHealth",
        value_data_pattern=r"%windir%\system32\SecurityHealthSystray.exe",
        autorun_type="Run",
    )
    kg.connect().commit()
    kg.close()
    ctx = ContextDB(root / "ctx.db")
    ctx.init_schema()
    ctx.connect().commit()
    ctx.close()
    import_process_expectations(root / "ctx.db", YAML)
    config = Config(
        data_dir=root,
        known_good_db=root / "kg.db",
        context_db=root / "ctx.db",
        registry_db=root / "none.db",
        skip_db_validation=True,
        cache_size=0,
    )
    return WindowsTriageServer(config=config)


def run(coro):
    return asyncio.run(coro)


# check_file: whether a hash was compared


def test_a_matching_hash_says_so(srv):
    r = run(srv._check_file(S32 + "sethc.exe", SHA1_SETHC))
    assert r["hash_compared"] is True
    assert "Hash matches a baseline build of this file" in r["reasons"]


def test_a_hash_the_baseline_has_no_algorithm_for_is_not_compared(srv):
    r = run(srv._check_file(S32 + "nohash.exe", "3" * 40))
    assert r["hash_compared"] is False
    assert "Hash not compared: the baseline has no SHA1 for this path" in r["reasons"]


def test_no_hash_says_the_content_was_not_checked(srv):
    r = run(srv._check_file(S32 + "sethc.exe"))
    assert r["hash_compared"] is False
    assert "No hash supplied: path match only, content not checked" in r["reasons"]


def test_a_foreign_hash_is_still_suspicious(srv):
    assert run(srv._check_file(S32 + "sethc.exe", "4" * 40))["verdict"] == "SUSPICIOUS"


# check_service: name and executable


def svc(srv, name, image_path=None, os_version=None):
    return run(srv._check_service(name, image_path, os_version))


@pytest.mark.parametrize(
    "name, image_path",
    [
        ("BITS", S32 + "svchost.exe -k netsvcs -p"),
        ("BITS", r"%SystemRoot%\system32\svchost.exe -k netsvcs"),  # arguments differ
        ("msiserver", r"C:\Windows\system32\msiexec.exe /V"),  # no .exe in the baseline
        ("ACPI", r"\SystemRoot\System32\drivers\ACPI.sys"),  # vs a relative path
        ("FltX", r"\SystemRoot\System32\drivers\fltx.sys"),  # vs a \??\ pattern
        (
            "Spooler",
            r"C:\Windows\SysWOW64\spoolsv.exe",
        ),  # its file name, at a default path
    ],
    ids=["default", "arguments", "msiexec", "systemroot", "nt prefix", "syswow64"],
)
def test_a_default_service_with_its_default_executable_is_expected(
    srv, name, image_path
):
    r = svc(srv, name, image_path)
    assert (r["verdict"], r["confidence"]) == ("EXPECTED", "high")
    assert "arguments, ServiceDll and account not compared" in r["reasons"][0]


def test_an_os_version_is_optional_through_the_mcp_handler(srv):
    from mcp.types import CallToolRequest

    handler = srv.server.request_handlers[CallToolRequest]
    args = {"service_name": "BITS", "binary_path": S32 + "svchost.exe -k netsvcs -p"}
    reply = asyncio.run(
        handler(
            CallToolRequest(
                method="tools/call", params={"name": "check_service", "arguments": args}
            )
        )
    )
    assert json.loads(reply.root.content[0].text)["verdict"] == "EXPECTED"


@pytest.mark.parametrize(
    "name, image_path, cause",
    [
        ("Spooler", None, "no binary_path supplied"),
        ("NoPath", r"C:\Users\Public\evil.exe", "the baseline has no executable"),
        (
            "WinDefend",
            r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2211.5-0\MsMpEng.exe"',
            "default file name but is not at a default Windows path",
        ),
        ("ACPI", r"\Driver\ACPI", "driver object"),
        ("storflt", r"\SystemRoot\System32\drivers\vmstorfl.sys", "default Windows driver file"),
    ],
    ids=["no executable given", "baseline has none", "default name elsewhere", "driver object",
         "another default driver"],
)  # fmt: skip
def test_what_cant_be_compared_is_unknown_and_says_why(srv, name, image_path, cause):
    r = svc(srv, name, image_path)
    assert (r["verdict"], r["confidence"]) == ("UNKNOWN", "low")
    assert cause in r["reasons"][0]


@pytest.mark.parametrize(
    "name, image_path, os_version",
    [
        ("Spooler", r"C:\ProgramData\x.exe", None),
        ("Spooler", r"C:\ProgramData\x.exe", "W10"),
        (
            "Spooler",
            r"C:\Windows\System32\cmd.exe /c evil",
            None,
        ),  # a default file, not its own
        (
            "Spooler",
            r"C:\Users\Public\spoolsv.exe",
            None,
        ),  # a masquerade target moved out
        (
            "storflt",
            r"\SystemRoot\System32\drivers\evil.sys",
            None,
        ),  # not a default driver file
    ],
    ids=[
        "other file",
        "other file, one build",
        "cmd.exe",
        "spoolsv.exe moved",
        "unknown driver",
    ],
)
def test_a_default_service_with_another_executable_is_flagged(
    srv, name, image_path, os_version
):
    r = svc(srv, name, image_path, os_version)
    assert (r["verdict"], r["confidence"]) == ("SUSPICIOUS", "medium")
    assert "spoolsv.exe" in r["reasons"][0] or name != "Spooler"


# check_process_tree


def tree(srv, child, parent, path=None):
    return run(srv._check_process_tree(child, parent, path))


@pytest.mark.parametrize(
    "child, parent",
    [
        ("cmd.exe", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
        ("cmd.exe", r"C:\Windows\System32\lsass.exe"),
        (r"C:\Windows\System32\svchost.exe", r"C:\Windows\explorer.exe"),
    ],
    ids=["shell under word", "child of lsass", "svchost under explorer"],
)
def test_full_path_names_still_meet_the_parent_rules(srv, child, parent):
    assert tree(srv, child, parent)["verdict"] == "SUSPICIOUS"


@pytest.mark.parametrize(
    "child, parent",
    [
        (r"C:\Users\Public\svchost.exe", "services.exe"),
        (r"C:\Temp\lsass.exe", "wininit.exe"),
        ("svchost.exe", r"C:\Users\Public\services.exe"),
    ],
    ids=["child outside its path", "lsass outside its path", "parent outside its path"],
)
def test_a_full_path_outside_the_expected_paths_is_flagged(srv, child, parent):
    r = tree(srv, child, parent)
    assert r["verdict"] == "SUSPICIOUS"


@pytest.mark.parametrize(
    "child, parent",
    [("cmd.exe", "w3wp.exe"), ("cmd.exe", "services.exe"), ("system", "cmd.exe")],
)
def test_a_process_with_no_list_of_expected_parents_is_unknown(srv, child, parent):
    r = tree(srv, child, parent)
    assert (r["verdict"], r["confidence"]) == ("UNKNOWN", "low")
    assert "No list of expected parents" in r["reasons"][-1]


@pytest.mark.parametrize(
    "child, parent, path, verdict",
    [
        ("svchost.exe", "services.exe", None, "EXPECTED"),
        ("cmd.exe", "winword.exe", None, "SUSPICIOUS"),
        ("notepad.exe", "explorer.exe", None, "UNKNOWN"),
        ("svchost.exe", "services.exe", r"C:\Users\Public\svchost.exe", "SUSPICIOUS"),
    ],
    ids=[
        "svchost",
        "shell under word",
        "unknown process",
        "bad path",
    ],
)
def test_other_trees_read_as_before(srv, child, parent, path, verdict):
    assert tree(srv, child, parent, path)["verdict"] == verdict


def test_a_valid_tree_given_as_full_paths_is_expected(srv):
    r = tree(
        srv, r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\services.exe"
    )
    assert r["verdict"] == "EXPECTED"


def test_a_service_hijack_checked_against_one_build_is_flagged_as_before(srv):
    assert (
        svc(srv, "Spooler", r"C:\ProgramData\x.exe", "W10")["verdict"] == "SUSPICIOUS"
    )


# Name-only matches say what wasn't checked


def test_a_task_says_its_action_was_not_checked(srv):
    r = run(
        srv._check_scheduled_task(r"\Microsoft\Windows\Defrag\ScheduledDefrag", "W10")
    )
    assert r["verdict"] == "EXPECTED"
    assert r["reasons"] == [
        "Task path is a default Windows task; its action (command and arguments) is not in the "
        "baseline and was not checked"
    ]


@pytest.mark.parametrize(
    "value_name, reason",
    [
        ("SecurityHealth", "the value data (what it runs) was not compared"),
        (None, "Key path matches a default Windows autorun key; no value was checked"),
    ],
)
def test_an_autorun_says_its_data_was_not_compared(srv, value_name, reason):
    r = run(
        srv._check_autorun(r"Microsoft\Windows\CurrentVersion\Run", value_name, "W10")
    )
    assert r["verdict"] == "EXPECTED" and reason in r["reasons"][0]


def test_a_pipe_says_its_server_was_not_checked(srv):
    r = run(srv._check_pipe("lsass"))
    assert r["verdict"] == "EXPECTED"
    assert r["reasons"] == [
        "Name matches a default Windows pipe; the process serving it was not checked"
    ]


# What the AI is told

ROOT = Path(__file__).parents[2]


def test_windows_triage_is_described_as_a_default_install_check():
    for ref in (
        "claude-code/full/TOOL_REFERENCE.md",
        "claude-code/lite/TOOL_REFERENCE.md",
    ):
        text = (ROOT / ref).read_text()
        section = text.split("### windows-triage", 1)[1].split("###", 1)[0]
        assert "is this legitimate" not in section.replace(
            'not "is this legitimate?"', ""
        )
        assert "default Windows install" in section
    from sift_common import instructions

    every = "".join(getattr(instructions, n) for n in dir(instructions) if n.isupper())
    assert "Use windows-triage to validate" not in every
    assert "default install" in instructions.WINDOWS_TRIAGE
    assert "UNKNOWN" in instructions.WINDOWS_TRIAGE
    assert (
        "Validate files, processes, services against Windows baselines"
        not in (ROOT / "docs/librechat-setup.md").read_text()
    )


# Where an ImagePath's executable ends


@pytest.mark.parametrize(
    "image_path, executable",
    [
        (
            r"C:\Windows\System32\spoolsv.exe.evil.exe",
            r"\windows\system32\spoolsv.exe.evil.exe",
        ),
        (r"C:\Program Files\Acme\svc.exe -k netsvcs", r"\program files\acme\svc.exe"),
        (r'"C:\Program Files\Acme\svc.exe" -run', r"\program files\acme\svc.exe"),
        (
            r"\SystemRoot\System32\drivers\ACPI.sys",
            r"\windows\system32\drivers\acpi.sys",
        ),
    ],
    ids=[
        "a second extension",
        "unquoted with arguments",
        "quoted with arguments",
        "a driver",
    ],
)
def test_an_executable_ends_where_its_token_ends(image_path, executable):
    from windows_triage.analysis.paths import parse_service_binary_path

    assert parse_service_binary_path(image_path).lower().endswith(executable)


def test_a_default_name_with_a_second_extension_is_flagged(srv):
    r = svc(srv, "Spooler", r"C:\Windows\System32\spoolsv.exe.evil.exe")
    assert r["verdict"] == "SUSPICIOUS"


def test_a_bare_name_in_capitals_is_not_a_path(srv):
    assert tree(srv, "SVCHOST.EXE", "SERVICES.EXE")["verdict"] == "EXPECTED"
