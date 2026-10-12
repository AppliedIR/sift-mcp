r"""A shadow-copy or local admin-share path is not the live path: check_file keeps its verdict and
names the outermost prefix as given (never a path taken from the input); check_process_tree and
check_service answer as before. A path with an 8.3 short folder that could be a default place keeps
its verdict, at MEDIUM at most, and says so. Rows go through the MCP call_tool handler, on the
fixture of test_process_tree_checks."""

from __future__ import annotations

import pytest
from windows_triage.server import MACHINE_ACCOUNT_NOT_JUDGED

from .test_process_tree_checks import CF, PT, answer, check, label, srv  # noqa: F401

SV = "check_service"
REL_OK = "Process relationship matches expectations"
SHORT_REASON = (
    "An 8.3 short name can stand for several long paths; pass the long path to check it"
)
SC3 = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3"
LH = "\\\\localhost\\C$"
SVC = "\\Windows\\System32\\svchost.exe"
MSMP = "\\Windows Defender\\MsMpEng.exe"


def wrong_place(name):
    return [
        "Critical filename issues detected",
        f"Protected process {name} in unexpected path",
    ]


def wraps(inner):
    return f", and it wraps a {inner} path" if inner else ""


def shadow(prefix, inner=None):
    return (
        f"The path is inside a shadow copy ({prefix}), not a live system location{wraps(inner)};"
        " to judge the file itself, pass its path on the volume's drive letter (e.g. C:\\…)"
    )


def share(prefix, inner=None, admin=""):
    return (
        f"The path is given through the local admin share ({prefix}), not as a local drive path{wraps(inner)};"
        f" to judge the file itself, pass its drive-letter path{admin}"
    )


def kept(name, *reasons):
    return dict(verdict="SUSPICIOUS", confidence="high", finding_types=["protected_process_wrong_path"],
                path_in_baseline=False, reasons=[*wrong_place(name), *reasons])  # fmt: skip


FILE_SHORT = dict(verdict="SUSPICIOUS", confidence="medium", finding_types=["protected_process_wrong_path"],
                  reasons=[*wrong_place("msmpeng.exe"), SHORT_REASON])  # fmt: skip
TREE_SHORT = dict(verdict="SUSPICIOUS", confidence="medium", finding_types=["unexpected_path"],
                  reasons=["Unexpected executable path", SHORT_REASON])  # fmt: skip
PROTECTED_WRONG = dict(
    verdict="SUSPICIOUS",
    confidence="high",
    finding_types=["protected_process_wrong_path"],
)
WRONG_PATH = dict(verdict="SUSPICIOUS", confidence="high", reasons=["Unexpected executable path"],
                  finding_types=["unexpected_path"])  # fmt: skip

# fmt: off
ORIGIN = [
    (CF, {'path': SC3 + SVC}, kept('svchost.exe', shadow(SC3))),
    (CF, {'path': '\\Device\\HarddiskVolumeShadowCopy3\\Windows\\System32\\cmd.exe'},
     kept('cmd.exe', shadow('\\Device\\HarddiskVolumeShadowCopy3'))),
    (CF, {'path': '//?/GLOBALROOT/Device/HarddiskVolumeShadowCopy3/Windows/System32/svchost.exe'},
     kept('svchost.exe', shadow('//?/GLOBALROOT/Device/HarddiskVolumeShadowCopy3'))),
    (CF, {'path': SC3 + '\\Windows\\System32\\rundll32.exe'},
     dict(verdict='SUSPICIOUS', confidence='medium', finding_types=[], is_lolbin=True,
          reasons=['System binary in unexpected directory (masquerade indicator)', shadow(SC3)])),
    (CF, {'path': SC3 + SVC, 'hash': 'aa' * 32},  # the right hash in a snapshot: still not the live path
     kept('svchost.exe', 'Hash not compared: the baseline has no SHA256 for this path', shadow(SC3))),
    (CF, {'path': LH + SVC}, kept('svchost.exe', share(LH))),
    (CF, {'path': '\\\\127.0.0.1\\d$' + SVC}, kept('svchost.exe', share('\\\\127.0.0.1\\d$'))),
    (CF, {'path': '\\\\localhost\\ADMIN$\\System32\\cmd.exe'},
     kept('cmd.exe', share('\\\\localhost\\ADMIN$', admin=' (ADMIN$ is %SystemRoot%)'))),
    # a wrapped form: the outermost prefix, and what it wraps; never a path from the input
    (CF, {'path': LH + '\\Device\\HarddiskVolume3' + SVC}, kept('svchost.exe', share(LH, 'volume'))),
    (CF, {'path': LH + '\\Volume{3f2504e0-4f89-11d3-9a0c-0305e82c3301}' + SVC}, kept('svchost.exe', share(LH, 'volume'))),
    (CF, {'path': LH + '\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3' + SVC},
     kept('svchost.exe', share(LH, 'shadow copy'))),
    (CF, {'path': SC3 + '\\Device\\HarddiskVolume3' + SVC}, kept('svchost.exe', shadow(SC3, 'volume'))),
    # another machine, another share, or no anchor: no origin reason
    (CF, {'path': '\\\\fileserver\\C$' + SVC}, dict(PROTECTED_WRONG, reasons=wrong_place('svchost.exe'))),
    (CF, {'path': 'GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3' + SVC},
     dict(PROTECTED_WRONG, reasons=wrong_place('svchost.exe'))),
    (CF, {'path': '\\Device\\HarddiskVolumeShadowCopy3x' + SVC}, dict(PROTECTED_WRONG, reasons=wrong_place('svchost.exe'))),
    (CF, {'path': LH + '\\Users\\x\\Device\\HarddiskVolume3' + SVC},
     dict(PROTECTED_WRONG, reasons=[*wrong_place('svchost.exe'), share(LH)])),
    (CF, {'path': '\\\\notlocalhost\\C$' + SVC}, dict(PROTECTED_WRONG, reasons=wrong_place('svchost.exe'))),
    (CF, {'path': '\\\\?\\GLOBALROOT\\Device\\HarddisKVolumeShadowCopy3' + SVC},
     dict(PROTECTED_WRONG, reasons=wrong_place('svchost.exe'))),
    (CF, {'path': '\\Device\\HarddiskVolumeShadowCopy٣' + SVC}, dict(PROTECTED_WRONG, reasons=wrong_place('svchost.exe'))),
]
WHERE_IT_RUNS = [
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'path': SC3 + SVC}, WRONG_PATH),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'path': LH + SVC}, WRONG_PATH),
    (PT, {'process_name': '\\\\?\\UNC\\localhost\\C$' + SVC, 'parent_name': 'services.exe'}, WRONG_PATH),
    (PT, {'process_name': 'svchost.exe', 'parent_name': SC3 + '\\Windows\\System32\\services.exe'},
     dict(verdict='SUSPICIOUS', confidence='high', finding_types=['unexpected_parent_path'])),
    (SV, {'service_name': 'Spooler', 'binary_path': SC3 + '\\Windows\\System32\\spoolsv.exe'},
     dict(verdict='SUSPICIOUS', confidence='medium')),
    (SV, {'service_name': 'Spooler', 'binary_path': LH + '\\Windows\\System32\\spoolsv.exe'},
     dict(verdict='SUSPICIOUS', confidence='medium')),
]
SHORT = [
    # the verdict stands, confidence at MEDIUM at most, and the reason says why
    (CF, {'path': 'C:\\PROGRA~1' + MSMP}, FILE_SHORT),  # was SUSPICIOUS/high
    (CF, {'path': 'C:\\PROGRA~3\\MICROS~1\\WINDOW~1\\Platform\\4.18.24090.11-0\\MsMpEng.exe'}, FILE_SHORT),  # was SUSPICIOUS/high
    (CF, {'path': 'C:\\PR3B4F~1' + MSMP}, FILE_SHORT),  # was SUSPICIOUS/high
    (CF, {'path': 'C:\\PROGRA~9' + MSMP}, FILE_SHORT),  # a folder anyone can name so: never milder than SUSPICIOUS
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'path': 'C:\\PROGRA~1' + MSMP}, TREE_SHORT),  # was SUSPICIOUS/high
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'path': 'C:\\PROGRA~9' + MSMP}, TREE_SHORT),  # was SUSPICIOUS/high
    (PT, {'process_name': 'nissrv.exe', 'parent_name': 'services.exe',
          'path': 'C:\\PROGRA~3\\MICROS~1\\WINDOW~1\\Platform\\4.18.24090.11-0\\NisSrv.exe'}, TREE_SHORT),  # was SUSPICIOUS/high
    (PT, {'process_name': 'mpcmdrun.exe', 'parent_name': 'C:\\PROGRA~1' + MSMP},
     dict(verdict='SUSPICIOUS', confidence='medium', finding_types=['unexpected_parent_path'],
          reasons=['Parent msmpeng.exe is not at an expected path', SHORT_REASON])),
    # a certain non-path finding (the parent) keeps its confidence: only path uncertainty is weakened
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'cmd.exe', 'path': 'C:\\PROGRA~1' + MSMP},
     dict(verdict='SUSPICIOUS', confidence='high', finding_types=['unexpected_parent', 'unexpected_path'],
          reasons=['Unexpected parent process', SHORT_REASON])),
    # no long name the short one can stand for makes it a default place: as before, no reason
    (CF, {'path': 'C:\\Windows\\WinSxS\\AMD64_~1\\svchost.exe'}, dict(PROTECTED_WRONG, reasons=wrong_place('svchost.exe'))),
    (CF, {'path': 'C:\\PROGRA~123456' + MSMP}, dict(PROTECTED_WRONG, reasons=wrong_place('msmpeng.exe'))),
    (CF, {'path': 'C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\svchost.exe'}, PROTECTED_WRONG),
    (CF, {'path': 'C:\\WINDOW~1\\System32\\svchost.exe'}, PROTECTED_WRONG),
    (CF, {'path': 'C:\\PROGRA~1\\evil\\MsMpEng.exe'}, PROTECTED_WRONG),
    (CF, {'path': 'C:\\PROGRA~3\\MICROS~1\\WINDOW~1\\Platform\\..\\MsMpEng.exe'}, PROTECTED_WRONG),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe',
          'path': 'C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\svchost.exe'}, WRONG_PATH),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'path': 'C:\\WINDOW~1\\System32\\svchost.exe'},
     WRONG_PATH),
]
# fmt: on


def _label(row):
    return label(row) if row[0] != SV else row[1]["binary_path"]


@pytest.mark.parametrize("row", ORIGIN, ids=[_label(r) for r in ORIGIN])
def test_a_shadow_copy_or_admin_share_path_keeps_its_verdict_and_says_what_it_is(
    srv, row
):  # noqa: F811
    check(srv, *row)


@pytest.mark.parametrize("row", WHERE_IT_RUNS, ids=[_label(r) for r in WHERE_IT_RUNS])
def test_a_program_run_from_a_shadow_copy_or_a_share_is_not_at_its_default_place(
    srv, row
):  # noqa: F811
    check(srv, *row)


@pytest.mark.parametrize("row", SHORT, ids=[_label(r) for r in SHORT])
def test_an_8_3_path_keeps_its_verdict_at_medium_when_it_could_be_the_default_place(
    srv, row
):  # noqa: F811
    check(srv, *row)


# Lands with whichever of process-tree-followons and normalize-path merges second.
NEITHER = [
    (
        ("services.exe", "C:\\PROGRA~1" + MSMP),  # nothing checked supports the verdict
        dict(
            verdict="SUSPICIOUS",
            confidence="low",
            finding_types=["unexpected_path"],
            user_valid=None,
            reasons=[
                "Unexpected executable path",
                MACHINE_ACCOUNT_NOT_JUDGED,
                SHORT_REASON,
            ],
        ),
    ),
    (
        (
            "cmd.exe",
            "C:\\PROGRA~1" + MSMP,
        ),  # a wrong parent is certain: its confidence stands
        dict(
            verdict="SUSPICIOUS",
            confidence="high",
            finding_types=["unexpected_parent", "unexpected_path"],
            user_valid=None,
            reasons=[
                "Unexpected parent process",
                MACHINE_ACCOUNT_NOT_JUDGED,
                SHORT_REASON,
            ],
        ),
    ),
    (
        (
            "services.exe",
            "C:\\Program Files" + MSMP,
        ),  # the path was checked: the account rule alone (MEDIUM)
        dict(
            verdict="EXPECTED",
            confidence="medium",
            user_valid=None,
            reasons=[REL_OK, MACHINE_ACCOUNT_NOT_JUDGED],
        ),
    ),
]


@pytest.mark.parametrize(
    "pp,expected", NEITHER, ids=[f"{p} {q}" for (p, q), _ in NEITHER]
)
def test_low_only_when_nothing_checked_supports_the_verdict(srv, pp, expected):  # noqa: F811
    check(
        srv,
        PT,
        dict(
            process_name="msmpeng.exe",
            parent_name=pp[0],
            path=pp[1],
            user="CONTOSO\\WKS01$",
        ),
        expected,
    )


# A baseline that also holds svchost.exe in a WinSxS folder: a protected name is read against
# its valid_paths only, so an 8.3 folder that could be that WinSxS folder changes nothing
SXS = (
    "C:\\Windows\\WinSxS\\amd64_microsoft-windows-services-svchost_31bf3856ad364e35"
    "_10.0.19041.1_none_1a2b3c4d5e6f7a8b\\svchost.exe"
)


@pytest.fixture(scope="module")
def srv_sxs(tmp_path_factory):
    from windows_triage.config import Config
    from windows_triage.db import ContextDB, KnownGoodDB
    from windows_triage.importers.process_expectations import (
        import_process_expectations,
    )
    from windows_triage.server import WindowsTriageServer

    from .test_process_tree_checks import BASELINE_FILES, W10, YAML

    root = tmp_path_factory.mktemp("triage-sxs")
    kg = KnownGoodDB(root / "known_good.db", read_only=False)
    kg.init_schema()
    kg.add_os_version(
        W10, "Windows 10", "Pro", "22H2", "19045", "x64", "FileHashes.csv"
    )
    files = [
        {"path": p, "md5": None, "sha1": None, "sha256": "aa" * 32, "file_size": 1}
        for p in [*BASELINE_FILES, SXS]
    ]
    kg.upsert_files_batch(files, W10, "FileHashes.csv")
    kg.connect().commit()
    kg.close()
    ctx = ContextDB(root / "context.db", read_only=False)
    ctx.init_schema()
    ctx.close()
    import_process_expectations(db_path=root / "context.db", yaml_path=YAML)
    config = Config(data_dir=root, known_good_db=root / "known_good.db",
                    context_db=root / "context.db", registry_db=root / "absent_registry.db",
                    skip_db_validation=False, cache_size=0)  # fmt: skip
    return WindowsTriageServer(config=config)


@pytest.mark.parametrize(
    "path",
    [
        SXS,
        "C:\\Windows\\WinSxS\\AMD64_~1\\svchost.exe",
        "C:\\Windows\\WinSxS\\AMD64_~9\\svchost.exe",
    ],
    ids=["long", "AMD64_~1", "AMD64_~9"],
)
def test_a_protected_name_is_read_against_its_own_places_only(srv_sxs, path):
    check(
        srv_sxs,
        CF,
        {"path": path},
        dict(PROTECTED_WRONG, reasons=wrong_place("svchost.exe")),
    )
