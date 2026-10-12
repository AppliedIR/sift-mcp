"""windows-triage judges accounts, wildcard paths, device paths and bare names.

- check_process_tree reads SYSTEM, LOCAL SERVICE and NETWORK SERVICE as a
  service account however they're written (with a domain, without the space,
  as LocalSystem, or as their SID), accepts the accounts a rule lists, and on
  a SYSTEM-only process gives LOCAL/NETWORK SERVICE one verdict in every form.
- Both tools match expected paths on normalised paths, where `*` is exactly
  one real folder.
- A device or volume form of a local path (\\?\C:\, \Device\HarddiskVolume3\,
  \VOLUME{...}\) is that path.
- A bare name says nothing about where the file is: its path isn't judged,
  its name still is.

Every row goes through the MCP call_tool handler, on small DBs built with the
package's own writers and importer, with the shipped process_expectations.yaml.
A row names the fields it pins; "was" marks an answer that changed.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from mcp.types import CallToolRequest, CallToolRequestParams
from windows_triage.config import Config
from windows_triage.db import ContextDB, KnownGoodDB
from windows_triage.importers.process_expectations import import_process_expectations
from windows_triage.server import WindowsTriageServer

YAML = (
    Path(__file__).parents[2]
    / "packages"
    / "windows-triage"
    / "data"
    / "process_expectations.yaml"
)
W10 = "W10_22H2_Pro_20230101_19045.0000"
BASELINE_FILES = [
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\SysWOW64\cmd.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\SysWOW64\svchost.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\rundll32.exe",
    r"C:\Windows\SysWOW64\rundll32.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Program Files\Windows Defender\MsMpEng.exe",
    r"C:\Program Files\Windows Defender\NisSrv.exe",
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\spoolsv.exe",
]


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    root = tmp_path_factory.mktemp("triage")
    kg = KnownGoodDB(root / "known_good.db", read_only=False)
    kg.init_schema()
    kg.add_os_version(
        W10, "Windows 10", "Pro", "22H2", "19045", "x64", "FileHashes.csv"
    )
    files = [
        {"path": p, "md5": None, "sha1": None, "sha256": "aa" * 32, "file_size": 1}
        for p in BASELINE_FILES
    ]
    kg.upsert_files_batch(files, W10, "FileHashes.csv")
    kg.upsert_service("Spooler", W10, binary_path=r"%SystemRoot%\System32\spoolsv.exe")
    kg.connect().commit()
    kg.close()
    ctx = ContextDB(root / "context.db", read_only=False)
    ctx.init_schema()
    ctx.add_lolbin(
        "powershell.exe", name="PowerShell", functions=["Execute", "Download"]
    )
    ctx.add_lolbin("rundll32.exe", name="Rundll32", functions=["Execute", "AWL Bypass"])
    ctx.close()
    import_process_expectations(db_path=root / "context.db", yaml_path=YAML)
    config = Config(
        data_dir=root,
        known_good_db=root / "known_good.db",
        context_db=root / "context.db",
        registry_db=root / "absent_registry.db",
        skip_db_validation=False,
        cache_size=0,
    )
    return WindowsTriageServer(config=config)


def answer(srv, tool: str, args: dict) -> dict:
    """The tool's answer through the MCP handler, in the fields the rows pin."""
    handler = srv.server.request_handlers[CallToolRequest]
    request = CallToolRequest(
        method="tools/call", params=CallToolRequestParams(name=tool, arguments=args)
    )
    reply = asyncio.run(handler(request))
    d = json.loads(reply.root.content[0].text)
    r = d.get("result", d)
    return {
        "verdict": r.get("verdict"),
        "confidence": r.get("confidence"),
        "reasons": r.get("reasons"),
        "finding_types": sorted(f.get("type") for f in r.get("findings") or []),
        "user_valid": (r.get("user_context") or {}).get("user_valid"),
        "path_in_baseline": r.get("path_in_baseline"),
        "is_lolbin": bool(r.get("is_lolbin")),
    }


def check(srv, tool, args, expected):
    got = answer(srv, tool, args)
    assert {k: got[k] for k in expected} == expected, got


def label(row) -> str:
    tool, args, _ = row
    if tool == CF:
        return args["path"]
    who = f" as {args['user']!r}" if "user" in args else ""
    where = f" at {args['path']}" if "path" in args else ""
    return f"{args['process_name']} <- {args['parent_name']}{who}{where}"


PT = "check_process_tree"
CF = "check_file"

UNEXPECTED_USER = dict(verdict="SUSPICIOUS", confidence="medium", reasons=["Unexpected user context"],
                       finding_types=["unexpected_user"], user_valid=False)  # fmt: skip
MATCHES = dict(verdict="EXPECTED", confidence="high", reasons=["Process relationship matches expectations"],
               finding_types=[])  # fmt: skip
MATCHES_USER = dict(MATCHES, user_valid=True)
BASELINE = dict(verdict="EXPECTED", confidence="high", path_in_baseline=True, finding_types=[],
                reasons=["Path matches Windows baseline",
                         "No hash supplied: path match only, content not checked"])  # fmt: skip
NO_DIR = dict(verdict="UNKNOWN", confidence="low", reasons=["No directory given: path not checked"],
              finding_types=[], path_in_baseline=False)  # fmt: skip
WRONG_PATH = dict(verdict="SUSPICIOUS", confidence="high", reasons=["Unexpected executable path"],
                  finding_types=["unexpected_path"])  # fmt: skip
PROTECTED_WRONG = dict(verdict="SUSPICIOUS", confidence="high",
                       finding_types=["protected_process_wrong_path"])  # fmt: skip

# fmt: off
ROWS_1 = [
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'NT AUTHORITY\\SYSTEM'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'nt authority\\system'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'NT AUTHORITY\\LOCAL SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'NT AUTHORITY\\NETWORK SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'S-1-5-18'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'NT-AUTORITÄT\\SYSTEM'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'runtimebroker.exe', 'parent_name': 'svchost.exe', 'user': 'NT AUTHORITY\\SYSTEM'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'sihost.exe', 'parent_name': 'svchost.exe', 'user': 'NT AUTHORITY\\SYSTEM'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'NT AUTHORITY\\SYSTEM '}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'S-1-5-19'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'S-1-5-20'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'LocalSystem'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'NT AUTHORITY\\NetworkService'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'CONTOSO\\alice'}, MATCHES_USER),
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'alice'}, MATCHES_USER),
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'WKS01\\Administrator'}, MATCHES_USER),
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'SYSTEM'}, UNEXPECTED_USER),
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe'}, {'verdict': 'EXPECTED', 'confidence': 'high', 'reasons': ['Process relationship matches expectations'], 'finding_types': []}),
    (PT, {'process_name': 'explorer.exe', 'parent_name': 'userinit.exe', 'user': 'CONTOSO\\WKS01$'}, dict(verdict='EXPECTED', confidence='high', finding_types=[])),
]
ROWS_2 = [
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'Window Manager\\DWM-1'}, MATCHES_USER),  # was SUSPICIOUS/medium
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'DWM-1'}, MATCHES_USER),  # was SUSPICIOUS/medium
    (PT, {'process_name': 'audiodg.exe', 'parent_name': 'svchost.exe', 'user': 'NT AUTHORITY\\LOCAL SERVICE'}, MATCHES_USER),  # was SUSPICIOUS/medium
    (PT, {'process_name': 'nissrv.exe', 'parent_name': 'services.exe', 'user': 'NT AUTHORITY\\LOCAL SERVICE'}, MATCHES_USER),  # was SUSPICIOUS/medium
    (PT, {'process_name': 'nissrv.exe', 'parent_name': 'services.exe', 'user': 'S-1-5-19'}, MATCHES_USER),  # was SUSPICIOUS/medium
    (PT, {'process_name': 'nissrv.exe', 'parent_name': 'services.exe', 'user': 'NT AUTHORITY\\LocalService'}, MATCHES_USER),  # was SUSPICIOUS/medium
    (PT, {'process_name': 'audiodg.exe', 'parent_name': 'svchost.exe', 'user': 'S-1-5-19'}, MATCHES_USER),  # was SUSPICIOUS/medium
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'Font Driver Host\\DWM-1'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsass.exe', 'parent_name': 'wininit.exe', 'user': 'S-1-5-18'}, MATCHES_USER),  # was SUSPICIOUS/medium
    (PT, {'process_name': 'nissrv.exe', 'parent_name': 'services.exe', 'user': 'NT AUTHORITY\\SYSTEM'}, MATCHES_USER),
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'CONTOSO\\DWM-1'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsass.exe', 'parent_name': 'wininit.exe', 'user': 'EVIL\\SYSTEM'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsass.exe', 'parent_name': 'wininit.exe', 'user': 'CONTOSO\\alice'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsass.exe', 'parent_name': 'wininit.exe', 'user': 'NT AUTHORITY\\SYSTEM'}, MATCHES_USER),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'user': 'CONTOSO\\alice'}, MATCHES_USER),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'user': 'NT AUTHORITY\\NETWORK SERVICE'}, MATCHES_USER),
    (PT, {'process_name': 'nissrv.exe', 'parent_name': 'services.exe', 'user': 'LOCAL SERVICE'}, MATCHES_USER),
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'CONTOSO\\alice'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsass.exe', 'parent_name': 'wininit.exe', 'user': 'NT-AUTORITÄT\\SYSTEM'}, dict(verdict='SUSPICIOUS', confidence='medium', finding_types=['unexpected_user'])),
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'Window Manager\\DWM-4'}, dict(verdict='SUSPICIOUS', confidence='medium', finding_types=['unexpected_user'])),
    (PT, {'process_name': 'lsass.exe', 'parent_name': 'wininit.exe', 'user': 'NT AUTHORITY\\LOCAL SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsass.exe', 'parent_name': 'wininit.exe', 'user': 'NT AUTHORITY\\NETWORK SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsass.exe', 'parent_name': 'wininit.exe', 'user': 'S-1-5-19'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsass.exe', 'parent_name': 'wininit.exe', 'user': 'S-1-5-20'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsass.exe', 'parent_name': 'wininit.exe', 'user': 'NT AUTHORITY\\LocalService'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsass.exe', 'parent_name': 'wininit.exe', 'user': 'LOCAL SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'lsass.exe', 'parent_name': 'wininit.exe', 'user': 'NETWORK SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'services.exe', 'parent_name': 'wininit.exe', 'user': 'NT AUTHORITY\\LOCAL SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'services.exe', 'parent_name': 'wininit.exe', 'user': 'NT AUTHORITY\\NETWORK SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'services.exe', 'parent_name': 'wininit.exe', 'user': 'S-1-5-19'}, UNEXPECTED_USER),
    (PT, {'process_name': 'services.exe', 'parent_name': 'wininit.exe', 'user': 'S-1-5-20'}, UNEXPECTED_USER),
    (PT, {'process_name': 'services.exe', 'parent_name': 'wininit.exe', 'user': 'NT AUTHORITY\\LocalService'}, UNEXPECTED_USER),
    (PT, {'process_name': 'services.exe', 'parent_name': 'wininit.exe', 'user': 'LOCAL SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'services.exe', 'parent_name': 'wininit.exe', 'user': 'NETWORK SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'csrss.exe', 'parent_name': 'smss.exe', 'user': 'NT AUTHORITY\\LOCAL SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'csrss.exe', 'parent_name': 'smss.exe', 'user': 'NT AUTHORITY\\NETWORK SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'csrss.exe', 'parent_name': 'smss.exe', 'user': 'S-1-5-19'}, UNEXPECTED_USER),
    (PT, {'process_name': 'csrss.exe', 'parent_name': 'smss.exe', 'user': 'S-1-5-20'}, UNEXPECTED_USER),
    (PT, {'process_name': 'csrss.exe', 'parent_name': 'smss.exe', 'user': 'NT AUTHORITY\\LocalService'}, UNEXPECTED_USER),
    (PT, {'process_name': 'csrss.exe', 'parent_name': 'smss.exe', 'user': 'LOCAL SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'csrss.exe', 'parent_name': 'smss.exe', 'user': 'NETWORK SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'wininit.exe', 'parent_name': 'smss.exe', 'user': 'NT AUTHORITY\\LOCAL SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'wininit.exe', 'parent_name': 'smss.exe', 'user': 'NT AUTHORITY\\NETWORK SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'wininit.exe', 'parent_name': 'smss.exe', 'user': 'S-1-5-19'}, UNEXPECTED_USER),
    (PT, {'process_name': 'wininit.exe', 'parent_name': 'smss.exe', 'user': 'S-1-5-20'}, UNEXPECTED_USER),
    (PT, {'process_name': 'wininit.exe', 'parent_name': 'smss.exe', 'user': 'NT AUTHORITY\\LocalService'}, UNEXPECTED_USER),
    (PT, {'process_name': 'wininit.exe', 'parent_name': 'smss.exe', 'user': 'LOCAL SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'wininit.exe', 'parent_name': 'smss.exe', 'user': 'NETWORK SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'lsaiso.exe', 'parent_name': 'wininit.exe', 'user': 'NT AUTHORITY\\LOCAL SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsaiso.exe', 'parent_name': 'wininit.exe', 'user': 'NT AUTHORITY\\NETWORK SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsaiso.exe', 'parent_name': 'wininit.exe', 'user': 'S-1-5-19'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsaiso.exe', 'parent_name': 'wininit.exe', 'user': 'S-1-5-20'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsaiso.exe', 'parent_name': 'wininit.exe', 'user': 'NT AUTHORITY\\LocalService'}, UNEXPECTED_USER),
    (PT, {'process_name': 'lsaiso.exe', 'parent_name': 'wininit.exe', 'user': 'LOCAL SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'lsaiso.exe', 'parent_name': 'wininit.exe', 'user': 'NETWORK SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'winlogon.exe', 'parent_name': 'smss.exe', 'user': 'NT AUTHORITY\\LOCAL SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'winlogon.exe', 'parent_name': 'smss.exe', 'user': 'NT AUTHORITY\\NETWORK SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'winlogon.exe', 'parent_name': 'smss.exe', 'user': 'S-1-5-19'}, UNEXPECTED_USER),
    (PT, {'process_name': 'winlogon.exe', 'parent_name': 'smss.exe', 'user': 'S-1-5-20'}, UNEXPECTED_USER),
    (PT, {'process_name': 'winlogon.exe', 'parent_name': 'smss.exe', 'user': 'NT AUTHORITY\\LocalService'}, UNEXPECTED_USER),
    (PT, {'process_name': 'winlogon.exe', 'parent_name': 'smss.exe', 'user': 'LOCAL SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'winlogon.exe', 'parent_name': 'smss.exe', 'user': 'NETWORK SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'spoolsv.exe', 'parent_name': 'services.exe', 'user': 'NT AUTHORITY\\LOCAL SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'spoolsv.exe', 'parent_name': 'services.exe', 'user': 'NT AUTHORITY\\NETWORK SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'spoolsv.exe', 'parent_name': 'services.exe', 'user': 'S-1-5-19'}, UNEXPECTED_USER),
    (PT, {'process_name': 'spoolsv.exe', 'parent_name': 'services.exe', 'user': 'S-1-5-20'}, UNEXPECTED_USER),
    (PT, {'process_name': 'spoolsv.exe', 'parent_name': 'services.exe', 'user': 'NT AUTHORITY\\LocalService'}, UNEXPECTED_USER),
    (PT, {'process_name': 'spoolsv.exe', 'parent_name': 'services.exe', 'user': 'LOCAL SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'spoolsv.exe', 'parent_name': 'services.exe', 'user': 'NETWORK SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'user': 'NT AUTHORITY\\LOCAL SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'user': 'NT AUTHORITY\\NETWORK SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'user': 'S-1-5-19'}, UNEXPECTED_USER),
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'user': 'S-1-5-20'}, UNEXPECTED_USER),
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'user': 'NT AUTHORITY\\LocalService'}, UNEXPECTED_USER),
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'user': 'LOCAL SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'user': 'NETWORK SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'NT AUTHORITY\\LOCAL SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'NT AUTHORITY\\NETWORK SERVICE'}, UNEXPECTED_USER),
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'S-1-5-19'}, UNEXPECTED_USER),
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'S-1-5-20'}, UNEXPECTED_USER),
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'NT AUTHORITY\\LocalService'}, UNEXPECTED_USER),
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'LOCAL SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
    (PT, {'process_name': 'dwm.exe', 'parent_name': 'winlogon.exe', 'user': 'NETWORK SERVICE'}, UNEXPECTED_USER),  # was EXPECTED/high
]
ROWS_3 = [
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'path': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe'}, MATCHES),  # was SUSPICIOUS/high
    (PT, {'process_name': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe', 'parent_name': 'services.exe'}, MATCHES),  # was SUSPICIOUS/high
    (PT, {'process_name': 'nissrv.exe', 'parent_name': 'services.exe', 'path': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\NisSrv.exe'}, MATCHES),  # was SUSPICIOUS/high
    (PT, {'process_name': 'mpcmdrun.exe', 'parent_name': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe'}, {'verdict': 'UNKNOWN', 'confidence': 'low', 'finding_types': [], 'reasons': ['Process not in expectations database (neutral)']}),  # was SUSPICIOUS/medium
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'path': 'C:\\Users\\Public\\MsMpEng.exe'}, WRONG_PATH),
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'path': 'C:\\Program Files\\Windows Defender\\MsMpEng.exe'}, MATCHES),
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'path': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\x\\..\\..\\..\\..\\Users\\Public\\MsMpEng.exe'}, WRONG_PATH),
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'path': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\evil\\MsMpEng.exe'}, WRONG_PATH),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'path': 'C:\\Windows\\System32\\svchost.exe'}, MATCHES),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'path': 'C:\\Windows\\Temp\\svchost.exe'}, WRONG_PATH),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'C:\\Users\\Public\\services.exe'}, {'verdict': 'SUSPICIOUS', 'confidence': 'high', 'finding_types': ['unexpected_parent_path']}),
    (PT, {'process_name': 'mpcmdrun.exe', 'parent_name': 'C:\\Users\\Public\\MsMpEng.exe'}, {'verdict': 'SUSPICIOUS', 'finding_types': ['unexpected_parent_path']}),
    (CF, {'path': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\x\\..\\..\\..\\..\\Users\\Public\\MsMpEng.exe'}, PROTECTED_WRONG),  # was UNKNOWN/low
    (CF, {'path': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\evil\\MsMpEng.exe'}, PROTECTED_WRONG),  # was UNKNOWN/low
    (CF, {'path': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\..\\MsMpEng.exe'}, PROTECTED_WRONG),  # was UNKNOWN/low
    (CF, {'path': 'C:\\Users\\Public\\MsMpEng.exe'}, PROTECTED_WRONG),
    (CF, {'path': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe'}, dict(verdict='UNKNOWN', confidence='low', finding_types=[])),
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'path': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\\\MsMpEng.exe'}, WRONG_PATH),
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'path': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\..\\MsMpEng.exe'}, WRONG_PATH),
    (PT, {'process_name': 'msmpeng.exe', 'parent_name': 'services.exe', 'path': 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\.\\MsMpEng.exe'}, WRONG_PATH),
    (CF, {'path': 'C:\\Program Files\\Windows Defender\\MsMpEng.exe'}, dict(verdict='EXPECTED', confidence='high', finding_types=[])),
]
ROWS_4 = [
    (CF, {'path': '\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe'}, BASELINE),  # was SUSPICIOUS/high
    (CF, {'path': '\\\\?\\C:\\Windows\\System32\\cmd.exe'}, BASELINE),  # was SUSPICIOUS/high
    (CF, {'path': '\\??\\C:\\Windows\\System32\\cmd.exe'}, BASELINE),  # was SUSPICIOUS/high
    (CF, {'path': '\\\\.\\C:\\Windows\\System32\\cmd.exe'}, BASELINE),  # was SUSPICIOUS/high
    (CF, {'path': '\\VOLUME{01d9a7c6b3e5f210-9a2b4c6d}\\WINDOWS\\SYSTEM32\\SVCHOST.EXE'}, BASELINE),  # was SUSPICIOUS/high
    (CF, {'path': '\\\\?\\Volume{3f2504e0-4f89-11d3-9a0c-0305e82c3301}\\Windows\\System32\\svchost.exe'}, BASELINE),  # was SUSPICIOUS/high
    (CF, {'path': '\\\\?\\GLOBALROOT\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe'}, BASELINE),  # was SUSPICIOUS/high
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'path': '\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe'}, MATCHES),  # was SUSPICIOUS/high
    (PT, {'process_name': 'svchost.exe', 'parent_name': '\\Device\\HarddiskVolume3\\Windows\\System32\\services.exe'}, MATCHES),  # was SUSPICIOUS/high
    (CF, {'path': '//?/C:/Windows/System32/cmd.exe'}, BASELINE),  # was SUSPICIOUS/high
    (CF, {'path': 'Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe'}, PROTECTED_WRONG),
    (CF, {'path': 'Volume{0}\\Windows\\System32\\cmd.exe'}, PROTECTED_WRONG),
    (CF, {'path': 'globalroot\\device\\harddiskvolume3\\Windows\\System32\\cmd.exe'}, PROTECTED_WRONG),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'path': 'Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe'}, WRONG_PATH),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'Device\\HarddiskVolume3\\Windows\\System32\\services.exe'}, {'verdict': 'SUSPICIOUS', 'confidence': 'high', 'finding_types': ['unexpected_parent_path']}),
    (CF, {'path': 'C:/Windows/System32/cmd.exe'}, BASELINE),
    (CF, {'path': '\\Device\\HarddiskVolume3\\Users\\Public\\svchost.exe'}, PROTECTED_WRONG),
    (CF, {'path': '\\\\?\\UNC\\server\\share\\Windows\\System32\\cmd.exe'}, PROTECTED_WRONG),
    (CF, {'path': '\\Device\\Mup\\server\\share\\Windows\\System32\\cmd.exe'}, PROTECTED_WRONG),
    (CF, {'path': '\\Device\\HarddiskVolumeShadowCopy3\\Windows\\System32\\cmd.exe'}, PROTECTED_WRONG),
    (CF, {'path': 'C:\\Windows\\System32\\cmd.exe'}, BASELINE),
    (CF, {'path': '\\SystemRoot\\System32\\svchost.exe'}, BASELINE),
    (CF, {'path': '%windir%\\System32\\cmd.exe'}, BASELINE),
    (CF, {'path': '\\\\?\\C:\\Users\\Public\\svchost.exe'}, PROTECTED_WRONG),
    (CF, {'path': '\\??\\C:\\Users\\Public\\svchost.exe'}, PROTECTED_WRONG),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'path': '\\Device\\HarddiskVolume3\\Windows\\Temp\\svchost.exe'}, WRONG_PATH),
]
ROWS_5 = [
    (CF, {'path': 'svchost.exe'}, NO_DIR),  # was SUSPICIOUS/high
    (CF, {'path': 'rundll32.exe'}, {'verdict': 'UNKNOWN', 'confidence': 'low', 'reasons': ['No directory given: path not checked'], 'finding_types': [], 'path_in_baseline': False, 'is_lolbin': True}),  # was SUSPICIOUS/medium
    (CF, {'path': 'cmd.exe'}, NO_DIR),  # was SUSPICIOUS/high
    (CF, {'path': 'SVCHOST.EXE'}, NO_DIR),  # was SUSPICIOUS/high
    (CF, {'path': 'powershell.exe'}, {'verdict': 'UNKNOWN', 'confidence': 'low', 'reasons': ['No directory given: path not checked'], 'finding_types': [], 'path_in_baseline': False, 'is_lolbin': True}),  # was SUSPICIOUS/high
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'path': 'svchost.exe'}, MATCHES),  # was SUSPICIOUS/high
    (CF, {'path': 'mimikatz.exe'}, {'verdict': 'SUSPICIOUS', 'confidence': 'high', 'finding_types': ['known_tool']}),
    (CF, {'path': 'svch0st.exe'}, dict(verdict='SUSPICIOUS', confidence='medium', finding_types=['leet_speak'])),
    (CF, {'path': 'invoice.pdf.exe'}, dict(verdict='SUSPICIOUS', confidence='high', finding_types=['double_extension'])),
    (CF, {'path': 'svсhost.exe'}, dict(verdict='SUSPICIOUS', confidence='high', finding_types=['homoglyph', 'mixed_scripts', 'process_spoofing'])),
    (CF, {'path': '\\svchost.exe'}, PROTECTED_WRONG),
    (CF, {'path': 'C:\\Users\\Public\\svchost.exe'}, PROTECTED_WRONG),
    (CF, {'path': 'cmd.exe /c start C:\\Users\\Public\\svchost.exe'}, PROTECTED_WRONG),
    (CF, {'path': 'rundll32.exe C:\\Users\\Public\\svchost.exe'}, PROTECTED_WRONG),
    (CF, {'path': 'C:\\Users\\Public\\rundll32.exe'}, dict(verdict='SUSPICIOUS', confidence='medium', finding_types=[])),
    (CF, {'path': 'C:\\Windows\\System32\\rundll32.exe'}, dict(verdict='EXPECTED_LOLBIN', confidence='high', finding_types=[])),
    (CF, {'path': 'C:svchost.exe'}, dict(verdict='SUSPICIOUS', confidence='medium', finding_types=['typosquatting'])),
    (CF, {'path': '\\\\?\\svchost.exe'}, PROTECTED_WRONG),
    (CF, {'path': '\\??\\lsass.exe'}, PROTECTED_WRONG),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'path': 'C:svchost.exe'}, WRONG_PATH),
    (PT, {'process_name': 'svchost.exe', 'parent_name': 'services.exe', 'path': '\\\\?\\svchost.exe'}, WRONG_PATH),
    (CF, {'path': 'svchost.exe -k netsvcs'}, dict(verdict='UNKNOWN', confidence='low', finding_types=[])),
]
# fmt: on


@pytest.mark.parametrize("row", ROWS_1, ids=[label(r) for r in ROWS_1])
def test_a_service_account_on_a_user_process_is_unexpected_however_written(srv, row):
    check(srv, *row)


@pytest.mark.parametrize("row", ROWS_2, ids=[label(r) for r in ROWS_2])
def test_a_system_process_accepts_its_listed_accounts_and_system_in_every_form(
    srv, row
):
    check(srv, *row)


@pytest.mark.parametrize("row", ROWS_3, ids=[label(r) for r in ROWS_3])
def test_a_wildcard_in_an_expected_path_is_one_real_folder_in_both_tools(srv, row):
    check(srv, *row)


@pytest.mark.parametrize("row", ROWS_4, ids=[label(r) for r in ROWS_4])
def test_a_device_or_volume_form_of_a_local_path_is_that_path(srv, row):
    check(srv, *row)


@pytest.mark.parametrize("row", ROWS_5, ids=[label(r) for r in ROWS_5])
def test_a_bare_name_has_no_directory_to_judge_but_its_name_is_still_checked(srv, row):
    check(srv, *row)


# On the processes that run only as SYSTEM, LOCAL SERVICE and NETWORK SERVICE
# are unexpected, and every way of writing them gives that same answer.
SYSTEM_ONLY = [
    ("lsass.exe", "wininit.exe"), ("services.exe", "wininit.exe"), ("csrss.exe", "smss.exe"),
    ("wininit.exe", "smss.exe"), ("lsaiso.exe", "wininit.exe"), ("winlogon.exe", "smss.exe"),
    ("spoolsv.exe", "services.exe"), ("msmpeng.exe", "services.exe"), ("dwm.exe", "winlogon.exe"),
]  # fmt: skip
SPELLINGS = {
    "LOCAL SERVICE": ["LOCAL SERVICE", "local service", "LocalService", " LOCAL SERVICE ",
                      "NT AUTHORITY\\LOCAL SERVICE", "nt authority\\local service",
                      "NT AUTHORITY\\LocalService", "S-1-5-19"],
    "NETWORK SERVICE": ["NETWORK SERVICE", "network service", "NetworkService",
                        "NT AUTHORITY\\NETWORK SERVICE", "nt authority\\network service",
                        "NT AUTHORITY\\NetworkService", "S-1-5-20"],
}  # fmt: skip


@pytest.mark.parametrize("account", sorted(SPELLINGS))
@pytest.mark.parametrize("process,parent", SYSTEM_ONLY)
def test_a_service_account_reads_the_same_on_a_system_only_process_in_every_form(
    srv, process, parent, account
):
    got = {
        user: answer(srv, PT, dict(process_name=process, parent_name=parent, user=user))
        for user in SPELLINGS[account]
    }
    verdicts = {
        u: (a["verdict"], a["confidence"], a["user_valid"]) for u, a in got.items()
    }
    assert set(verdicts.values()) == {("SUSPICIOUS", "medium", False)}, verdicts


# A path is normalised once on its way to a verdict. A device or volume
# prefix only counts at the very start of what was given: after a drive, or
# after one prefix already taken, `Device\HarddiskVolume3` is a folder anyone
# can make, never the volume's root.
NESTED = [
    r"C:\Device\HarddiskVolume3\Windows\System32\{f}",
    r"\\?\C:\Device\HarddiskVolume3\Windows\System32\{f}",
    r"\\?\\\?\C:\Windows\System32\{f}",
    r"\Device\HarddiskVolume3\Device\HarddiskVolume3\Windows\System32\{f}",
    r"\\?\GLOBALROOT\Device\HarddiskVolume3\Device\HarddiskVolume3\Windows\System32\{f}",
    r"C:\VOLUME{{01d9a7c6b3e5f210-9a2b4c6d}}\Windows\System32\{f}",
]


@pytest.mark.parametrize("form", NESTED)
@pytest.mark.parametrize("f", ["rundll32.exe", "cmd.exe", "svchost.exe"])
def test_a_device_prefix_inside_a_path_is_a_folder_for_check_file(srv, form, f):
    got = answer(srv, CF, {"path": form.format(f=f)})
    assert got["verdict"] not in ("EXPECTED", "EXPECTED_LOLBIN"), got
    assert got["path_in_baseline"] is False, got


@pytest.mark.parametrize("form", NESTED)
def test_a_device_prefix_inside_a_path_is_a_folder_for_check_process_tree(srv, form):
    path = form.format(f="svchost.exe")
    as_path = answer(srv, PT, dict(process_name="svchost.exe", parent_name="services.exe",
                                   path=path))  # fmt: skip
    as_parent = answer(srv, PT, dict(process_name="svchost.exe",
                                     parent_name=form.format(f="services.exe")))  # fmt: skip
    assert (as_path["verdict"], as_path["finding_types"]) == (
        "SUSPICIOUS",
        ["unexpected_path"],
    )
    assert as_parent["verdict"] == "SUSPICIOUS"
    assert as_parent["finding_types"] == ["unexpected_parent_path"]


@pytest.mark.parametrize("form", NESTED)
def test_a_device_prefix_inside_a_service_binary_path_is_a_folder(srv, form):
    args = {"service_name": "Spooler", "binary_path": form.format(f="spoolsv.exe")}
    got = answer(srv, "check_service", args)
    assert got["verdict"] != "EXPECTED", got


def test_a_verdict_never_normalises_a_path_it_already_normalised(srv, monkeypatch):
    """Each normalize_path output is recorded; none is ever its input again
    (that second pass is what strips a prefix found inside a path)."""
    from windows_triage import server
    from windows_triage.analysis import paths
    from windows_triage.db import known_good

    real, outputs, again = paths.normalize_path, set(), []

    def counted(p):
        if p in outputs:
            again.append(p)
        out = real(p)
        if out != p:
            outputs.add(out)
        return out

    for mod in (paths, server, known_good):
        monkeypatch.setattr(mod, "normalize_path", counted)
    path = NESTED[0].format(f="rundll32.exe")
    answer(srv, CF, {"path": path, "hash": "aa" * 32})
    answer(srv, PT, {"process_name": path, "parent_name": path, "path": path})
    answer(srv, "check_service", {"service_name": "Spooler", "binary_path": path})
    assert again == []


# A service's ImagePath is normalised once too: a second NT prefix after the
# first is part of the path, never stripped again.
@pytest.mark.parametrize(
    "binary_path",
    [
        r"\??\\??\C:\Windows\System32\spoolsv.exe",
        r"\??\\\?\C:\Windows\System32\spoolsv.exe",
        r"\??\\\.\C:\Windows\System32\spoolsv.exe",
    ],
)
def test_a_service_path_with_two_nt_prefixes_is_never_expected(srv, binary_path):
    got = answer(
        srv, "check_service", {"service_name": "Spooler", "binary_path": binary_path}
    )
    assert got["verdict"] != "EXPECTED", got


@pytest.mark.parametrize(
    "binary_path",
    [
        r"\??\C:\Windows\System32\spoolsv.exe",
        r"\??\C:\Windows\System32\spoolsv.exe -k netsvcs",
        r"C:\Windows\System32\spoolsv.exe",
        r"%SystemRoot%\System32\spoolsv.exe",
    ],
)
def test_a_service_path_with_one_nt_prefix_reads_as_before(srv, binary_path):
    got = answer(
        srv, "check_service", {"service_name": "Spooler", "binary_path": binary_path}
    )
    assert (got["verdict"], got["confidence"]) == ("EXPECTED", "high"), got
