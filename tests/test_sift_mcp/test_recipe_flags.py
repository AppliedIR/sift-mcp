"""Every flag a catalog recipe uses appears in the help of each version the
recipe is tagged for, and a recipe uses only what that version has: its own
command name (plaso 20240308's log2timeline.py, 20260720's log2timeline) and,
for a tool with subcommands, a subcommand whose help that version gives
(Hayabusa 3.9.0 has json-timeline, 4.2.0 only dfir-timeline). The help texts
are fixtures under tests/fixtures/tool_help/<tool>/<version>/, captured from
the tools (<tool>-<version>-<subcommand>-help.txt for a subcommand's);
adding a tool version means capturing its help, and this test names any
recipe it breaks."""

from __future__ import annotations

import re
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version
from sift_mcp.catalog import load_catalog

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tool_help"
# The switches the catalog carried before recipes (its common_flags at the
# 0.6.5 assembly, 2dd165f). Each is in one of that tool's recipes or listed in
# DROPPED with why, so nothing is lost silently.
FORMER = {
    "hayabusa": ["json-timeline", "-o", "-w", "--min-level"],
    "vol3": ["-r"],
    "AmcacheParser": ["--csv"],
    "PECmd": ["--csv"],
    "AppCompatCacheParser": ["--csv"],
    "RECmd": ["--bn", "--csv"],
    "MFTECmd": ["--csv"],
    "EvtxECmd": ["--csv", "--maps"],
    "JLECmd": ["--csv"],
    "LECmd": ["--csv"],
    "SBECmd": ["--csv"],
    "RBCmd": ["--csv"],
    "SrumECmd": ["--csv"],
    "SQLECmd": ["--csv"],
}
# (tool, switch) -> why it is not a recipe (the audit lists the same)
DROPPED: dict[tuple[str, str], str] = {
    (
        "PECmd",
        "--csv",
    ): "PECmd isn't installed on this SIFT: no help to check it against",
    (
        "SrumECmd",
        "--csv",
    ): "SrumECmd isn't installed on this SIFT: no help to check it against",
}


def _flags(argv: list[str]) -> set[str]:
    return {a.split("=", 1)[0] for a in argv[1:] if a.startswith("-") and len(a) > 1}


def _in_help(flag: str, text: str) -> bool:
    """`flag` as a whole option in the help: -o isn't found inside --output."""
    return re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", text) is not None


def _helps(tool: str) -> dict[Version, dict[str, str]]:
    """{version: {kind: help text}} from the fixtures, kind being "help" or
    "<subcommand>-help"."""
    out: dict[Version, dict[str, str]] = {}
    for d in sorted((FIXTURES / tool).glob("*")) if (FIXTURES / tool).is_dir() else []:
        try:
            v = Version(d.name)
        except InvalidVersion:
            continue
        prefix = f"{tool}-{d.name}-"
        out[v] = {
            p.stem[len(prefix) :]: p.read_text(errors="replace")
            for p in sorted(d.glob("*.txt"))
        }
    return out


def _tagged(td, recipe) -> dict[Version, dict[str, str]]:
    return {
        v: t
        for v, t in _helps(td.name).items()
        if v in SpecifierSet(recipe["versions"])
    }


def test_every_former_switch_is_a_recipe_or_dropped_with_a_reason():
    cat = load_catalog()
    lost = [
        (tool, switch)
        for tool, switches in FORMER.items()
        for switch in switches
        if (tool, switch) not in DROPPED
        and not any(switch in r["argv"] for r in cat[tool.lower()].recipes)
    ]
    assert lost == []
    assert all(reason for reason in DROPPED.values())


def test_every_recipe_flag_is_in_a_tagged_versions_help():
    problems = []
    for td in load_catalog().values():
        for r in td.recipes:
            helps = _tagged(td, r)
            if not helps:
                problems.append(
                    f"{td.name}: no help fixture in {r['versions']} for {r['task']!r}"
                )
                continue
            for v, kinds in helps.items():
                if td.subcommand_help:  # the subcommand's own help
                    text = kinds.get(f"{r['argv'][1]}-help")
                    if text is None:
                        problems.append(
                            f"{td.name} {v} {r['task']!r}: no help for "
                            f"{r['argv'][1]!r} in this version"
                        )
                        continue
                else:
                    text = "\n".join(kinds.values())
                missing = sorted(f for f in _flags(r["argv"]) if not _in_help(f, text))
                if missing:
                    problems.append(
                        f"{td.name} {v} {r['task']!r}: {missing} not in its help"
                    )
    assert problems == []


def _names(name: str, text: str) -> bool:
    """`name` as a whole command name: log2timeline isn't found in
    log2timeline.py."""
    return re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", text) is not None


def _usage(text: str) -> str:
    """The usage line and the one after it ("Usage:" alone, then the
    command): the examples further down can lag (plaso 20260720's still say
    log2timeline.py)."""
    lines = text.splitlines()
    i = next(
        (n for n, ln in enumerate(lines) if re.match(r"\s*usage\b", ln, re.I)), None
    )
    return "" if i is None else "\n".join(lines[i : i + 2])


def test_a_recipe_names_the_command_its_version_has():
    """Its command is one the catalog finds for the tool and, where that
    version's usage line names one of them (plaso's says log2timeline.py or
    log2timeline), the one it names."""
    problems = []
    for td in load_catalog().values():
        for r in td.recipes:
            if r["argv"][0] not in td.binaries:
                problems.append(f"{td.name} {r['task']!r}: {r['argv'][0]} not a binary")
            for v, kinds in _tagged(td, r).items():
                text = "\n".join(_usage(t) for t in kinds.values())
                named = [b for b in td.binaries if _names(b, text)]
                if named and r["argv"][0] not in named:
                    problems.append(
                        f"{td.name} {v}: help names {named}, not {r['argv'][0]}"
                    )
    assert problems == []
