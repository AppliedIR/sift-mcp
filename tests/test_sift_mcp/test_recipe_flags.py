"""Every flag a catalog recipe uses appears in the help of a version the recipe
is tagged for. The help texts are fixtures under tests/fixtures/tool_help/
<tool>/<version>/, captured from the installed tools; adding a tool version
means capturing its help, and this test names any recipe it breaks."""

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


def _helps(tool: str) -> dict[Version, str]:
    out: dict[Version, str] = {}
    for d in sorted((FIXTURES / tool).glob("*")) if (FIXTURES / tool).is_dir() else []:
        try:
            v = Version(d.name)
        except InvalidVersion:
            continue
        out[v] = "\n".join(p.read_text(errors="replace") for p in sorted(d.glob("*")))
    return out


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
            helps = {
                v: t
                for v, t in _helps(td.name).items()
                if v in SpecifierSet(r["versions"])
            }
            if not helps:
                problems.append(
                    f"{td.name}: no help fixture in {r['versions']} for {r['task']!r}"
                )
                continue
            for v, text in helps.items():
                missing = sorted(f for f in _flags(r["argv"]) if not _in_help(f, text))
                if missing:
                    problems.append(
                        f"{td.name} {v} {r['task']!r}: {missing} not in its help"
                    )
    assert problems == []
