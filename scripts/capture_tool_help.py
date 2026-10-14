"""Record an installed tool's help as the fixtures tests/test_sift_mcp/
test_recipe_flags.py checks the catalog's recipes against:

    python scripts/capture_tool_help.py <catalog tool> [subcommand ...]

writes tests/fixtures/tool_help/<tool>/<version>/<tool>-<version>-help.txt
(and -<subcommand>-help.txt for each subcommand), the version and help read
the way get_tool_help reads them: stdout, then stderr under its label. The
home folder is written as /home/<user>.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from sift_mcp import tool_version
from sift_mcp.catalog import get_tool_def

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "tool_help"


def capture(name: str, subcommands: list[str], out: Path = FIXTURES) -> list[Path]:
    td = get_tool_def(name)
    if not td:
        raise SystemExit(f"{name} isn't in the catalog")
    found = tool_version.probe(td)
    version = found.get("installed_version")
    if not version or version == "unknown":
        raise SystemExit(f"{name}: no version read ({found or 'not installed'})")
    home = os.path.expanduser("~")
    d = out / td.name / version
    d.mkdir(parents=True, exist_ok=True)
    written = []
    for sub in ["", *subcommands]:
        cap, tool_version.HELP_INLINE = tool_version.HELP_INLINE, 1 << 30
        try:  # the whole help, not the reply's cut
            got = tool_version.help_text(td, sub)
        finally:
            tool_version.HELP_INLINE = cap
        if "help" not in got:
            raise SystemExit(f"{name} {sub}: {got}")
        kind = f"{sub}-help" if sub else "help"
        p = d / f"{td.name}-{version}-{kind}.txt"
        p.write_text(got["help"].replace(home, "/home/<user>"))
        written.append((p, got["help_exit_code"]))
    return written


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    for p, code in capture(sys.argv[1], sys.argv[2:]):
        print(p, f"(exit {code})")
