"""Every copy of the confidence levels and the evidence standards names the
knowledge base's levels in its order: the discipline files (full and lite),
forensic-mcp's instructions and the LibreChat prompt."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FK = ROOT / "packages/forensic-knowledge/data/discipline"
# (FORENSIC_DISCIPLINE.md heading, the line that starts the one-line copy)
LADDERS = {
    "confidence": ("## Confidence Levels", "CONFIDENCE LEVELS"),
    "evidence": ("## Evidence Classification", "EVIDENCE STANDARDS"),
}
LINE_COPIES = (
    "packages/sift-common/src/sift_common/instructions.py",
    "docs/librechat-setup.md",
)
# a level as the one-line copies write it: "MEDIUM (intelligence "moderate") —"
NAME = r"\b([A-Z]{3,})(?: \([^)]*\))? —"


def _fk() -> dict[str, list[str]]:
    conf = yaml.safe_load((FK / "confidence.yaml").read_text())["levels"]
    std = yaml.safe_load((FK / "evidence_standards.yaml").read_text())["standards"]
    return {
        "confidence": list(conf),
        "evidence": sorted(std, key=lambda name: std[name]["level"]),
    }


def _copies(ladder: str) -> dict[str, list[str]]:
    heading, start = LADDERS[ladder]
    found = {}
    for rel in ("claude-code/full", "claude-code/lite"):
        text = (ROOT / rel / "FORENSIC_DISCIPLINE.md").read_text()
        section = text.split(heading + "\n", 1)[1].split("\n## ", 1)[0]
        found[rel] = re.findall(r"^\| ([A-Z]{3,})\b", section, re.M)
    for rel in LINE_COPIES:
        lines = [
            x for x in (ROOT / rel).read_text().splitlines() if x.startswith(start)
        ]
        # one line holds the ladder; with none or two, the lines are the answer
        found[rel] = re.findall(NAME, lines[0]) if len(lines) == 1 else lines
    return found


def test_every_copy_names_the_knowledge_bases_levels_in_order():
    fk = _fk()
    assert all(fk.values())
    differ = {
        (ladder, rel): names
        for ladder in LADDERS
        for rel, names in _copies(ladder).items()
        if names != fk[ladder]
    }
    assert differ == {}
