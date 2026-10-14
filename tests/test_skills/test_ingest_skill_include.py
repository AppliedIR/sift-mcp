"""The vhir-ingest skill says what idx_ingest's `include` does, in both modes
(opensearch-mcp's get_active_tools and its Plaso and custom filters): without
`full`, `include` adds tools to the tier-1 tools, which still run, and limits
the other artifacts to the ones named; with `full`, every tool tier runs and
`include` still limits those other artifacts. An AI reading only
`include: ["timeline"]` would otherwise expect a filter."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_the_skill_says_what_include_does_with_and_without_full():
    skill = " ".join((ROOT / "skills/vhir-ingest/SKILL.md").read_text().split())
    # without full: include adds to the tier-1 tools, and limits the others
    assert "`include` adds tier-2 and tier-3 tools" in skill
    assert "to the tier-1 tools, which still run" in skill
    assert "are limited to the ones named" in skill
    # with full: every tool tier, and include still limits the others
    assert (
        "`full: true` runs every tool tier; `include` still limits those other artifacts"
        in skill
    )
    assert "`exclude` removes types in either case" in skill
