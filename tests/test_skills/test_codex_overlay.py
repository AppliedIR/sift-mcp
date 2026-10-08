"""Codex's developer_instructions fit their budget.

`vhir setup client --client=codex` writes the AGENTS.md core, the forensic
discipline and `codex/OVERLAY.md`, joined, into the profile's
developer_instructions. Together they stay within 24 KiB.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PARTS = ["AGENTS.md", "claude-code/full/FORENSIC_DISCIPLINE.md", "codex/OVERLAY.md"]


def test_the_codex_instructions_fit_in_24_kib():
    text = "\n\n".join((ROOT / p).read_text().strip() for p in PARTS) + "\n"
    assert len(text.encode()) <= 24 * 1024


def test_the_overlay_names_the_profile_and_never_a_start_subfolder():
    overlay = (ROOT / "codex" / "OVERLAY.md").read_text()
    assert "codex -p valhuntir" in overlay
    assert "work/" not in overlay
