"""Codex's developer_instructions fit their budget.

`vhir setup client --client=codex` writes the AGENTS.md core, the forensic
discipline and `codex/OVERLAY.md`, joined, into the profile's
developer_instructions; on another machine (remote), `codex/REMOTE.md` too.
Together they stay within 25 KiB. That cap is our own always-on budget, not a
Codex limit: Codex's documentation sets none on developer_instructions (checked
for codex-cli 0.138 and 0.158), and the profile sets project_doc_max_bytes = 0
and inlines the text. It rose from 24 KiB for the section on a failed tool.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PARTS = ["AGENTS.md", "claude-code/full/FORENSIC_DISCIPLINE.md", "codex/OVERLAY.md"]


def test_the_codex_instructions_fit_in_25_kib_remote_too():
    text = "\n\n".join((ROOT / p).read_text().strip() for p in PARTS) + "\n"
    remote = text + "\n" + (ROOT / "codex" / "REMOTE.md").read_text().strip() + "\n"
    assert len(remote.encode()) <= 25 * 1024


def test_the_overlay_names_the_profile_and_never_a_start_subfolder():
    overlay = (ROOT / "codex" / "OVERLAY.md").read_text()
    assert "codex -p valhuntir" in overlay
    for part in ("OVERLAY.md", "REMOTE.md"):
        assert "work/" not in (ROOT / "codex" / part).read_text()
