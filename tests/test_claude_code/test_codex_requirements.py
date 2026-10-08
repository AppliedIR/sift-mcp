"""Codex's managed requirements template: Valhuntir's marker leads it, Codex's
sandbox can't be turned off, the shell can't read the store, the gateway's
tokens or the profile, and the four hooks run from the root-owned copies,
the guard on shell calls only (a patch's text isn't a shell command)."""

from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
TEXT = (ROOT / "codex" / "requirements.toml").read_text()


def test_the_marker_leads_and_the_sandbox_stays_on():
    assert TEXT.splitlines()[0] == "# managed-by: valhuntir"
    modes = next(x for x in TEXT.splitlines() if x.startswith("allowed_sandbox_modes"))
    assert modes == 'allowed_sandbox_modes = ["read-only", "workspace-write"]'


def test_the_shell_cant_read_the_store_the_tokens_or_the_profile():
    line = next(x for x in TEXT.splitlines() if x.startswith("deny_read"))
    for path in (
        "/var/lib/vhir",
        "{home}/.vhir/gateway.yaml",
        "{home}/.codex/valhuntir.config.toml",
    ):
        assert f'"{path}"' in line


def test_the_hooks_run_from_the_root_owned_copies():
    for hook in ("case-data-guard.sh", "forensic-audit.sh --client codex",
                 "codex-stdin-capture.sh", "case-dir-check.sh --client codex"):  # fmt: skip
        assert f'command = "{{hooks}}/{hook}"' in TEXT
        assert any((ROOT / "claude-code").rglob(hook.split()[0])), hook
    pre = TEXT[TEXT.index("[[hooks.PreToolUse]]") :].splitlines()[1]
    assert pre == 'matcher = "^Bash$"'
