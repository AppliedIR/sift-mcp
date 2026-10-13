"""Codex's managed requirements template: Valhuntir's marker leads it, Codex's
sandbox can't be turned off (only the vhir and read-only permission profiles,
vhir the default, with ~/.vhir read-only), web search stays off, the shell
can't read the store, the gateway's tokens or the profile, and the four hooks
run from the root-owned copies, the guard on shell calls and on apply_patch
(by the paths a patch names)."""

from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent
TEXT = (ROOT / "codex" / "requirements.toml").read_text()


def _toml(text: str) -> dict:
    try:
        import tomllib
    except ImportError:  # Python 3.10
        tomllib = pytest.importorskip("tomli")
    return tomllib.loads(text)


def test_the_marker_leads_and_the_sandbox_stays_on():
    assert TEXT.splitlines()[0] == "# managed-by: valhuntir"
    req = _toml(TEXT)
    assert "allowed_sandbox_modes" not in req  # the legacy key: profiles replace it
    assert req["default_permissions"] == "vhir"
    assert req["allowed_permission_profiles"] == {"vhir": True, ":read-only": True}
    assert req["permissions"]["vhir"]["extends"] == ":workspace"
    assert req["permissions"]["vhir"]["filesystem"] == {"{home}/.vhir": "read"}


def test_web_search_stays_off():
    assert _toml(TEXT)["allowed_web_search_modes"] == []


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
    assert pre == 'matcher = "^(Bash|apply_patch)$"'
