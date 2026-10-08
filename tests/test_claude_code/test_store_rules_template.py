"""The full template keeps the AI's tools out of the signing and approval
store: Read and Edit rules on its absolute path ("//"; the single-slash form
matched nothing), and the sandbox read-denies the whole folder, so a shell
sees it empty. The same rules are in vhir's own client settings where both
sources are installed."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent
STORE_RULES = {"Read(//var/lib/vhir/**)", "Edit(//var/lib/vhir/**)"}


def _full():
    return json.loads((ROOT / "claude-code" / "full" / "settings.json").read_text())


def test_the_template_denies_the_store_by_its_absolute_path():
    deny = set(_full()["permissions"]["deny"])
    assert deny >= STORE_RULES
    assert not {"Read(/var/lib/vhir/**)", "Edit(/var/lib/vhir/**)"} & deny


def test_the_sandbox_read_denies_the_whole_store():
    assert "/var/lib/vhir" in _full()["sandbox"]["filesystem"]["denyRead"]


def test_vhirs_client_settings_carry_the_same_store_rules():
    cs = pytest.importorskip("vhir_cli.commands.client_setup")
    assert STORE_RULES <= cs._FORENSIC_DENY_RULES
