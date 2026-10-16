"""setup-sift.sh writes the examiner name to ~/.vhir/config.yaml as a string.

The name was written unquoted, so a name of digits, a date or a YAML word
(`123`, `017`, `2026-10-16`, `on`, `no`) loaded as a number, a date or a
bool. vhir's identity lookup then raised, or, for `no`, skipped the value and
ran as the OS user. These run the installer's own config.yaml block, on each
of its three write paths, in a scratch HOME.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
_START = "# Write to config.yaml"
_I = SCRIPT.index(_START)
CONFIG_BLOCK = SCRIPT[_I : SCRIPT.index("# Write VHIR_EXAMINER to shell profile", _I)]

NAMES = ["123", "017", "2026-10-16", "on", "no", "alice"]

# what ~/.vhir/config.yaml holds before the block runs, per write path
BEFORE = {
    "new-file": None,
    "replace-line": "examiner: old-name\ngateway_url: https://10.0.0.5:4508\n",
    "append-line": "gateway_url: https://10.0.0.5:4508\n",
}


def _write(home: Path, name: str, path: str) -> Path:
    cfg = home / ".vhir" / "config.yaml"
    if BEFORE[path] is not None:
        cfg.parent.mkdir(parents=True)
        cfg.write_text(BEFORE[path])
    r = subprocess.run(
        ["/bin/bash", "-c", "set -euo pipefail\n" + CONFIG_BLOCK],
        env={"HOME": str(home), "PATH": "/usr/bin:/bin", "EXAMINER_NAME": name},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stderr
    return cfg


@pytest.mark.parametrize("path", list(BEFORE))
@pytest.mark.parametrize("name", NAMES)
def test_the_name_loads_back_as_the_same_string(tmp_path, name, path):
    cfg = _write(tmp_path, name, path)
    doc = yaml.safe_load(cfg.read_text())
    assert doc["examiner"] == name and type(doc["examiner"]) is str
    if path != "new-file":
        assert doc["gateway_url"] == "https://10.0.0.5:4508"
    assert cfg.read_text().count("examiner:") == 1


@pytest.mark.parametrize("name", NAMES)
def test_vhir_runs_as_the_name_the_installer_wrote(tmp_path, monkeypatch, name):
    identity = pytest.importorskip("vhir_cli.identity")
    _write(tmp_path, name, "new-file")
    for k in ("VHIR_EXAMINER", "VHIR_ANALYST", "USERNAME"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("USER", "osuser")
    monkeypatch.setenv("HOME", str(tmp_path))
    got = identity.get_examiner_identity()
    assert (got["examiner"], got["examiner_source"]) == (name, "config")
