"""``update_sources.py``: each update clones its source with that source's timeout.

The VanillaWindowsRegistryHives repo is about 14 GiB, so a clone for the
registry DB or the registry extractions gets 7200 s; every other source's clone
gets 600 s. These run the updater's own ``main`` for one source with
``--force --dry-run``, its status check stubbed (no GitHub call) and
``subprocess.run`` recorded, so no clone or import runs; they read the timeout
each ``git clone`` was given.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "packages/windows-triage/scripts"
REGISTRY = ("registry", "registry_extractions")
OTHERS = ("files", "lolbas", "loldrivers", "hijacklibs")


def _clone_timeouts(monkeypatch, key: str) -> list:
    spec = importlib.util.spec_from_file_location(
        "update_sources_clone_timeout", SCRIPTS / "update_sources.py"
    )
    us = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(us)

    def check_source(source_key, data_dir):
        return {
            "key": source_key,
            "name": us.SOURCES[source_key]["name"],
            "db": us.SOURCES[source_key]["db"],
            "db_exists": True,
            "last_sync": None,
            "latest_commit": "a" * 40,
            "needs_update": True,
            "changed_files": [],
            "skipped": False,
        }

    timeouts = []

    def run(cmd, *args, **kwargs):
        if list(cmd[:2]) == ["git", "clone"]:
            timeouts.append(kwargs.get("timeout"))
            Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(us, "check_source", check_source)
    monkeypatch.setattr(us.subprocess, "run", run)
    argv = ["update_sources.py", "--source", key, "--force", "--dry-run"]
    monkeypatch.setattr(sys, "argv", argv)
    us.main()
    return timeouts


@pytest.mark.parametrize("key", REGISTRY)
def test_a_registry_update_clones_with_7200(monkeypatch, key):
    assert _clone_timeouts(monkeypatch, key) == [7200]


@pytest.mark.parametrize("key", OTHERS)
def test_every_other_update_clones_with_600(monkeypatch, key):
    assert _clone_timeouts(monkeypatch, key) == [600]
