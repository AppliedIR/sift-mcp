"""The gateway puts ~/.local/bin on its backends' PATH.

SIFT installs hayabusa, capa, floss and chainsaw in ~/.local/bin, and the
gateway's systemd user unit starts with a PATH without it, so the backends
found none of them.
"""

from __future__ import annotations

import os
import sys

import pytest
import sift_gateway.__main__ as gw_main

BASE = "/usr/local/bin:/usr/bin:/bin"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PATH", BASE)
    return tmp_path


def test_an_existing_local_bin_is_put_first(home):
    (home / ".local" / "bin").mkdir(parents=True)
    gw_main.prepend_local_bin()
    assert os.environ["PATH"] == f"{home}/.local/bin:{BASE}"


def test_no_local_bin_leaves_path_alone(home):
    gw_main.prepend_local_bin()
    assert os.environ["PATH"] == BASE


def test_a_local_bin_already_on_path_is_not_added_twice(home, monkeypatch):
    (home / ".local" / "bin").mkdir(parents=True)
    monkeypatch.setenv("PATH", f"/usr/bin:{home}/.local/bin:/bin")
    gw_main.prepend_local_bin()
    assert os.environ["PATH"] == f"/usr/bin:{home}/.local/bin:/bin"


def test_main_extends_path_before_starting_backends(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(gw_main, "prepend_local_bin", lambda: calls.append("path"))
    monkeypatch.setattr(gw_main, "Gateway", lambda config: calls.append("gateway"))
    monkeypatch.setattr(gw_main.uvicorn, "run", lambda *a, **k: None)
    monkeypatch.setattr(gw_main, "setup_logging", lambda name: None)
    cfg = tmp_path / "gateway.yaml"
    cfg.write_text("gateway: {host: 127.0.0.1, port: 4999}\nbackends: {}\n")
    monkeypatch.setattr(sys, "argv", ["sift-gateway", "--config", str(cfg)])
    with pytest.raises(AttributeError):  # the Gateway stand-in has no create_app
        gw_main.main()
    assert calls == ["path", "gateway"]
