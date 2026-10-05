"""setup-sift.sh deletes only what it created.

The venv step deleted any existing directory without bin/python as a "broken
venv" (--venv=~/.vhir wiped the install's config and tokens). Uninstall step
[4] deleted the parent of --install-dir, and step [7] deleted the gateway
config and credentials the user had just chosen to keep at step [6]. These run
the installer's own blocks under its shell options, in tmp_path only, with
answers from a file and uv stubbed.
"""

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()


def _block(start, end):
    i = SCRIPT.index(start)
    return SCRIPT[i : SCRIPT.index(end, i)]


VENV = _block("# --- Virtual environment ---", "VENV_PYTHON=")
SOURCE = _block("    # [4] Source code", "    # [5] Shell profile")
CONFIG_AND_REST = _block("    # [6] Gateway config", "    # [8] Verification ledger")
_p = SCRIPT.index("prompt_yn_strict() {")
PROMPT = SCRIPT[_p : SCRIPT.index("\n}\n", _p) + 3]

PROLOGUE = (
    "set -euo pipefail\nBOLD=; NC=; YELLOW=; GREEN=; BLUE=; RED=\n"
    'info() { echo "INFO $*"; }; ok() { echo "OK $*"; }\n'
    'warn() { echo "WARN $*"; }; err() { echo "ERROR $*"; }\n'
)


def _bash(tmp_path, home, body, answers="", **env):
    # answers arrive on a pipe: each prompt reopens READ_FROM, and a pipe hands
    # every prompt the next line (a regular file would restart at the first)
    p = subprocess.run(
        ["bash", "-c", PROLOGUE + 'READ_FROM="/dev/stdin"\n' + PROMPT + body],
        env={"PATH": "/usr/bin:/bin", "HOME": str(home), **env},
        cwd=tmp_path,
        input=answers,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return p.returncode, p.stdout + p.stderr


def _tree(root):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


# --- The venv step -----------------------------------------------------------

UV_STUB = (
    'uv() { [[ "$1" == venv ]] || return 1; mkdir -p "$2/bin"; '
    ': > "$2/bin/python"; : > "$2/pyvenv.cfg"; }\nPYTHON=python3\n'
)


def _venv(tmp_path, venv):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return _bash(
        tmp_path, home, UV_STUB + VENV + 'echo "venv step done"\n', VENV_DIR=str(venv)
    )


def _vhir_like(path):
    """An install's ~/.vhir: config, a token and the source checkout."""
    (path / "src" / "sift-mcp").mkdir(parents=True)
    (path / "src" / "sift-mcp" / "README.md").write_text("x")
    (path / "gateway.yaml").write_text("x")
    (path / "opencti-mcp.token").write_text("x")
    return path


def test_a_directory_that_is_not_a_venv_stops_the_install_and_is_kept(tmp_path):
    target = _vhir_like(tmp_path / "home" / ".vhir")
    before = _tree(target)
    rc, out = _venv(tmp_path, target)
    assert rc == 1, out
    assert f"ERROR {target} exists and is not a virtual environment" in out
    assert "Remove it or choose a different --venv" in out
    assert "venv step done" not in out
    assert _tree(target) == before


def test_a_folder_holding_one_file_is_not_a_venv_either(tmp_path):
    target = tmp_path / "project"
    target.mkdir()
    (target / "notes.txt").write_text("x")
    rc, out = _venv(tmp_path, target)
    assert rc == 1 and (target / "notes.txt").exists(), out


def test_a_venv_missing_its_python_is_recreated(tmp_path):
    target = tmp_path / "venv"
    target.mkdir()
    (target / "pyvenv.cfg").write_text("x")
    (target / "old-file").write_text("x")
    rc, out = _venv(tmp_path, target)
    assert rc == 0 and "Broken virtual environment detected" in out, out
    assert (target / "bin" / "python").exists() and not (target / "old-file").exists()


def test_a_venv_whose_python_link_dangles_is_recreated(tmp_path):
    target = tmp_path / "venv"
    (target / "bin").mkdir(parents=True)
    (target / "pyvenv.cfg").write_text("x")
    (target / "bin" / "python").symlink_to(tmp_path / "gone" / "python3")
    rc, out = _venv(tmp_path, target)
    assert rc == 0 and "Broken virtual environment detected" in out, out
    assert (target / "bin" / "python").is_file()


def test_a_healthy_venv_is_kept(tmp_path):
    target = tmp_path / "venv"
    (target / "bin").mkdir(parents=True)
    (target / "bin" / "python").write_text("x")
    (target / "pyvenv.cfg").write_text("x")
    (target / "installed-package").write_text("x")
    rc, out = _venv(tmp_path, target)
    assert rc == 0 and (target / "installed-package").exists(), out


@pytest.mark.parametrize("state", ["absent", "empty"])
def test_an_absent_or_empty_directory_gets_a_new_venv(tmp_path, state):
    target = tmp_path / "venv"
    if state == "empty":
        target.mkdir()
    rc, out = _venv(tmp_path, target)
    assert rc == 0 and "venv step done" in out and (target / "pyvenv.cfg").exists(), out


# --- Uninstall step [4]: the source code ---------------------------------------


def _source(tmp_path, home, install_dir, answer="y\n"):
    return _bash(tmp_path, home, SOURCE, answer, INSTALL_DIR=str(install_dir))


def _repos(parent):
    for name in ("sift-mcp", "vhir", "opensearch-mcp"):
        (parent / name / "src").mkdir(parents=True)
        (parent / name / "src" / "f.py").write_text("x")


def test_uninstall_removes_only_the_three_repos_beside_other_projects(tmp_path):
    home = tmp_path / "home"
    code = home / "code"
    _repos(code)
    (code / "my-project").mkdir()
    (code / "my-project" / "work.py").write_text("x")
    rc, out = _source(tmp_path, home, code / "sift-mcp")
    assert rc == 0, out
    assert (code / "my-project" / "work.py").exists()
    assert not any((code / n).exists() for n in ("sift-mcp", "vhir", "opensearch-mcp"))


def test_uninstall_with_the_repo_in_home_leaves_the_rest_of_home(tmp_path):
    home = tmp_path / "home"
    (home / "sift-mcp" / "src").mkdir(parents=True)
    (home / "cases" / "INC-1").mkdir(parents=True)
    (home / "cases" / "INC-1" / "findings.json").write_text("[]")
    (home / ".bashrc").write_text("x")
    rc, out = _source(tmp_path, home, home / "sift-mcp")
    assert rc == 0, out
    assert (home / "cases" / "INC-1" / "findings.json").exists()
    assert (home / ".bashrc").exists() and not (home / "sift-mcp").exists()


def test_uninstall_in_the_default_layout_removes_the_repos_and_their_folder(tmp_path):
    home = tmp_path / "home"
    src = home / ".vhir" / "src"
    _repos(src)
    rc, out = _source(tmp_path, home, src / "sift-mcp")
    assert rc == 0 and not src.exists(), out


def test_uninstall_keeps_a_users_own_folder_in_the_source_dir(tmp_path):
    home = tmp_path / "home"
    src = home / ".vhir" / "src"
    _repos(src)
    (src / "my-notes").mkdir()
    rc, out = _source(tmp_path, home, src / "sift-mcp")
    assert rc == 0 and (src / "my-notes").exists(), out


def test_answering_no_keeps_the_source_code(tmp_path):
    home = tmp_path / "home"
    src = home / ".vhir" / "src"
    _repos(src)
    before = _tree(src)
    rc, out = _source(tmp_path, home, src / "sift-mcp", answer="n\n")
    assert rc == 0 and _tree(src) == before, out


# --- Uninstall steps [6] and [7]: config, then the rest of ~/.vhir -------------

KEPT = ("gateway.yaml", "manifest.json", "config.yaml", "tls")
REST = ("hooks", "logs", "start-gateway.sh")


def _vhir_dir(home):
    vhir = home / ".vhir"
    (vhir / "tls").mkdir(parents=True)
    (vhir / "tls" / "gateway.key").write_text("x")
    (vhir / "hooks").mkdir()
    (vhir / "hooks" / "forensic-audit.sh").write_text("x")
    (vhir / "logs").mkdir()
    for name in ("gateway.yaml", "manifest.json", "config.yaml", "start-gateway.sh"):
        (vhir / name).write_text("x")
    return vhir


def _config_and_rest(tmp_path, answers):
    home = tmp_path / "home"
    vhir = _vhir_dir(home)
    rc, out = _bash(
        tmp_path, home, "KEPT_VENV=false\nKEPT_SRC=false\n" + CONFIG_AND_REST, answers
    )
    return rc, out, vhir


def test_config_kept_at_step_6_survives_step_7(tmp_path):
    rc, out, vhir = _config_and_rest(tmp_path, "n\ny\n")
    assert rc == 0, out
    assert all((vhir / n).exists() for n in KEPT), sorted(os.listdir(vhir))
    assert not any((vhir / n).exists() for n in REST), sorted(os.listdir(vhir))


def test_yes_at_both_steps_removes_everything(tmp_path):
    rc, out, vhir = _config_and_rest(tmp_path, "y\ny\n")
    assert rc == 0 and not any(vhir.iterdir()), out


def test_no_at_both_steps_removes_nothing(tmp_path):
    rc, out, vhir = _config_and_rest(tmp_path, "n\nn\n")
    assert rc == 0 and all((vhir / n).exists() for n in KEPT + REST), out
