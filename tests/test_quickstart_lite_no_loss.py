"""quickstart-lite never silently replaces a file in the user's project.

It deploys into the directory it runs in, and copied CLAUDE.md, the discipline
files, the hook, .claude/settings.json and the commands over whatever was
there. Now an absent or identical file is deployed quietly, a version Valhuntir
shipped is replaced with a notice, and one the user changed is replaced only
with -y or a "y" at a terminal (stdin), after a backup, with an undo block; it's
otherwise left with "NOT deployed". An unparseable .mcp.json is left as it is.

The script's own deploy step runs against a scratch sift clone (a git repo with
two versions of the hook) and a scratch project whose name has a space.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "quickstart-lite.sh").read_text()
HELPERS = (  # absent in an older script, whose step doesn't call them
    SCRIPT[
        SCRIPT.index("# Whether $1's bytes are a version") : SCRIPT.index(
            "\n}\n", SCRIPT.index("_deploy_file() {")
        )
        + 3
    ]
    if "_deploy_file() {" in SCRIPT
    else ""
)
_d = SCRIPT.index("# Deploy doc files to project root")
STEP = SCRIPT[_d : SCRIPT.index("# Deploy case templates", _d)]

HOOK_V1 = "#!/bin/bash\necho old hook\n"
HOOK_V2 = "#!/bin/bash\necho new hook\n"
SETTINGS = '{"hooks": "$CLAUDE_PROJECT_DIR/hooks/forensic-audit.sh"}\n'


def _git(repo, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )


@pytest.fixture
def clone(tmp_path):
    """A sift clone: lite and shared files, the hook committed twice."""
    root = tmp_path / "sift-mcp"
    lite, shared = root / "claude-code" / "lite", root / "claude-code" / "shared"
    (lite / "commands").mkdir(parents=True)
    (shared / "hooks").mkdir(parents=True)
    for name in ("CLAUDE.md", "FORENSIC_DISCIPLINE.md", "TOOL_REFERENCE.md"):
        (lite / name).write_text(f"valhuntir {name}\n")
    (lite / "settings.json").write_text(SETTINGS)
    (lite / "commands" / "case.md").write_text("valhuntir case command\n")
    (shared / "FORENSIC_TOOLS.md").write_text("valhuntir tools\n")
    hook = shared / "hooks" / "forensic-audit.sh"
    _git(root, "init", "-q")
    hook.write_text(HOOK_V1)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "v1")
    hook.write_text(HOOK_V2)
    hook.chmod(0o644)  # the step makes it executable
    _git(root, "commit", "-qam", "v2")
    return root


def _project(tmp_path):
    p = tmp_path / "my project"
    (p / ".claude" / "commands").mkdir(parents=True)
    return p


def _user_state(clone, project):
    """User-different CLAUDE.md, settings.json, commands/case.md; TOOL_REFERENCE
    identical; FORENSIC_DISCIPLINE absent."""
    (project / "CLAUDE.md").write_text("MY OWN CLAUDE.md\n")
    (project / ".claude" / "settings.json").write_text('{"mine": true}\n')
    (project / ".claude" / "commands" / "case.md").write_text("my case command\n")
    shutil.copy(clone / "claude-code" / "lite" / "TOOL_REFERENCE.md", project)
    return {
        p: p.read_bytes()
        for p in (
            project / "CLAUDE.md",
            project / ".claude" / "settings.json",
            project / ".claude" / "commands" / "case.md",
        )
    }


def _run(tmp_path, clone, project, yes=False, pty_answers=None):
    """Run the deploy step. pty_answers: stdin is a terminal (stdout still a pipe)."""
    bin_dir = tmp_path / "bin"
    if not bin_dir.exists():
        bin_dir.mkdir()
        (bin_dir / "date").write_text(
            "#!/bin/sh\necho 20261003T120000Z\n"
        )  # one second
        (bin_dir / "date").chmod(0o755)
    run = tmp_path / "step.sh"
    run.write_text(
        "set -euo pipefail\numask 022\nRED=; GREEN=; YELLOW=; NC=\n"
        'ok() { echo "OK $1"; }; warn() { echo "WARN $1"; }; fail() { echo "FAIL $1"; exit 1; }\n'
        + HELPERS
        + STEP
    )
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "YES": "true" if yes else "false",
        "SCRIPT_DIR": str(clone),
        "LITE_DIR": str(clone / "claude-code" / "lite"),
        "SHARED_DIR": str(clone / "claude-code" / "shared"),
        "PROJECT_DIR": str(project),
    }
    if pty_answers is None:
        p = subprocess.run(
            ["/bin/bash", str(run)],
            input="",
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        return p.returncode, p.stdout + p.stderr
    p = subprocess.run(  # script gives the step a pty on stdin; its stdout stays piped
        ["script", "-qec", f"/bin/bash {run} | cat", "/dev/null"],
        input=pty_answers,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    return p.returncode, p.stdout + p.stderr


def _backups(project):
    return sorted(project.rglob("*.vhir-backup-*"))


def test_without_a_terminal_or_y_the_users_files_are_kept(tmp_path, clone):
    project = _project(tmp_path)
    before = _user_state(clone, project)
    rc, out = _run(tmp_path, clone, project)
    assert rc == 0, out
    assert {p: p.read_bytes() for p in before} == before
    assert out.count("NOT deployed") == 3 and _backups(project) == []
    assert (project / "FORENSIC_DISCIPLINE.md").exists()  # absent: deployed
    assert "TOOL_REFERENCE" not in out  # identical: quiet


def test_y_replaces_with_backups_and_the_undo_block_restores(tmp_path, clone):
    project = _project(tmp_path)
    before = _user_state(clone, project)
    hook = project / "hooks" / "forensic-audit.sh"
    hook.parent.mkdir()
    hook.write_text("#!/bin/bash\necho my own hook\n")
    hook.chmod(0o755)
    before[hook] = hook.read_bytes()
    (project / "CLAUDE.md").chmod(0o664)  # group-write: a copy without -p loses it
    (project / ".claude" / "settings.json").chmod(0o600)
    modes = {p: stat.S_IMODE(p.stat().st_mode) for p in before}
    rc, out = _run(tmp_path, clone, project, yes=True)
    assert rc == 0, out
    assert (project / "CLAUDE.md").read_text() == "valhuntir CLAUDE.md\n"
    backups = _backups(project)
    assert len(backups) == 4 and not any(b.name.endswith(".md") for b in backups)
    for b in backups:  # each backup has its original's bytes and mode
        orig = Path(str(b).split(".vhir-backup-")[0])
        assert (b.read_bytes(), stat.S_IMODE(b.stat().st_mode)) == (
            before[orig],
            modes[orig],
        )
    undo = [ln.strip() for ln in out.splitlines() if ln.strip().startswith("cp -p ")]
    assert len(undo) == 4
    # and repeated as the script's last output
    tail = SCRIPT[SCRIPT.index("# The undo block, repeated") :]
    run = tmp_path / "tail.sh"
    run.write_text('BOLD=; RED=; NC=; PROJECT_DIR=p\nUNDO_LINES=("$@")\n' + tail)
    last = subprocess.run(
        ["/bin/bash", str(run), *undo], capture_output=True, text=True, check=True
    ).stdout
    assert [ln.strip() for ln in last.splitlines()[1:5]] == undo
    # a second change in the same second gets its own backup
    (project / "CLAUDE.md").write_text("EDITED AGAIN\n")
    _run(tmp_path, clone, project, yes=True)
    claude = sorted(project.glob("CLAUDE.md.vhir-backup-*"))
    assert [b.read_text() for b in claude] == ["MY OWN CLAUDE.md\n", "EDITED AGAIN\n"]
    subprocess.run(["/bin/bash", "-c", "\n".join(undo)], check=True)
    assert {p: p.read_bytes() for p in before} == before
    assert {p: stat.S_IMODE(p.stat().st_mode) for p in before} == modes
    assert modes[hook] == 0o755


@pytest.mark.skipif(not shutil.which("script"), reason="needs script(1)")
@pytest.mark.parametrize(
    "answer,replaced", [("n", False), ("", False), ("y", True)], ids=["n", "Enter", "y"]
)
def test_at_a_terminal_it_asks_and_defaults_to_no(tmp_path, clone, answer, replaced):
    project = _project(tmp_path)
    before = _user_state(clone, project)
    rc, out = _run(tmp_path, clone, project, pty_answers=f"{answer}\n" * 3)
    assert out.count("with Valhuntir's? [y/N]") == 3, out  # stdin is the terminal
    after = {p: p.read_bytes() for p in before}
    assert (after != before) is replaced
    assert (len(_backups(project)) == 3) is replaced


def _r5(tmp_path, clone):
    project = _project(tmp_path)
    rc, out = _run(tmp_path, clone, project)  # as today
    assert rc == 0, out
    lite, shared = clone / "claude-code" / "lite", clone / "claude-code" / "shared"
    want = {  # every file, its bytes and its mode
        "CLAUDE.md": ((lite / "CLAUDE.md").read_bytes(), 0o644),
        "FORENSIC_DISCIPLINE.md": (
            (lite / "FORENSIC_DISCIPLINE.md").read_bytes(),
            0o644,
        ),
        "TOOL_REFERENCE.md": ((lite / "TOOL_REFERENCE.md").read_bytes(), 0o644),
        "FORENSIC_TOOLS.md": ((shared / "FORENSIC_TOOLS.md").read_bytes(), 0o644),
        "hooks/forensic-audit.sh": (HOOK_V2.encode(), 0o755),
        ".claude/settings.json": (
            SETTINGS.replace("$CLAUDE_PROJECT_DIR", str(project)).encode(),
            0o644,
        ),
        ".claude/commands/case.md": (b"valhuntir case command\n", 0o644),
    }
    got = {
        str(f.relative_to(project)): (f.read_bytes(), stat.S_IMODE(f.stat().st_mode))
        for f in project.rglob("*")
        if f.is_file()
    }
    assert got == want
    return project


def test_anchor_an_empty_project_gets_every_file(tmp_path, clone):
    _r5(tmp_path, clone)


def test_a_re_run_is_silent(tmp_path, clone):
    project = _r5(tmp_path, clone)
    rc, out = _run(tmp_path, clone, project)
    assert rc == 0 and out.strip() == "" and _backups(project) == [], out


def test_an_older_shipped_hook_is_replaced_without_asking(tmp_path, clone):
    project = _project(tmp_path)
    (project / "hooks").mkdir()
    (project / "hooks" / "forensic-audit.sh").write_text(HOOK_V1)
    rc, out = _run(tmp_path, clone, project)  # no terminal, no -y
    assert rc == 0, out
    assert (project / "hooks" / "forensic-audit.sh").read_text() == HOOK_V2
    assert "Updated forensic-audit.sh (an earlier Valhuntir version)" in out
    assert "NOT deployed" not in out and _backups(project) == []


# --- The .mcp.json merge ------------------------------------------------------

_m = SCRIPT.index('"$VENV_PYTHON" -c "\nimport json, sys, os\n\nmanaged')
MERGE = SCRIPT[_m : SCRIPT.index("\n# =====", _m)]


def _merge(tmp_path, existing):
    mcp = tmp_path / ".mcp.json"
    if existing is not None:
        mcp.write_text(existing)
    run = tmp_path / "merge.sh"
    run.write_text(
        "set -euo pipefail\n"
        'ok() { echo "OK $1"; }; warn() { echo "WARN $1"; }; fail() { echo "FAIL $1"; exit 1; }\n'
        f"VENV_PYTHON={json.dumps(os.environ.get('PYTHON', shutil.which('python3')))}\n"
        f"MCP_JSON='{mcp}'\n"
        "_MANAGED_SERVERS='[\"forensic-rag\"]'\n"
        '_NEW_CORE=\'{"mcpServers": {"forensic-rag": {"command": "x"}}}\'\n' + MERGE
    )
    p = subprocess.run(
        ["/bin/bash", str(run)], capture_output=True, text=True, timeout=60
    )
    return p.returncode, p.stdout + p.stderr, mcp


def test_an_unparseable_mcp_json_is_left_with_the_entries(tmp_path):
    rc, out, mcp = _merge(tmp_path, '{"mcpServers": {"mine": ')
    assert rc == 0 and mcp.read_text() == '{"mcpServers": {"mine": '
    assert "NOT changed" in out and "forensic-rag" in out and "preserved" not in out


def test_anchor_a_file_without_mcp_servers_is_merged(tmp_path):
    rc, out, mcp = _merge(tmp_path, '{"other": 1}\n')
    assert rc == 0 and "preserved" in out
    assert json.loads(mcp.read_text())["mcpServers"] == {
        "forensic-rag": {"command": "x"}
    }


# --- after .mcp.json is left alone, the optional servers don't abort -----------

_p5 = SCRIPT.index('header "Phase 5: Optional MCPs"')
PHASE5_TO_END = SCRIPT[_p5:]
_w = SCRIPT.index("_write_install_marker() {")
MARKER = SCRIPT[  # to the next top-level definition: its Python has a "}" line
    _w : re.compile(r"^[A-Za-z_]+\(\) \{$", re.M).search(SCRIPT, _w + 1).start()
]


def _phase5(tmp_path, mcp_text):
    mcp = tmp_path / "my project" / ".mcp.json"
    mcp.parent.mkdir(parents=True, exist_ok=True)
    mcp.write_text(mcp_text)
    (tmp_path / ".vhir").mkdir(exist_ok=True)  # made by the earlier phases
    run = tmp_path / "phase5.sh"
    run.write_text(
        "set -euo pipefail\nBOLD=; RED=; GREEN=; YELLOW=; NC=\n"
        'ok() { echo "OK $1"; }; warn() { echo "WARN $1"; }; fail() { echo "FAIL $1"; exit 1; }\n'
        'header() { echo "== $1"; }\n'
        + MARKER
        + 'UNDO_LINES=("cp -p a\\ b c")\n'  # an earlier replacement's undo line
        + PHASE5_TO_END
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "YES": "true",
        "VENV_PYTHON": shutil.which("python3"),
        "VENV_DIR": str(tmp_path / "venv"),
        "SCRIPT_DIR": str(tmp_path),
        "PROJECT_DIR": str(mcp.parent),
        "MCP_JSON": str(mcp),
        "INDEX_DIR": str(tmp_path),
        "INSTALL_MSLEARN": "true",
        "INSTALL_ZELTSER": "true",
        "INSTALL_OPENCTI": "false",
        "INSTALL_RAG": "false",
        "INSTALL_TRIAGE": "false",
        "INSTALL_REGISTRY": "false",
        "SKIP_OPTIONAL_MCPS": "false",
        "REMNUX_ADDR": "",
    }
    p = subprocess.run(
        ["/bin/bash", str(run)], capture_output=True, text=True, env=env, timeout=60
    )
    return p.returncode, p.stdout + p.stderr, mcp


def test_an_unparseable_mcp_json_doesnt_stop_the_optional_servers(tmp_path):
    rc, out, mcp = _phase5(tmp_path, '{"mcpServers": {"mine": ')
    assert rc == 0, out
    assert mcp.read_text() == '{"mcpServers": {"mine": '
    assert out.count("NOT added. Add it to") == 2
    assert '"microsoft-learn": {' in out and '"zeltser-ir-writing": {' in out
    assert "OK Added" not in out
    assert "microsoft-learn (documentation)" not in out  # not listed as installed
    assert out.rstrip().endswith("cp -p a\\ b c")  # the end, with the undo block


def test_anchor_a_valid_mcp_json_gets_the_optional_servers(tmp_path):
    rc, out, mcp = _phase5(tmp_path, '{"mcpServers": {"mine": {}}}')
    assert rc == 0, out
    servers = json.loads(mcp.read_text())["mcpServers"]
    assert list(servers) == ["mine", "microsoft-learn", "zeltser-ir-writing"]
    assert out.count("OK Added") == 2 and "microsoft-learn (documentation)" in out


def test_a_link_planted_at_the_staging_path_isnt_written_through(tmp_path, clone):
    project = _project(tmp_path)
    target = tmp_path / "elsewhere.json"
    target.write_text("NOT YOURS\n")
    (project / ".claude" / "settings.json.vhir-new").symlink_to(target)
    (project / ".claude" / "settings.json").write_text('{"mine": true}\n')
    rc, out = _run(tmp_path, clone, project)  # no terminal, no -y
    assert rc == 0, out
    assert target.read_text() == "NOT YOURS\n"
    assert (project / ".claude" / "settings.json").read_text() == '{"mine": true}\n'
    assert "settings.json differs" in out and "NOT deployed" in out
    assert not (project / ".claude" / "settings.json.vhir-new").exists()
