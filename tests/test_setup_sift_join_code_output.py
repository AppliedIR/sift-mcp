"""setup-sift.sh --remote shows why 'vhir setup join-code' gave no code.

Only the join-code block runs, with a stub vhir; nothing is installed.
"""

import subprocess
from pathlib import Path

import pytest

TEXT = (Path(__file__).resolve().parents[1] / "setup-sift.sh").read_text()
START = "        # Generate join code for the remote LLM client machine"
END = '    else\n        warn "Gateway not responding.'
PROLOGUE = (
    "set -euo pipefail\nBOLD=; NC=\n"
    'warn() { echo "[WARN] $*"; }\n'
    'prompt_yn() { [[ "$WINDOWS" == y ]]; }\n'
    'HOST_IP=192.0.2.5; GATEWAY_PORT=4508; VENV_DIR="$STUB"\n'
)
WINDOWS_LINE = (
    "  Set-ExecutionPolicy -Scope Process Bypass -Force; cd $env:TEMP; "
    "Invoke-WebRequest "
    "https://github.com/AppliedIR/wintools-mcp/archive/refs/heads/main.zip "
    "-OutFile wintools.zip; if ($?) { Expand-Archive wintools.zip "
    "-DestinationPath . -Force; if ($?) { "
    ".\\wintools-mcp-main\\scripts\\setup-windows.ps1 -JoinCode ABCD-EFGH "
    "-GatewayHost 192.0.2.5 -GatewayPort 4508 } }"
)
OK = (  # what join-code prints when it works
    "STUB-SETUP-TEXT\n"
    "\nJoin code: ABCD-EFGH (expires in 2 hours)\n"
    "\nOn Windows, in PowerShell as Administrator, download the current "
    "installer and run it (one line):\n"
    f"{WINDOWS_LINE}\n"
    "  Unattended: add -NonInteractive -AcknowledgeSecurityHole after the port number\n"
    "\nWhen the installer has finished: run 'vhir setup client' on each "
    "examiner machine, then /mcp in Claude Code\n"
)
STOPPED = (
    "\nError: Samba share setup failed: smbd restart failed\n"
    "No join code was shown: the Windows installer can't use this SIFT box"
    " until this step works.\n"
    "Fix the cause above, then run 'vhir setup join-code' again.\n"
)


def _run(tmp_path, outputs, windows="n"):
    """Run the block; the stub vhir's Nth call prints outputs[N] (rc 1 if no code)."""
    stub = tmp_path / "venv"
    (stub / "bin").mkdir(parents=True)
    for i, text in enumerate(outputs):
        (tmp_path / f"out{i}").write_text(text)
    vhir = stub / "bin" / "vhir"
    vhir.write_text(
        "#!/bin/bash\n"
        f'n=$(cat "{tmp_path}/n" 2>/dev/null || echo 0); echo $((n + 1)) > "{tmp_path}/n"\n'
        f'cat "{tmp_path}/out$n"; grep -q "Join code:" "{tmp_path}/out$n"\n'
    )
    vhir.chmod(0o755)
    script = tmp_path / "block.sh"
    script.write_text(PROLOGUE + TEXT[TEXT.index(START) : TEXT.index(END)])
    p = subprocess.run(
        ["/bin/bash", str(script)],
        env={"PATH": "/usr/bin:/bin", "STUB": str(stub), "WINDOWS": windows},
        capture_output=True,
        text=True,
        timeout=30,
    )
    return p.returncode, p.stdout + p.stderr


def _reason_then_warning(out, warning):
    assert "Error: Samba share setup failed: smbd restart failed" in out, out
    assert "run 'vhir setup join-code' again" in out
    assert out.index("Samba share setup failed") < out.index(warning)


def test_no_client_code_shows_join_codes_reason_before_the_warning(tmp_path):
    rc, out = _run(tmp_path, [STOPPED])
    assert rc == 0
    _reason_then_warning(out, "Could not generate join code")
    assert "--code=" not in out


def test_no_windows_code_shows_join_codes_reason_and_a_warning(tmp_path):
    rc, out = _run(tmp_path, [OK, STOPPED], windows="y")
    assert rc == 0
    assert "--code=ABCD-EFGH" in out  # the client code still shows
    _reason_then_warning(out, "Could not generate the Windows join code")
    assert "Windows Workstation" not in out


@pytest.mark.parametrize("windows", ["n", "y"])
def test_a_code_shows_with_only_the_windows_lines_of_join_codes_text(tmp_path, windows):
    rc, out = _run(tmp_path, [OK, OK], windows=windows)
    assert rc == 0 and "--code=ABCD-EFGH" in out, out
    assert "STUB-SETUP-TEXT" not in out and "Could not generate" not in out
    assert (WINDOWS_LINE in out.splitlines()) == (windows == "y")
    assert "Unattended:" in out if windows == "y" else "On Windows" not in out


def test_the_windows_code_comes_with_join_codes_one_liner_not_the_old_prompt(tmp_path):
    rc, out = _run(tmp_path, [OK, OK], windows="y")
    assert rc == 0
    lines = out.splitlines()
    i = lines.index("Join code: ABCD-EFGH (expires in 2 hours)")
    assert lines[i - 1] == "Windows Workstation"
    assert WINDOWS_LINE in lines[i:]
    assert "The Windows installer will prompt for:" not in out
    assert "If the installer is not already running:" not in out


def test_the_client_lines_start_with_copying_the_ca_to_the_client(tmp_path):
    rc, out = _run(tmp_path, [OK])
    assert rc == 0
    lines = out.splitlines()
    unix = [s for s in lines if ":.vhir/tls/ca-cert.pem ~/.vhir/tls/" in s]
    assert len(unix) == 1 and "mkdir -p ~/.vhir/tls && scp " in unix[0], out
    assert "@192.0.2.5:" in unix[0]
    win = [s for s in lines if s.strip().startswith("Windows:") and "scp " in s]
    assert len(win) == 1 and win[0].endswith(":.vhir/tls/ca-cert.pem ."), out
    # before any installer line, which needs it
    assert lines.index(unix[0]) < lines.index("  Linux (full support):")
