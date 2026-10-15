"""setup-sift.sh --remote waits for the gateway before generating join codes.

A gateway just started by systemd often does not answer /health on the first
check. The Multi-Machine Setup block must poll /health (time-bounded) instead
of checking once, or no join code is generated on a fresh --remote install.

These tests extract the wait block from setup-sift.sh and run it under bash with
a stub curl, so nothing is installed. They fail on the pre-fix revision only
because the single curl check never waits:
  - a gateway that answers a few seconds late is missed -> WARN, no join code;
  - and the WARN path is reached instantly instead of after the bounded wait.
"""

import subprocess
import time
from pathlib import Path

TEXT = (Path(__file__).resolve().parents[1] / "setup-sift.sh").read_text()
START = "    # Wait for gateway to be ready before generating join codes"
END = '\n    echo ""\n    echo -e "${BOLD}SSH Access${NC}"'

PROLOGUE = (
    "set -euo pipefail\n"
    "BOLD=; NC=\n"
    'info() { echo "[INFO] $*"; }\n'
    'warn() { echo "[WARN] $*"; }\n'
    "prompt_yn() { return 1; }\n"  # always "no" -> skip the Windows sub-block
    'HOST_IP=192.0.2.5; GATEWAY_PORT=4508; VENV_DIR="$STUB"\n'
    'GATEWAY_START="systemctl --user start vhir-gateway"\n'
    'HEALTH_URL="https://127.0.0.1:4508/health"\n'
    'CURL_EXTRA="-k"\n'
)


def _run(tmp_path, curl_body, *, reduce_bound=False, timeout=90):
    """Run the wait block with a stub curl whose body decides each call's rc.

    reduce_bound shrinks the ~60s elapsed bound to 4s so the no-gateway case
    finishes quickly; the substring it replaces does not exist on the pre-fix
    revision (no loop), so that revision is unaffected and still checks once.
    """
    stub = tmp_path / "venv"
    (stub / "bin").mkdir(parents=True)
    vhir = stub / "bin" / "vhir"
    vhir.write_text("#!/bin/bash\necho 'Join code: ABCD-EFGH (expires in 2 hours)'\n")
    vhir.chmod(0o755)

    curlbin = tmp_path / "curlbin"
    curlbin.mkdir()
    curl = curlbin / "curl"
    curl.write_text("#!/bin/bash\n" + curl_body)
    curl.chmod(0o755)

    block = TEXT[TEXT.index(START) : TEXT.index(END)]
    # Marker sanity: true on both the pre-fix and fixed revisions, so it never
    # short-circuits the behavioral assertions below (the pre-fix block must run
    # its single check and fail on behavior, not on a structural guard).
    assert "curl -sf" in block and "JOIN_READY" in block, block
    if reduce_bound:
        # Shrink the ~60s elapsed bound to 4s for speed. Best-effort: the
        # substring is absent on the pre-fix revision (no loop), so that
        # revision is left untouched and still checks /health exactly once.
        block = block.replace(
            "SECONDS - join_wait_start >= 60", "SECONDS - join_wait_start >= 4"
        )
    script = tmp_path / "block.sh"
    script.write_text(PROLOGUE + block)

    t0 = time.monotonic()
    p = subprocess.run(
        ["/bin/bash", str(script)],
        env={
            "PATH": f"{curlbin}:/usr/bin:/bin",
            "STUB": str(stub),
            "CURLN": str(tmp_path / "n"),
        },
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout + p.stderr, time.monotonic() - t0


def test_late_gateway_is_found_by_the_poll_and_a_join_code_is_shown(tmp_path):
    # curl fails the first 3 checks, then the gateway answers.
    rc, out, _ = _run(
        tmp_path,
        'n=$(cat "$CURLN" 2>/dev/null || echo 0); echo $((n + 1)) > "$CURLN"\n'
        '[ "$n" -lt 3 ] && exit 7\nexit 0\n',
    )
    assert rc == 0, out
    assert "--code=ABCD-EFGH" in out, out  # the poll found the gateway
    assert "Gateway not responding" not in out, out
    # the "waiting" INFO line prints exactly once, only after the first check fails
    assert out.count("Waiting up to 60s for the gateway to respond") == 1, out


def test_no_gateway_warns_after_a_bounded_wait_with_todays_text(tmp_path):
    # curl always fails: the gateway never answers.
    rc, out, elapsed = _run(tmp_path, "exit 7\n", reduce_bound=True, timeout=30)
    assert rc == 0, out
    # output is exactly today's WARN plus the two commands, no join code
    assert "Gateway not responding. Start it first, then generate join codes:" in out, (
        out
    )
    assert "systemctl --user start vhir-gateway" in out, out
    assert "vhir setup join-code" in out, out
    assert "--code=" not in out, out
    # it waited (did not fall through on the first check) but stayed bounded
    assert elapsed >= 3.0, f"did not wait: {elapsed:.2f}s\n{out}"
    assert elapsed <= 20.0, f"not bounded: {elapsed:.2f}s\n{out}"
