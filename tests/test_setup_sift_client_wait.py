"""setup-sift.sh configures the LLM client only after the gateway answers.

The gateway listens only once every backend has started. 'vhir setup client'
lists the backends from it with one check, and with no answer it configures one
combined server instead of the per-backend ones (the finding challenger then
has no tools). So the installer waits for the serving gateway before setup
client on every route where it started one, and says so once when the wait
runs out.

These tests run the installer from the gateway start, or from the Phase 13b
banner, up to setup client under bash, with a stub curl and a stub vhir that
records whether the gateway had answered when each command ran; nothing is
installed. Both ends of each block exist on the pre-fix revision, so it fails
these rows on behaviour.
"""

import subprocess
import time
from pathlib import Path

import pytest

TEXT = (Path(__file__).resolve().parents[1] / "setup-sift.sh").read_text()
START = "# Phase 13b"
START_GATEWAY = "# Check if gateway is already running"
END = 'rm -f "$CLIENT_LOG"'
TIMEOUT = "The gateway didn't answer within"
REMEDY = (
    "[WARN] The finding challenger needs the per-backend servers. Once the "
    "gateway answers, run:\n"
)
MANUAL = (
    "[WARN] The installer didn't start the gateway (--manual-start): the AI "
    "client may be configured with a single combined server"
)
MANUAL_REMEDY = (
    "[WARN] The finding challenger needs the per-backend servers. After "
    "starting the gateway ({home}/.vhir/start-gateway.sh), run:\n"
)
CLIENT_CMD = "    vhir setup client --client=claude-code --sift=http://127.0.0.1:4508"

PROLOGUE = (
    "set -euo pipefail\n"
    "BOLD=; NC=\n"
    'info() { echo "[INFO] $*"; }; ok() { echo "[OK] $*"; }\n'
    'warn() { echo "[WARN] $*"; }; err() { echo "[ERROR] $*"; }\n'
    "header() { :; }; prompt_yn() { return 1; }; prompt() { echo 2; }\n"
    'GATEWAY_PORT=4508; VENV_DIR="$STUB"; CLIENT=claude-code\n'
    'GATEWAY_START="$HOME/.vhir/start-gateway.sh"; READ_FROM=/dev/null\n'
    'GATEWAY_CONFIG="$HOME/.vhir/gateway.yaml"\n'
    'EXAMINER_NAME=examiner; CASE_DIR="$HOME/cases"\n'
)

# The stub curl's answer, by kind: "up" answers any check; "503" is a gateway
# up but degraded (an HTTP error status, so curl -f fails); "slow" is a /health
# that replies after 10s (its per-backend checks' cap), so an attempt allowed
# less than that times out.
CURL_KINDS = {
    "up": "",
    "503": 'for a; do case "$a" in -f|-sf|-fs) exit 22 ;; esac; done\n',
    "slow": (
        "prev=; for a; do\n"
        '  [ "$prev" = --max-time ] && [ "${a%.*}" -lt 10 ] && exit 28\n'
        "  prev=$a\n"
        "done\n"
    ),
}


def _run(
    tmp_path,
    answer_from,
    *,
    remote=False,
    manual=False,
    bound=None,
    kind="up",
    start=START,
    pre="",
    dies=False,
    timeout=60,
):
    """Run the block; curl answers from its answer_from-th check on (None: never).

    Returns rc, output, the stub vhir's calls (each with ready=yes/no as the
    gateway stood then), the number of /health checks and the elapsed time.
    bound shrinks the wait for speed; on the pre-fix revision there is no local
    wait to shrink, so it is left unchanged. dies makes the direct start's
    gateway process exit at once (a gateway that crashes on start).
    """
    stub = tmp_path / "venv"
    (stub / "bin").mkdir(parents=True)
    vhir = stub / "bin" / "vhir"
    vhir.write_text(
        "#!/bin/bash\n"
        f'r=no; [ -e "{tmp_path}/up" ] && r=yes\n'
        f'echo "$1 $2 ready=$r" >> "{tmp_path}/calls"\n'
        '[ "$2" = join-code ] && echo "Join code: ABCD-EFGH (expires in 2 hours)"\n'
        "exit 0\n"
    )
    vhir.chmod(0o755)
    # The direct start's gateway process: alive, answering only through curl.
    python = stub / "bin" / "python"
    python.write_text("#!/bin/bash\n" + ("exit 1\n" if dies else "exec sleep 30\n"))
    python.chmod(0o755)
    curlbin = tmp_path / "curlbin"
    curlbin.mkdir()
    first = 10**6 if answer_from is None else answer_from
    stubs = {
        "curl": (
            f'n=$(cat "{tmp_path}/n" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "{tmp_path}/n"\n'
            f'[ "$n" -ge {first} ] || exit 7\n'
            + CURL_KINDS[kind]
            + f': > "{tmp_path}/up"; exit 0\n'
        ),
        # No systemd user session: the direct start keeps serving.
        "systemctl": "exit 1",
    }
    for name, body in stubs.items():
        (curlbin / name).write_text(f"#!/bin/bash\n{body}")
        (curlbin / name).chmod(0o755)

    block = TEXT[TEXT.index(start) : TEXT.index(END)]
    if bound is not None:
        block = block.replace("GW_WAIT_BOUND=240", f"GW_WAIT_BOUND={bound}")
    proto = "https" if remote else "http"
    script = tmp_path / "block.sh"
    script.write_text(
        PROLOGUE
        + f"REMOTE_MODE={'true' if remote else 'false'}\n"
        + f"MANUAL_START={'true' if manual else 'false'}\n"
        + f'HEALTH_URL="{proto}://127.0.0.1:4508/health"\n'
        + f'CURL_EXTRA="{"-k" if remote else ""}"\n'
        + (pre or "MODE=recommended; AUTO_YES=true\n")
        # the direct start's stub process is left running: stop it at the end
        + 'trap \'[[ -z "${GATEWAY_PID:-}" ]] || kill "$GATEWAY_PID" 2>/dev/null || :\' EXIT\n'
        + block
    )
    t0 = time.monotonic()
    p = subprocess.run(
        ["/bin/bash", str(script)],
        env={
            "PATH": f"{curlbin}:/usr/bin:/bin",
            "STUB": str(stub),
            "HOME": str(tmp_path),
            "TMPDIR": str(tmp_path),
        },
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    elapsed = time.monotonic() - t0
    calls_file = tmp_path / "calls"
    calls = calls_file.read_text().splitlines() if calls_file.exists() else []
    n_file = tmp_path / "n"
    checks = int(n_file.read_text()) if n_file.exists() else 0
    return p.returncode, p.stdout + p.stderr, calls, checks, elapsed


def _warnings(out):
    return [s for s in out.splitlines() if s.startswith("[WARN]")]


def test_local_setup_client_runs_only_after_the_gateway_answers(tmp_path):
    # The gateway answers from the 4th check on.
    rc, out, calls, _, _ = _run(tmp_path, 4)
    assert rc == 0, out
    assert calls == ["setup client ready=yes"], (calls, out)
    assert TIMEOUT not in out, out


def test_the_progress_line_prints_first_even_when_the_gateway_answers_at_once(
    tmp_path,
):
    rc, out, calls, checks, _ = _run(tmp_path, 1)
    assert rc == 0, out
    lines = out.splitlines()
    assert lines[0] == "[INFO] Waiting up to 240s for the gateway to respond...", out
    assert out.count("Waiting up to") == 1, out
    assert checks == 1, (checks, out)
    assert calls == ["setup client ready=yes"], (calls, out)


@pytest.mark.parametrize("kind", ["503", "slow"])
def test_any_http_answer_counts_and_a_slow_health_is_not_a_timeout(tmp_path, kind):
    # A degraded gateway (HTTP 503) is listening, so its services list is
    # complete; a /health that takes 10s to answer is listening too.
    rc, out, calls, checks, _ = _run(tmp_path, 1, kind=kind, bound=4)
    assert rc == 0, out
    assert calls == ["setup client ready=yes"], (calls, out)
    assert checks == 1, (checks, out)
    assert TIMEOUT not in out, out


def test_local_timeout_warns_once_and_setup_client_still_runs(tmp_path):
    rc, out, calls, _, elapsed = _run(tmp_path, None, bound=3)
    assert rc == 0, out
    assert "[WARN] The gateway didn't answer within 3s: the AI client may be" in out, (
        out
    )
    assert REMEDY + CLIENT_CMD in out, out
    assert len(_warnings(out)) == 2, out  # one message: consequence + remedy
    # the warning comes before setup client's run, which still happens
    assert calls == ["setup client ready=no"], (calls, out)
    assert elapsed >= 2.0, f"did not wait: {elapsed:.2f}s\n{out}"
    assert elapsed <= 30.0, f"not bounded: {elapsed:.2f}s\n{out}"


def test_the_wait_never_takes_the_first_probes_answer(tmp_path):
    # The direct-start probe said ready, then that process was replaced: the
    # serving gateway never answers, so the wait must time out on its own check.
    rc, out, calls, checks, _ = _run(
        tmp_path,
        None,
        bound=3,
        pre=("MODE=recommended; AUTO_YES=true; GW_READY=true\n"),
    )
    assert rc == 0, out
    assert checks >= 2, (checks, out)
    assert TIMEOUT in out, out
    assert calls == ["setup client ready=no"], (calls, out)


def test_remote_polls_once_and_join_code_and_setup_client_follow_ready(tmp_path):
    rc, out, calls, checks, _ = _run(tmp_path, 3, remote=True)
    assert rc == 0, out
    assert calls == ["setup join-code ready=yes", "setup client ready=yes"], (
        calls,
        out,
    )
    assert out.count("Waiting up to") == 1, out  # one poll, not one per step
    assert checks == 3, (checks, out)  # no second poll after the first answer
    assert "--code=ABCD-EFGH" in out, out
    assert TIMEOUT not in out, out


def test_remote_timeout_is_one_message_covering_join_codes_and_client(tmp_path):
    # timeout 90: the pre-fix revision's own 60s remote poll can't be shrunk
    rc, out, calls, _, _ = _run(tmp_path, None, remote=True, bound=3, timeout=90)
    assert rc == 0, out
    assert (
        "[WARN] The gateway didn't answer within 3s: the AI client may be "
        "configured with a single combined server, and no join code was generated."
    ) in out, out
    assert (
        REMEDY + "    vhir setup join-code\n"
        "    vhir setup client --client=claude-code --sift=https://127.0.0.1:4508"
    ) in out, out
    assert "Gateway not responding" not in out, out
    assert len(_warnings(out)) == 2, out
    assert calls == ["setup client ready=no"], (calls, out)


def test_manual_start_with_a_gateway_answering_carries_on_as_ready(tmp_path):
    rc, out, calls, _, _ = _run(tmp_path, 1, manual=True)
    assert rc == 0, out
    assert [c.split(" ready=")[0] for c in calls] == ["setup client"], (calls, out)
    assert "Waiting up to" not in out, out
    assert "[WARN]" not in out, out


def test_manual_start_checks_the_gateway_once_before_setup_client(tmp_path):
    rc, out, calls, checks, _ = _run(tmp_path, 1, manual=True)
    assert rc == 0, out
    assert checks == 1, (checks, out)
    assert calls == ["setup client ready=yes"], (calls, out)


def test_manual_start_with_no_gateway_checks_once_and_says_so_at_once(tmp_path):
    rc, out, calls, checks, elapsed = _run(tmp_path, None, manual=True)
    assert rc == 0, out
    assert checks == 1, (checks, out)  # one immediate check, no wait
    assert "Waiting up to" not in out, out
    assert elapsed < 5.0, f"waited: {elapsed:.2f}s\n{out}"
    assert MANUAL + "." in out, out
    assert MANUAL_REMEDY.format(home=tmp_path) + CLIENT_CMD in out, out
    assert TIMEOUT not in out and "failed" not in out, out
    assert len(_warnings(out)) == 2, out
    assert calls == ["setup client ready=no"], (calls, out)


@pytest.mark.parametrize(
    "pre",
    ["MODE=recommended; AUTO_YES=true\n", "MODE=custom; AUTO_YES=false\n"],
    ids=["no-systemd", "manual-start-choice"],
)
def test_a_cold_direct_start_is_waited_for_and_never_called_failed(tmp_path, pre):
    # The direct-start process is the serving gateway. It answers after the
    # 6s first probe gave up (check 9: the running check, 6 probes, then the
    # wait), so the wait's answer is the last word.
    rc, out, calls, _, _ = _run(tmp_path, 9, start=START_GATEWAY, pre=pre)
    assert rc == 0, out
    assert "failed" not in out.lower(), out
    assert TIMEOUT not in out, out
    assert calls == ["setup client ready=yes"], (calls, out)


@pytest.mark.parametrize(
    "pre",
    ["MODE=recommended; AUTO_YES=true\n", "MODE=custom; AUTO_YES=false\n"],
    ids=["no-systemd", "manual-start-choice"],
)
def test_a_direct_start_that_dies_ends_the_wait_and_says_it_isnt_running(tmp_path, pre):
    # The direct-start process is the serving gateway and exits at once: no
    # process is left to answer, so the wait ends then, not at the bound.
    rc, out, calls, _, elapsed = _run(
        tmp_path, None, start=START_GATEWAY, pre=pre, dies=True, bound=30
    )
    assert rc == 0, out
    assert (
        "[WARN] The gateway process isn't running (it exited after it started): "
        "the AI client may be configured with a single combined server.\n"
        "[WARN] The finding challenger needs the per-backend servers. Check "
        f"{tmp_path}/.vhir/gateway.yaml, start the gateway "
        f"({tmp_path}/.vhir/start-gateway.sh), then run:\n" + CLIENT_CMD
    ) in out, out
    assert TIMEOUT not in out, out
    assert calls == ["setup client ready=no"], (calls, out)
    assert elapsed < 15.0, f"waited for the bound: {elapsed:.2f}s\n{out}"
