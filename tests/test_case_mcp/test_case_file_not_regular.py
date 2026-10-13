"""case-mcp refuses a case data file that isn't a regular file, unread.

`evidence.json`, `findings.json`, an audit log or the file-identity log as a
FIFO (held open by another process, with case data in it) or a link to
/dev/zero: each tool answers at once, takes nothing out of the pipe, and
leaves the file as it is. Each call runs in a forked child with a hard join
timeout and its address space capped, so a blocking read fails the test
instead of hanging it, and an endless read fails instead of taking the box's
memory.
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import resource
import select
import signal
import stat
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are POSIX")

X_SHA = "42a33254c2648e3d5f93077128bc31ce8c2be9eabc1899172d6f0384e4e8cb8e"
A_SHA = "010392a9864a"  # the start of kape/a.txt's real hash


def _within(fn, timeout=8.0):
    """What `fn` returns in a forked child, or ("blocked",) if it doesn't
    within `timeout` (the child is then killed). The child's address space is
    capped at its size plus 1 GiB."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # the child: answer through the pipe, then exit at once
        os.close(r)
        try:
            with open("/proc/self/statm") as f:
                size = int(f.read().split()[0]) * os.sysconf("SC_PAGE_SIZE")
            resource.setrlimit(resource.RLIMIT_AS, (size + (1 << 30), size + (1 << 30)))
            out = ("ok", fn())
        except BaseException as e:  # noqa: BLE001 - reported to the parent
            out = ("raised", f"{type(e).__name__}: {e}")
        os.write(w, pickle.dumps(out))
        os._exit(0)
    os.close(w)
    try:
        ready, _, _ = select.select([r], [], [], timeout)
        if not ready:
            os.kill(pid, signal.SIGKILL)
            return ("blocked",)
        data = b""
        while chunk := os.read(r, 65536):
            data += chunk
        return pickle.loads(data)
    finally:
        os.close(r)
        os.waitpid(pid, 0)


@pytest.fixture
def env(tmp_path, monkeypatch):
    import case_mcp.server as cs

    for var in (
        "VHIR_CASE_DIR",
        "VHIR_CASES_DIR",
        "VHIR_ACTIVE_CASE",
        "VHIR_AUDIT_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    active = tmp_path / "active_case"
    monkeypatch.setattr(cs, "_ACTIVE_CASE_FILE", active)
    held: list[int] = []

    def case(name):
        d = tmp_path / "cases" / name
        for sub in ("audit", "evidence/kape"):
            (d / sub).mkdir(parents=True)
        (d / "CASE.yaml").write_text(
            f"case_id: {name}\nstatus: open\nexaminer: tester\n"
        )
        (d / "findings.json").write_text("[]")
        (d / "timeline.json").write_text("[]")
        (d / "evidence.json").write_text(json.dumps({"files": []}))
        (d / "evidence" / "x.bin").write_bytes(b"registered evidence bytes\n")
        (d / "evidence" / "kape" / "a.txt").write_bytes(b"kape file a\n")
        (d / "evidence" / "kape" / "b.txt").write_bytes(b"kape file b\n")
        active.write_text(f"{d}\n")
        return d

    def hold(path, payload: bytes):
        """`path` as a FIFO another process holds open, with `payload` in it."""
        path.unlink(missing_ok=True)
        os.mkfifo(path)
        fd = os.open(path, os.O_RDWR)
        os.write(fd, payload)
        held.append(fd)

    def tool(name, **args):
        """The tool's answer, run in a forked child."""
        from case_mcp.server import create_server

        def call():
            fn = create_server()._tool_manager._tools[name].fn
            r = fn(**args)
            return r if isinstance(r, dict) else json.loads(r)

        kind, *out = _within(call)
        assert kind == "ok", (kind, out)
        return out[0]

    yield case, hold, tool
    for fd in held:
        os.close(fd)


def _fifo(path):
    path.unlink(missing_ok=True)
    os.mkfifo(path)


def _is_fifo(path) -> bool:
    return stat.S_ISFIFO(os.lstat(path).st_mode)


def test_a_fifo_registry_refuses_registration_and_is_kept(env):
    case, hold, tool = env
    d = case("fifo-registry")
    _fifo(d / "evidence.json")
    reg = d / "evidence.json"
    assert tool("evidence_register", path=str(d / "evidence" / "x.bin")) == {
        "error": f"{reg} can't be read as JSON ({reg} isn't a regular file (a named pipe, socket or device). Put the case's own file back, then try again.); nothing was "
        "registered. Fix or restore it, then register again."
    }
    assert _is_fifo(reg)


def test_a_held_fifo_registry_lists_and_verifies_nothing_from_the_pipe(env):
    case, hold, tool = env
    d = case("held-fifo-registry")
    hold(d / "evidence.json", json.dumps({"files": [{"path": "/from/the/pipe",
                                                     "sha256": "ab" * 32}]}).encode())  # fmt: skip
    error = {
        "error": f"{d / 'evidence.json'} isn't a regular file (a named pipe, socket or device). Put the case's own file back, then try again."
    }
    assert tool("evidence_list") == error
    assert tool("evidence_verify") == error
    assert _is_fifo(d / "evidence.json")


def test_a_registry_linked_to_dev_zero_is_refused(env):
    case, hold, tool = env
    d = case("zero-registry")
    (d / "evidence.json").unlink()
    (d / "evidence.json").symlink_to("/dev/zero")
    assert tool("evidence_list") == {
        "error": f"{d / 'evidence.json'} isn't a regular file (a named pipe, socket or device). Put the case's own file back, then try again."
    }


@pytest.mark.parametrize("how", ["held fifo", "dev zero"])
def test_a_findings_file_that_isnt_regular_gives_the_case_status_an_error(env, how):
    case, hold, tool = env
    d = case(f"findings-{how.replace(' ', '-')}")
    if how == "held fifo":
        hold(d / "findings.json", b'[{"id": "F-planted-001"}]')
    else:
        (d / "findings.json").unlink()
        (d / "findings.json").symlink_to("/dev/zero")
    assert tool("case_status") == {
        "error": f"{d / 'findings.json'} isn't a regular file (a named pipe, socket or device). Put the case's own file back, then try again."
    }


def test_an_audit_log_held_as_a_fifo_is_named_and_its_entry_isnt_taken(env):
    """The pipe holds an entry recording x.bin as this case's output: unread,
    so the file registers as one with an unchecked derivation."""
    case, hold, tool = env
    d = case("held-fifo-log")
    entry = {"audit_id": "wintools-rig-20261012-001", "tool": "x", "outputs": [
        {"path": str(d / "evidence" / "x.bin"), "sha256": X_SHA}]}  # fmt: skip
    hold(d / "audit" / "wintools-mcp.jsonl", (json.dumps(entry) + "\n").encode())
    r = tool("evidence_register", path=str(d / "evidence" / "x.bin"))
    assert "error" not in r, r  # read, it would be "an output this case recorded"
    assert {k: r.get(k) for k in ("path", "sha256", "derivation_note")} == {
        "path": str(d / "evidence" / "x.bin"),
        "sha256": X_SHA,
        "derivation_note": "derivation unchecked: audit/wintools-mcp.jsonl can't be read "
        f"({d / 'audit' / 'wintools-mcp.jsonl'} isn't a regular file (a named pipe, socket or device). Put the case's own file back, then try again.)",
    }
    assert _is_fifo(d / "audit" / "wintools-mcp.jsonl")


def test_a_file_identity_log_held_as_a_fifo_doesnt_give_a_folder_its_hashes(env):
    """The pipe holds a finished hash for kape/a.txt (cdcd…) with a.txt's
    exact stat key: unread, so the manifest keeps a.txt's real hash."""
    case, hold, tool = env
    d = case("held-fifo-file-identity")
    a = d / "evidence" / "kape" / "a.txt"
    st = os.stat(a)
    row = {"tool": "hash_complete", "job_id": "hash-planted", "path": os.path.realpath(a),
           "sha256": "cd" * 32, "size": st.st_size, "st_dev": st.st_dev, "st_ino": st.st_ino,
           "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns}  # fmt: skip
    hold(d / "audit" / "file-identity.jsonl", (json.dumps(row) + "\n").encode())
    r = tool("evidence_register", path=str(d / "evidence" / "kape"))
    assert {k: r.get(k) for k in ("kind", "file_count", "derivation_note")} == {
        "kind": "folder",
        "file_count": 2,
        "derivation_note": "derivation unchecked: audit/file-identity.jsonl can't be read "
        f"({d / 'audit' / 'file-identity.jsonl'} isn't a regular file (a named pipe, socket or device). Put the case's own file back, then try again.)",
    }
    (manifest,) = (d / "evidence-manifests").glob("*.json")
    rows = {f["path"]: f["sha256"] for f in json.loads(manifest.read_text())["files"]}
    assert rows["evidence/kape/a.txt"].startswith(A_SHA)
    assert rows["evidence/kape/a.txt"] == hashlib.sha256(a.read_bytes()).hexdigest()
    assert _is_fifo(d / "audit" / "file-identity.jsonl")
