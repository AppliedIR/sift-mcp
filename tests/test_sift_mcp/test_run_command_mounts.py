"""run_command records what a mount tool mounted and what an umount removed.

The stub tools "mount" by adding a line to a mountinfo file that the server
reads in place of /proc/self/mountinfo, and "unmount" by taking it away.
Nothing is really mounted.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path

import pytest
from sift_common import file_place
from sift_mcp.server import create_server

BASE_INFO = "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"

MOUNT = """#!/bin/sh
tgt=; prev=
for a; do
  case "$prev" in --target) tgt=$a;; esac
  case "$a" in --target=*) tgt=${a#--target=};; esac
  prev=$a; last=$a
done
[ -n "$tgt" ] || tgt=$last
echo "$((70 + $(wc -l < "$FAKE_MOUNTINFO"))) 22 7:5 / $(realpath "$tgt") ro - $KIND $SRC ro" >> "$FAKE_MOUNTINFO"
"""
UMOUNT = """#!/bin/sh
for a; do last=$a; done
grep -v " $(realpath "$last") " "$FAKE_MOUNTINFO" > "$FAKE_MOUNTINFO.new"
mv "$FAKE_MOUNTINFO.new" "$FAKE_MOUNTINFO"
"""
SUDO = """#!/bin/sh
while [ "${1#-}" != "$1" ]; do case "$1" in -u|-g) shift;; esac; shift; done
exec "$@"
"""
# Mounts, then stays running a while, so two of these overlap
SLOW_MOUNT = """#!/bin/sh
for a; do last=$a; done
echo "$((1000 + $$ % 50000)) 22 7:5 / $(realpath "$last") ro - ntfs3 /dev/loop$$ ro" >> "$FAKE_MOUNTINFO"
sleep 1
"""
FAIL = "#!/bin/sh\nexit 32\n"


@pytest.fixture
def case(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "examiner1")
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    d = tmp_path / "cases" / "case-a"
    (d / "evidence").mkdir(parents=True)
    (d / "extractions").mkdir()
    (d / "CASE.yaml").write_text("case_id: case-a\nstatus: open\n")
    (home / ".vhir" / "active_case").write_text(str(d))
    info = tmp_path / "mountinfo"
    info.write_text(BASE_INFO)
    monkeypatch.setattr(file_place, "MOUNTINFO", str(info))
    monkeypatch.setenv("FAKE_MOUNTINFO", str(info))
    monkeypatch.setenv("KIND", "ntfs3")
    monkeypatch.setenv("SRC", "/dev/loop5")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (
        ("mount", MOUNT),
        ("ewfmount", MOUNT),
        ("umount", UMOUNT),
        ("fusermount", UMOUNT),
        ("sudo", SUDO),
    ):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755 | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return d


def run(case: Path, command: list[str]) -> dict:
    r = asyncio.run(
        create_server().call_tool("run_command", {"command": command, "purpose": "t"})
    )
    r = r[0] if isinstance(r, tuple) else r
    assert json.loads(r[0].text)["success"] is True, r[0].text
    lines = (case / "audit" / "sift-mcp.jsonl").read_text().splitlines()
    return [json.loads(x) for x in lines if x.strip()][-1]


def _image(case: Path) -> Path:
    img = case / "evidence" / "disk.E01"
    img.write_bytes(b"E01")
    (case / "evidence.json").write_text(
        json.dumps({"files": [{"path": str(img.resolve()), "sha256": "e" * 64}]})
    )
    return img


@pytest.mark.parametrize("sudo", [[], ["sudo"]])
def test_a_mount_records_its_image_and_the_point_it_mounted(case, sudo):
    img = _image(case)
    mnt = case / "mnt"
    mnt.mkdir()
    e = run(case, [*sudo, "mount", "-o", "ro,loop", str(img), str(mnt)])
    (point,) = e["mount"]["points"]
    assert e["mount"]["image"] == str(img.resolve())
    assert e["input_registered"] == [str(img.resolve())]
    assert point == {
        "target": str(mnt),
        "realpath": str(mnt.resolve()),
        "st_dev": os.stat(mnt).st_dev,
        "mnt_id": 71,
    }
    assert "sha256" not in json.dumps(e["mount"])  # mount points are never hashed


def test_an_umount_records_the_mount_it_removed_and_pairs_with_it(case):
    img = _image(case)
    mnt = case / "mnt"
    mnt.mkdir()
    point = run(case, ["mount", "-o", "ro,loop", str(img), str(mnt)])["mount"][
        "points"
    ][0]
    e = run(case, ["umount", str(mnt)])
    assert e["umount"] == {"realpath": point["realpath"], "mnt_id": point["mnt_id"]}
    assert "mount" not in e


def test_fusermount_u_is_an_umount_and_a_device_names_its_mount(case, monkeypatch):
    img = _image(case)
    fuse = case / "fuse"
    fuse.mkdir()
    monkeypatch.setenv("KIND", "fuse.ewfmount")
    monkeypatch.setenv("SRC", "ewfmount")
    run(case, ["ewfmount", str(img), str(fuse)])
    e = run(case, ["fusermount", "-u", str(fuse)])
    assert e["umount"]["realpath"] == str(fuse.resolve()) and e["umount"]["mnt_id"]
    monkeypatch.setenv("KIND", "ntfs3")
    monkeypatch.setenv("SRC", "/dev/loop5")
    mnt = case / "mnt"
    mnt.mkdir()
    point = run(case, ["mount", str(img), str(mnt)])["mount"]["points"][0]
    info = Path(file_place.MOUNTINFO)  # a device that exists stands in for the loop
    info.write_text(info.read_text().replace("/dev/loop5", "/dev/null"))
    e = run(case, ["umount", "/dev/null"])
    assert e["umount"] == {"realpath": point["realpath"], "mnt_id": point["mnt_id"]}


def test_a_mount_that_failed_records_no_mount(case, tmp_path):
    img = _image(case)
    (tmp_path / "bin" / "mount").write_text(FAIL)
    r = asyncio.run(
        create_server().call_tool(
            "run_command",
            {"command": ["mount", str(img), str(case)], "purpose": "t"},
        )
    )
    r = r[0] if isinstance(r, tuple) else r
    lines = (case / "audit" / "sift-mcp.jsonl").read_text().splitlines()
    e = json.loads(lines[-1])
    assert e["result_summary"]["exit_code"] == 32 and "mount" not in e


def test_a_command_that_mounts_nothing_has_no_mount_record(case):
    e = run(case, ["ls", str(case)])
    assert "mount" not in e and "umount" not in e


def test_an_umount_that_failed_records_no_umount(case, tmp_path):
    img = _image(case)
    mnt = case / "mnt"
    mnt.mkdir()
    run(case, ["mount", str(img), str(mnt)])
    (tmp_path / "bin" / "umount").write_text(FAIL)
    asyncio.run(
        create_server().call_tool(
            "run_command", {"command": ["umount", str(mnt)], "purpose": "t"}
        )
    )
    lines = (case / "audit" / "sift-mcp.jsonl").read_text().splitlines()
    e = json.loads(lines[-1])
    assert e["result_summary"]["exit_code"] == 32 and "umount" not in e


@pytest.mark.parametrize(
    "command, tool",
    [
        (["sudo", "-u", "root", "mount", "a", "b"], "mount"),
        (["sudo", "-g", "disk", "dc3dd", "if=a"], "dc3dd"),
        (["sudo", "-E", "--", "umount", "b"], "umount"),
        (["timeout", "-s", "KILL", "30", "ewfmount", "a", "b"], "ewfmount"),
        (["nice", "-n", "5", "sudo", "mount", "a", "b"], "mount"),
    ],
)
def test_the_tool_is_found_past_wrappers_and_their_option_values(command, tool):
    from sift_mcp import mounts

    assert mounts.tool_of(command)[0] == tool


def test_sudo_with_a_user_still_records_the_mount(case):
    img = _image(case)
    mnt = case / "mnt"
    mnt.mkdir()
    e = run(case, ["sudo", "-u", "root", "mount", str(img), str(mnt)])
    (point,) = e["mount"]["points"]
    assert point["realpath"] == str(mnt.resolve())


def test_two_mounts_at_once_each_record_only_their_own_point(case, tmp_path):
    import threading

    (tmp_path / "bin" / "mount").write_text(SLOW_MOUNT)
    img = _image(case)
    targets = [case / "mnt-a", case / "mnt-b"]
    for t in targets:
        t.mkdir()

    def go(t):
        asyncio.run(
            create_server().call_tool(
                "run_command", {"command": ["mount", str(img), str(t)], "purpose": "t"}
            )
        )

    threads = [threading.Thread(target=go, args=(t,)) for t in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lines = (case / "audit" / "sift-mcp.jsonl").read_text().splitlines()
    entries = [json.loads(x) for x in lines if '"mount"' in x]
    got = sorted(p["realpath"] for e in entries for p in e["mount"]["points"])
    assert len(entries) == 2 and got == sorted(str(t.resolve()) for t in targets)
    for e in entries:
        (point,) = e["mount"]["points"]
        assert point["target"] in e["params"]["command"]


def test_a_mount_names_its_target_with_the_target_option(case):
    img = _image(case)
    mnt = case / "mnt"
    mnt.mkdir()
    e = run(case, ["mount", f"--source={img}", f"--target={mnt}"])
    (point,) = e["mount"]["points"]
    assert point["realpath"] == str(mnt.resolve()) and point["target"] == str(mnt)
    e = run(case, ["umount", str(mnt)])
    mnt2 = case / "mnt2"
    mnt2.mkdir()
    e = run(case, ["mount", str(img), "--target", str(mnt2)])
    (point,) = e["mount"]["points"]
    assert point["realpath"] == str(mnt2.resolve())
