"""Where a file is: its mount, read from /proc/self/mountinfo."""

from sift_common import file_place

MOUNTINFO = (
    "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
    "40 22 0:35 / /mnt/case\\040one rw - fuse.ewfmount ewfmount rw\n"
    "41 40 7:0 / /mnt/case\\040one/fs ro - ntfs3 /dev/loop0 ro\n"
    "42 22 7:1 / /mnt/case ro - ntfs3 /dev/loop1 ro\n"
)


def _info(tmp_path, monkeypatch, text=MOUNTINFO):
    f = tmp_path / "mountinfo"
    f.write_text(text)
    monkeypatch.setattr(file_place, "MOUNTINFO", str(f))


def test_mounts_are_read_with_their_points_unescaped(tmp_path, monkeypatch):
    _info(tmp_path, monkeypatch)
    assert file_place.mounts()[1] == (40, "/mnt/case one", "ewfmount")
    assert file_place.mounts()[2] == (41, "/mnt/case one/fs", "/dev/loop0")


def test_a_path_is_on_the_longest_mount_point_holding_it(tmp_path, monkeypatch):
    _info(tmp_path, monkeypatch)
    assert file_place.mnt_id("/mnt/case one/fs/Windows/a.evtx") == 41
    assert file_place.mnt_id("/mnt/case one/ewf1") == 40
    assert file_place.mnt_id("/mnt/case/x") == 42
    assert file_place.mnt_id("/mnt/caseX/x") == 22  # a prefix that isn't a folder


def test_the_last_mount_on_a_point_holds_it(tmp_path, monkeypatch):
    _info(
        tmp_path,
        monkeypatch,
        MOUNTINFO + "43 42 7:2 / /mnt/case ro - ext4 /dev/loop2 ro\n",
    )
    assert file_place.mnt_id("/mnt/case/x") == 43


def test_no_mountinfo_gives_no_mount_id(tmp_path, monkeypatch):
    monkeypatch.setattr(file_place, "MOUNTINFO", str(tmp_path / "none"))
    assert file_place.mnt_id("/x") is None and file_place.mounts() == []
