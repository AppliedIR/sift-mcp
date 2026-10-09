"""The mount and umount records of a run_command call.

A mount tool's run records the image it mounted and every mount point that
appeared while it ran, each as ``/proc/self/mountinfo`` shows it:
``mount: {image, points: [{target, realpath, st_dev, mnt_id}]}``. An umount's
run records the mount it is about to remove, read before it runs:
``umount: {realpath, mnt_id}``. A reader pairs the two by realpath and mount
id. Mount points are never hashed.
"""

from __future__ import annotations

import os

from sift_common import file_place

from sift_mcp import command_files

MOUNT_TOOLS = frozenset({"ewfmount", "mount", "qemu-nbd", "xmount", "losetup"})
_FUSERMOUNT = frozenset({"fusermount", "fusermount3"})
_WRAPPERS = frozenset({"sudo", "nice", "nohup", "time", "timeout", "stdbuf"})


def tool_of(command: list[str]) -> tuple[str, list[str]]:
    """The tool a command runs, past any wrapper (sudo, timeout, ...), and
    its arguments."""
    cmd = list(command)
    while cmd and os.path.basename(cmd[0]) in _WRAPPERS:
        cmd.pop(0)
        while cmd and (cmd[0].startswith("-") or cmd[0][:1].isdigit()):
            cmd.pop(0)
    if not cmd:
        return "", []
    return os.path.basename(cmd[0]), cmd[1:]


def is_mount(command: list[str]) -> bool:
    return tool_of(command)[0] in MOUNT_TOOLS


def _is_umount(name: str, args: list[str]) -> bool:
    if name == "umount":
        return True
    return name in _FUSERMOUNT and any(
        a.startswith("-") and not a.startswith("--") and "u" in a[1:] for a in args
    )


def _positionals(args: list[str]) -> list[str]:
    return [a for a in args if a and not a.startswith("-")]


def mounted() -> dict[int, str]:
    """The mounts there are now: mount id -> mount point."""
    return {mid: point for mid, point, _ in file_place.mounts()}


def mount_record(command, before: dict[int, str], inputs, registered, base=None):
    """``{image, points}`` for a mount tool's successful run, or None when it
    named no image and nothing was mounted. ``before`` is :func:`mounted`
    taken just before the run."""
    name, args = tool_of(command)
    if name not in MOUNT_TOOLS:
        return None
    reg = {r["path"] for r in registered}
    image = next(
        (
            i.get("realpath")
            for i in inputs
            if i.get("found") != "declared"
            and (i.get("realpath") in reg or os.path.isfile(i.get("realpath") or ""))
        ),
        None,
    )
    named = {
        os.path.realpath(command_files.absolute(a, base)): a for a in _positionals(args)
    }
    points = []
    for mid, point, _ in file_place.mounts():
        real = os.path.realpath(point)
        # only this command's own targets: another run may mount at the same time
        if mid in before or real not in named:
            continue
        p: dict = {"target": named[real], "realpath": real}
        try:
            p["st_dev"] = os.stat(real).st_dev
        except OSError:
            p["st_dev"] = None
        p["mnt_id"] = mid
        points.append(p)
    if image is None and not points:
        return None
    return {"image": image, "points": points}


def umount_record(command, base=None):
    """``{realpath, mnt_id}`` of the mount an umount (or ``fusermount -u``) is
    about to remove, read before it runs; None for any other command. A
    target that is a device names the mount whose source it is."""
    name, args = tool_of(command)
    if not _is_umount(name, args):
        return None
    targets = _positionals(args)
    if not targets:
        return None
    real = os.path.realpath(command_files.absolute(targets[-1], base))
    found = None
    for mid, point, source in file_place.mounts():  # the last one mounted wins
        if os.path.realpath(point) == real or (
            source.startswith("/") and os.path.realpath(source) == real
        ):
            found = (os.path.realpath(point), mid)
    if found is None:
        return {"realpath": real, "mnt_id": None}
    return {"realpath": found[0], "mnt_id": found[1]}
