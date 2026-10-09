"""A scratch case for provenance tests: registered roots (files, and folders with
a manifest, as `vhir evidence register` writes them) and audit entries in the
trail's format. Shared by the provenance tests and, through it, the ingest
check's tests."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def sha(p) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


class TrailCase:
    def __init__(self, d: Path):
        self.d = d
        for sub in ("evidence", "extractions", "audit"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        (d / "evidence.json").write_text('{"files": []}')

    def file(self, rel: str, data: bytes | str) -> str:
        p = self.d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)
        return str(p)

    def _add(self, entry: dict) -> None:
        reg = json.loads((self.d / "evidence.json").read_text())
        reg["files"].append(entry)
        (self.d / "evidence.json").write_text(json.dumps(reg))

    def register(self, path: str, **extra) -> dict:
        entry = {"path": os.path.realpath(path), "sha256": sha(path),
                 "registered_by": "tester", **extra}  # fmt: skip
        self._add(entry)
        return entry

    def register_folder(self, folder: str, **extra) -> dict:
        """As vhir writes a folder root: a manifest file of case-relative rows."""
        base = self.d.resolve()
        rows = [{"path": os.path.relpath(os.path.join(r, n), base),
                 "sha256": sha(os.path.join(r, n))}
                for r, _, names in sorted(os.walk(folder)) for n in sorted(names)]  # fmt: skip
        data = json.dumps({"folder": folder, "files": rows, "skipped": []}).encode()
        n = len(list((self.d / "evidence-manifests").glob("*.json"))) + 1
        (self.d / "evidence-manifests").mkdir(exist_ok=True)
        (self.d / "evidence-manifests" / f"{n}.json").write_bytes(data)
        entry = {"kind": "folder", "path": os.path.realpath(folder),
                 "manifest_path": f"evidence-manifests/{n}.json",
                 "manifest_sha256": hashlib.sha256(data).hexdigest(),
                 "file_count": len(rows), "registered_by": "tester", **extra}  # fmt: skip
        self._add(entry)
        return entry

    def op(self, log: str, aid: str, **fields) -> bytes:
        """One audit entry; returns its line's bytes."""
        entry = {"audit_id": aid, "ts": "2026-10-09T00:00:00Z", "examiner": "tester",
                 **fields}  # fmt: skip
        line = json.dumps(entry).encode()
        with open(self.d / "audit" / f"{log}.jsonl", "ab") as f:
            f.write(line + b"\n")
        return line

    def run(self, aid: str, cmd: list, inputs: list, out_text: str, method="parsed",
            **extra) -> str:  # fmt: skip
        """A run_command entry: hashed inputs, its stdout saved."""
        out = self.file(f"extractions/{aid}.txt", out_text)
        self.op("sift-mcp", aid, tool="run_command",
                params={"command": cmd, "purpose": "p"},
                result_summary={"exit_code": 0, "output_file": out,
                                "output_sha256": sha(out)},
                input_files=inputs,
                input_sha256s=[sha(i) if Path(i).is_file() else "" for i in inputs],
                input_detection_method=method, **extra)  # fmt: skip
        return out

    def extract(
        self, aid: str, archive: str, log="sift-mcp", **extra
    ) -> tuple[str, str]:
        """A recorded 7z extraction of two samples; the archive is a registered
        file, so its input carries no fresh hash."""
        s1 = self.file(f"extractions/{aid}/sample1.raw", "sample one")
        s2 = self.file(f"extractions/{aid}/sample2.raw", "sample two")
        self.op(log, aid, tool="run_command",
                params={"command": ["7z", "x", archive], "purpose": "p"},
                input_files=[archive], input_sha256s=[""], input_detection_method="parsed",
                result_summary={"exit_code": 0, "output_files": [s1, s2],
                                "output_sha256s": [sha(s1), sha(s2)]}, **extra)  # fmt: skip
        return s1, s2

    def mount(
        self, aid: str, image: str, mount_point: str, st_dev: int, **extra
    ) -> None:
        self.op("sift-mcp", aid, tool="run_command",
                params={"command": ["mount", "-o", "ro,loop", image, mount_point]},
                result_summary={"exit_code": 0}, input_files=[image], input_sha256s=[""],
                input_detection_method="parsed",
                mount={"image": image, "points": [
                    {"target": mount_point, "realpath": os.path.realpath(mount_point),
                     "st_dev": st_dev, "mnt_id": st_dev}]}, **extra)  # fmt: skip

    def umount(self, aid: str, mount_point: str, mnt_id: int, **extra) -> None:
        self.op("sift-mcp", aid, tool="run_command",
                params={"command": ["umount", mount_point]},
                umount={"realpath": os.path.realpath(mount_point), "mnt_id": mnt_id},
                **extra)  # fmt: skip
