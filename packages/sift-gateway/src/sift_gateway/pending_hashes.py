"""Hash, on SIFT, the files a wintools call left unhashed.

wintools records a file over its size limit as ``hash_state: pending`` with
its case-relative path (``sift_path``). The gateway finds that file in the
active case and records its hash there: the registry's hash for a registered
file (never re-read), else one from ``hash_for_call`` (in the call, or a
background job whose ``hash_complete`` entry closes it). The paths come from
the remote's reply, so a path that leads outside the case is refused.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


def pending_files(result) -> list[dict]:
    """The pending inputs and outputs in a wintools reply."""
    found = []
    for item in result or []:
        text = getattr(item, "text", None)
        if not isinstance(text, str) or "pending" not in text:
            continue
        try:
            data = json.loads(text)
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        for key in ("inputs", "outputs"):
            for f in data.get(key) or []:
                if isinstance(f, dict) and f.get("hash_state") == "pending":
                    found.append({**f, "role": key[:-1]})
    return found


def hash_in_case(case_dir: Path, files: list[dict], requested_by: str) -> list[dict]:
    """Each pending file's record: its SIFT path and hash, or why not."""
    from sift_common.file_identity import (
        HashResult,
        NotRegularFile,
        hash_for_call,
        registered_hash,
    )

    root = os.path.realpath(case_dir)
    out = []
    for f in files:
        rel = str(f.get("sift_path") or f.get("share_path") or "").replace("\\", "/")
        record = {
            "role": f["role"],
            "sift_path": rel,
            "share_path": f.get("share_path"),
        }
        parts = Path(rel).parts
        if not rel or rel.startswith("/") or ":" in rel or ".." in parts:
            out.append({**record, "error": "not a path in the case"})
            continue
        real = os.path.realpath(os.path.join(root, rel))
        if os.path.commonpath([real, root]) != root:
            out.append({**record, "error": "leads outside the case"})
            continue
        record["path"] = real
        registered = registered_hash(root, real)
        if registered:
            out.append({**record, "sha256": registered, "registered": True})
            continue
        try:
            got = hash_for_call(real, case_dir=root, requested_by=requested_by)
        except (OSError, NotRegularFile) as e:
            out.append({**record, "error": f"{type(e).__name__}: {e}"})
            continue
        if isinstance(got, HashResult):
            out.append({**record, "sha256": got.sha256, "size": got.size})
        elif got is not None:
            out.append({**record, "sha256": f"pending:{got.job_id}"})
    return out
