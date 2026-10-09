"""Reference lookups: what a reference source (threat intel, the Windows
baseline) said, kept so a finding citing it can be checked.

A call to opencti ``lookup_ioc`` or a windows-triage ``check_*`` tool gets an
entry of its own in the active case, with ``reference: {source,
source_version, response: {path, sha256}}``; the raw response is saved at
``extractions/<audit id>/response.json``. ``source_version`` is the version the
backend reported for itself, not its data's version.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os

logger = logging.getLogger(__name__)

_ALIASES = {"threatintel-mcp": "opencti-mcp"}


def is_reference(backend_name: str, tool: str) -> bool:
    source = _ALIASES.get(backend_name, backend_name)
    if source == "opencti-mcp":
        return tool == "lookup_ioc"
    return source == "windows-triage-mcp" and tool.startswith("check_")


def _raw(result) -> bytes:
    """The response's content as the backend returned it: each text item's
    text, any other item as its JSON."""
    parts = []
    for item in result:
        text = getattr(item, "text", None)
        if isinstance(text, str):
            parts.append(text)
        elif hasattr(item, "model_dump"):
            parts.append(json.dumps(item.model_dump(), default=str))
        else:
            parts.append(str(item))
    return "\n".join(parts).encode("utf-8")


def case_for(backend_name: str, tool: str) -> str:
    """The case a reference call is recorded in, resolved once as it starts
    (whatever case is active when it answers); "" for any other call."""
    if not is_reference(backend_name, tool):
        return ""
    from sift_common import resolve_case_dir

    try:
        return resolve_case_dir()
    except Exception as e:  # noqa: BLE001 -- an unreadable case: answered, not recorded
        logger.warning("reference call %s: no case to record it in: %s", tool, e)
        return ""


def record(audit, backend_name: str, backend, tool: str, arguments: dict, result,
           examiner=None, case_dir: str = "") -> str | None:  # fmt: skip
    """Save a reference call's response in ``case_dir`` (from :func:`case_for`)
    and write its entry there; the entry's audit id, or None (no case, or not
    a reference call). Never raises: a lookup is answered whether or not it
    could be recorded."""
    if not case_dir or not is_reference(backend_name, tool):
        return None
    try:
        from sift_gateway.audit_helpers import _truncate_params

        audit_dir = audit._get_audit_dir(case_dir) if case_dir else None
        if not audit_dir:
            return None
        op_id = audit._next_audit_id(audit_dir)
        folder = os.path.join(case_dir, "extractions", op_id)
        os.makedirs(folder)
        data = _raw(result)
        path = os.path.join(folder, "response.json")
        with open(path, "xb") as f:
            f.write(data)
        source = _ALIASES.get(backend_name, backend_name)
        return audit.log(
            tool=tool,
            params=_truncate_params(arguments),
            result_summary="reference response saved",
            source="gateway_proxy",
            audit_id=op_id,
            case_dir=case_dir,
            extra={
                "backend": backend_name,
                "examiner": examiner,
                "reference": {
                    "source": source,
                    "source_version": getattr(backend, "server_version", "") or "",
                    "response": {
                        "path": path,
                        "sha256": hashlib.sha256(data).hexdigest(),
                    },
                },
            },
        )
    except Exception as e:  # noqa: BLE001 -- the lookup still answers
        logger.warning("reference call %s not recorded: %s", tool, e)
        return None
