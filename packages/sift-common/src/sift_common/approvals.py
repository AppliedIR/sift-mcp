"""Whether each APPROVED item a tool returns still verifies.

The verdict is vhir's own: `ledger_verify.approved_view`, the one check
report-mcp and the portal use. Nothing here judges an approval.
"""

from __future__ import annotations

from pathlib import Path


def mark_approvals(case_dir, items: list) -> str:
    """Set `approval_verification` on each APPROVED item in `items`: "VALID"
    when it verifies, else why not (e.g. ALTERED_AFTER_APPROVAL), or
    UNVERIFIED when the check can't run. Returns a one-line warning naming
    those that don't verify ("" when all do)."""
    approved = [
        i for i in items if isinstance(i, dict) and i.get("status") == "APPROVED"
    ]
    if not approved:
        return ""
    try:
        from vhir_cli.ledger_verify import approved_view

        failed = {
            n["id"]: n["status"] for n in approved_view(Path(case_dir))["not_verified"]
        }
        why = ""
    except Exception as e:  # noqa: BLE001 - never read as approved when unchecked
        failed = {i.get("id"): "UNVERIFIED" for i in approved}
        why = f" (couldn't verify: {e})"
    for item in approved:
        item["approval_verification"] = failed.get(item.get("id"), "VALID")
    bad = [f"{i.get('id')} {i['approval_verification']}" for i in approved
           if i["approval_verification"] != "VALID"]  # fmt: skip
    if not bad:
        return ""
    return (
        f"Not approved as recorded{why}: {', '.join(bad)}. The examiner must "
        "review these again; don't build on them as approved."
    )
