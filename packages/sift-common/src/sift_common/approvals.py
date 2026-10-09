"""Whether each APPROVED item a tool returns still verifies.

The verdict is vhir's own: `ledger_verify.approved_view`, the one check
report-mcp and the portal use. Nothing here judges an approval.
"""

from __future__ import annotations

from pathlib import Path


def mark_approvals(case_dir, items: list) -> str:
    """Set `approval_verification` on each APPROVED finding in `items`: "VALID"
    only when the item is the record the check verified (same id, same
    content hash), the check's own wording for one approved under 0.6, its
    status when the check lists it as not verified, and UNVERIFIED for
    anything else (an id the check didn't judge, content that differs from
    what it verified, or the check not running). Returns a one-line warning
    naming those that aren't approved as recorded ("" when all are)."""
    approved = [
        i for i in items if isinstance(i, dict) and i.get("status") == "APPROVED"
    ]
    if not approved:
        return ""
    why = ""
    try:
        from vhir_cli.ledger_verify import _record_sha, approved_view

        view = approved_view(Path(case_dir))
        verdicts = {v.item_id: v for v in view["result"].items}
        marks = {n["id"]: n["status"] for n in view["not_verified"]}
        for record in view["findings"]:
            v = verdicts[str(record["id"])]
            marks[record["id"]] = (v.content_sha256, v.view, view["labels"].get(
                record["id"]) if v.status == "APPROVED_UNDER_0_6" else "VALID")  # fmt: skip
    except Exception as e:  # noqa: BLE001 - never read as approved when unchecked
        marks, why = {}, f" (couldn't verify: {e})"
    bad = []
    for item in approved:
        mark, ok = marks.get(item.get("id"), "UNVERIFIED"), False
        if isinstance(mark, tuple):  # verified: only if this is that record
            sha, view_n, label = mark
            ok = _record_sha(item, "finding", view_n) == sha
            mark = label if ok else "UNVERIFIED"
        item["approval_verification"] = mark
        if not ok:
            bad.append(f"{item.get('id')} {mark}")
    if not bad:
        return ""
    return (
        f"Not approved as recorded{why}: {', '.join(bad)}. The examiner must "
        "review these again; don't build on them as approved."
    )
