"""Whether each APPROVED item a tool returns still verifies.

The verdict is vhir's own: `ledger_verify.approved_view`, the one check
report-mcp and the portal use. Nothing here judges an approval.
"""

from __future__ import annotations

from pathlib import Path

_VIEW_KEYS = {"finding": "findings", "timeline": "timeline"}


def _an_id(value) -> bool:
    """Whether `value` can be a record's id: a list or a dict id is checked by
    nothing, so its item reads UNVERIFIED (and can't be a key)."""
    return value is None or isinstance(value, (str, int))


def mark_approvals(case_dir, items: list, kind: str = "finding", *, timeline=()) -> str:
    """Set `approval_verification` on each APPROVED item in `items` (of
    `kind`, finding or timeline) and in `timeline` (events), with one check
    and one warning for both: "VALID"
    only when the item is the record the check verified (same id, same
    content hash, same approved_by and approved_at), the check's own wording for one approved under 0.6, its
    status when the check lists it as not verified, and UNVERIFIED for
    anything else (an id the check didn't judge, content that differs from
    what it verified, or the check not running). Returns a one-line warning
    naming those that aren't approved as recorded ("" when all are)."""
    approved = [
        (i, k) for group, k in ((items, kind), (timeline, "timeline")) for i in group
        if isinstance(i, dict) and i.get("status") == "APPROVED"
    ]  # fmt: skip
    if not approved:
        return ""
    why = ""
    try:
        from vhir_cli import ledger_verify
        from vhir_cli.ledger_verify import _record_sha, approved_view

        # what people (and the AI relaying it) read; nothing matches this marker
        shown = getattr(ledger_verify, "shown_label", lambda label: label)

        view = approved_view(Path(case_dir))
        verdicts = {v.item_id: v for v in view["result"].items}
        marks = {n["id"]: n["status"] for n in view["not_verified"] if _an_id(n["id"])}
        for k in {k for _, k in approved}:
            for record in view[_VIEW_KEYS[k]]:
                if not _an_id(record["id"]):
                    continue
                v = verdicts[str(record["id"])]
                marks[(k, record["id"])] = (record, v.content_sha256, v.view, shown(view["labels"].get(
                    record["id"])) if v.status == "APPROVED_UNDER_0_6" else "VALID")  # fmt: skip
    except Exception as e:  # noqa: BLE001 - never read as approved when unchecked
        marks, why = {}, f" (couldn't verify: {e})"
    bad = []
    for item, item_kind in approved:
        iid = item.get("id")
        mark = (
            marks.get((item_kind, iid), marks.get(iid, "UNVERIFIED"))
            if _an_id(iid)
            else "UNVERIFIED"
        )
        ok = False
        if isinstance(mark, tuple):  # verified: only if this is that record
            verified, sha, view_n, label = mark
            ok = _record_sha(item, item_kind, view_n) == sha and all(
                item.get(k) == verified.get(k) for k in ("approved_by", "approved_at"))  # fmt: skip
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
