"""forensic-mcp's copy of the content hash is vhir's: the same item gives the
same digest, pinned here and in vhir's import tests. When an item was imported
isn't content, so `imported_from.imported_at` is left out of both."""

from forensic_mcp.case.manager import _compute_content_hash

PINNED_ITEM = {
    "id": "F-alice-001",
    "title": "Suspicious process",
    "status": "DRAFT",
    "provenance_grade": "IMPORTED",
    "imported_from": {
        "case_id": "INC-A",
        "examiner": "alice",
        "exported_at": "2026-10-01T00:00:00+00:00",
        "imported_at": "2026-10-09T12:00:00+00:00",
        "original": {"examiner": "alice"},
    },
}
PINNED_SHA256 = "6fd72fbe10bcb82e3fd1340274347595ca281656438850714fdd8b5722f45e29"


def test_the_content_hash_of_an_imported_item_is_the_pinned_one():
    assert _compute_content_hash(PINNED_ITEM) == PINNED_SHA256


def test_the_import_time_isnt_hashed():
    later = {**PINNED_ITEM, "imported_from": {**PINNED_ITEM["imported_from"],
                                              "imported_at": "2027-01-01T00:00:00+00:00"}}  # fmt: skip
    assert _compute_content_hash(later) == PINNED_SHA256
