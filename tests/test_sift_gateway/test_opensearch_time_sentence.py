"""The opensearch-mcp instructions say which indices time windows leave out."""

from sift_common.instructions import OPENSEARCH


def test_ez_csv_indices_are_said_to_carry_no_event_time():
    assert (
        "idx_search and idx_timeline support time_from/time_to for temporal filtering. "
        "EZ-tool CSV indices made by idx_ingest (mft, usn, amcache, shimcache, registry, ...) "
        "carry file and key times, not event times: they aren't in time windows, the default "
        "timeline or the case time range, so query them by their own date field (e.g. "
        "Created0x10) with index=. "
    ) in OPENSEARCH
