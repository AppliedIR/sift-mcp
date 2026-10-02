"""backup_case tells the examiner what a backup copies.

It said it "Does NOT include evidence", but it copies everything outside
evidence/ and extractions/ except registered evidence, so an unregistered
image under work/ goes into the backup (a 43 GB backup on a real case).
"""

from __future__ import annotations

from case_mcp.server import create_server


def test_the_description_names_what_is_left_out_and_what_is_not():
    srv = create_server()
    text = " ".join(srv._tool_manager._tools["backup_case"].description.split())
    assert "except evidence/, extractions/ and registered evidence" in text
    assert "unregistered images or copies" in text
    assert "Does NOT include evidence" not in text
