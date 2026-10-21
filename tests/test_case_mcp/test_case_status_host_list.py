"""case_status reports the case's host list, from the state host_list_hint reads.

- With a list: `host_list` {count, examiner, t}, never the names.
- Without one: `host_list_hint`, the text case_init and evidence_register give.
- Host logs that can't be read: `host_list_error`, and the counts still come.

Before, case_status said nothing about the list, so a model that read only it
asked the examiner for a list the case already had.
"""

from __future__ import annotations

import json
import os

from case_mcp.server import create_server
from sift_common import host_gate as hg
from sift_common import host_identity as hi
from sift_common import host_proposal as hp

from .test_server import _parse, case_dir  # noqa: F401 (fixture)


def _status():
    return _parse(create_server()._tool_manager._tools["case_status"].fn())


def test_a_list_is_reported_by_count_examiner_and_time(case_dir):  # noqa: F811
    hp.upload_host_list(case_dir["path"], "WKS01\nWKS02 wks02.corp.example\n", "tester")
    out = _status()
    listed = out["host_list"]
    assert set(listed) == {"count", "examiner", "t"}
    assert (listed["count"], listed["examiner"]) == (2, "tester")
    assert isinstance(listed["t"], str) and listed["t"]
    assert "host_list_hint" not in out and "host_list_error" not in out
    # the names stay in the Hosts tab
    text = json.dumps(out)
    assert "WKS01" not in text and "wks02.corp.example" not in text


def test_no_list_gives_the_hint(case_dir):  # noqa: F811
    out = _status()
    assert out["host_list_hint"] == hg.host_list_hint(case_dir["path"])
    assert out["host_list_hint"] in (hg.HOST_LIST_HINT, hg.HOST_LIST_HINT_PROPOSED)
    assert "host_list" not in out and "host_list_error" not in out


def test_an_unreadable_host_log_says_so(case_dir):  # noqa: F811
    os.mkfifo(case_dir["path"] / hi.OBSERVATIONS)
    out = _status()
    assert out["host_list_error"].startswith("couldn't read the host list: ")
    assert hi.OBSERVATIONS in out["host_list_error"]
    assert "host_list" not in out and "host_list_hint" not in out
    # the rest of the status still comes
    assert "error" not in out and "finding_count" in out
    # case_init and evidence_register keep giving the hint here, as before
    assert hg.host_list_hint(case_dir["path"]) == hg.HOST_LIST_HINT
