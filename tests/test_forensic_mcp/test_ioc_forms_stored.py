"""The report rows over the IOC form corpus (test_report_ioc_forms) state
the records record_finding stores for each set of citations: the real
record_finding stores those."""

from __future__ import annotations

import json

import pytest
from test_report_mcp.test_report_ioc_forms import CORPUS, IDS, ROWS, stored

from .test_finding_challenge import (  # noqa: F401 (case and home are fixtures)
    FINDING,
    _record,
    case,
    home,
)


@pytest.mark.parametrize(("name", "forms"), [r[1:] for r in ROWS], ids=IDS)
def test_record_finding_stores_the_records_the_report_rows_state(case, name, forms):
    kind = CORPUS[name][0]
    result = _record({**FINDING, "iocs": [{"value": f, "type": kind} for f in forms]})
    assert result["status"] == "STAGED", result
    records = json.loads((case / "iocs.json").read_text())
    assert [(r["value"], r["type"]) for r in records] == [
        (r["value"], r["type"]) for r in stored(forms, kind)
    ]
