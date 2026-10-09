"""The content hash of an indexed record: the same value whether it is
computed on the record as the ingest sends it or on its ``_source`` as
OpenSearch returns it.

The record is flattened to dotted keys and dumped as JSON with sorted keys,
no spaces, and non-ASCII kept (UTF-8). Left out: the hash itself; the fields
that later operations change (``host.id`` on a host rename or merge,
``vhir.prev_ids``, the ``triage`` and ``threat_intel`` enrichment groups); and
what the evtx pipeline adds to a stored record (``winlog.event_data``'s
``_pipeline_error``, and its ``Data_raw`` when ``Data`` is an object).
"""

from __future__ import annotations

import datetime
import decimal
import hashlib
import json
import uuid

FIELD = "vhir.content_hash"

_LEFT_OUT = {FIELD, "vhir.prev_ids", "host.id", "winlog.event_data._pipeline_error"}
_LEFT_OUT_GROUPS = ("triage", "threat_intel")
_DATA = "winlog.event_data.Data"
_DATA_RAW = "winlog.event_data.Data_raw"


def _flatten(value: dict, prefix: str, out: dict, objects: set) -> None:
    for key, item in value.items():
        name = f"{prefix}{key}"
        if isinstance(item, dict):
            objects.add(name)  # an empty one too: the pipeline still adds Data_raw
            if item:
                _flatten(item, f"{name}.", out, objects)
                continue
        out[name] = item


def canonical_fields(record: dict) -> dict:
    """The record's fields that the hash covers, by dotted name."""
    flat: dict = {}
    objects: set = set()
    _flatten(record, "", flat, objects)
    data_is_object = _DATA in objects
    return {
        name: value
        for name, value in flat.items()
        if name not in _LEFT_OUT
        and not any(name == g or name.startswith(f"{g}.") for g in _LEFT_OUT_GROUPS)
        and not (name == _DATA_RAW and data_is_object)
    }


def _as_sent(value):
    """A value JSON can't write, as the OpenSearch client sends it: dates and
    times ISO 8601, a UUID its text, a Decimal a float. Anything else the
    client would refuse; its text keeps the hash defined."""
    if isinstance(value, (datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, decimal.Decimal):
        return float(value)
    return str(value)


def content_hash(record: dict) -> str:
    """SHA-256 (hex) of the record's canonical JSON."""
    text = json.dumps(
        canonical_fields(record),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_as_sent,
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
