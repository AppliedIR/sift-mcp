"""A record's content hash is the same on the record the ingest sends and on
its ``_source`` as stored: nested or dotted, with the fields later operations
change and what the evtx pipeline adds left out."""

from __future__ import annotations

import hashlib
import json

from sift_common.content_hash import canonical_fields, content_hash

SENT = {
    "@timestamp": "2026-10-09T01:02:03Z",
    "winlog.event_data": {"Data": {"Name": "a"}, "TargetUserName": "bob"},
    "message": "café",
    "host.name": "dc01",
    "vhir.ingest_audit_id": "opensearch-ingest-7-20261009-001",
}


def test_it_is_the_sha256_of_the_sorted_compact_utf8_json_of_the_dotted_fields():
    record = {"b": {"c": 1}, "a": "é"}
    expected = hashlib.sha256(
        json.dumps({"a": "é", "b.c": 1}, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")
    ).hexdigest()  # fmt: skip
    assert content_hash(record) == expected


def test_nested_and_dotted_forms_hash_alike():
    nested = {
        "@timestamp": SENT["@timestamp"],
        "winlog": {"event_data": {"Data": {"Name": "a"}, "TargetUserName": "bob"}},
        "message": "café",
        "host": {"name": "dc01"},
        "vhir": {"ingest_audit_id": SENT["vhir.ingest_audit_id"]},
    }
    assert content_hash(nested) == content_hash(SENT)


def test_what_later_operations_change_is_left_out():
    stored = json.loads(json.dumps(SENT))
    stored["host.id"] = "DC01 (renamed)"
    stored["vhir.prev_ids"] = ["x"]
    stored["vhir.content_hash"] = "f" * 64
    stored["triage.verdict"] = "SUSPICIOUS"
    stored["triage"] = {"op_id": "e1"}
    stored["threat_intel"] = {"vt": {"malicious": 3}}
    assert content_hash(stored) == content_hash(SENT)


def test_the_pipelines_additions_are_left_out_when_data_is_an_object():
    stored = json.loads(json.dumps(SENT))
    stored["winlog.event_data"]["Data_raw"] = "{Name=a}"  # the pipeline's toString
    stored["winlog.event_data"]["_pipeline_error"] = "x"
    assert content_hash(stored) == content_hash(SENT)
    empty = {"winlog.event_data": {"Data": {}}}
    assert content_hash({"winlog.event_data": {"Data": {}, "Data_raw": "{}"}}) == (
        content_hash(empty)
    )


def test_data_raw_counts_when_the_parser_set_it_for_a_non_object_data():
    record = {"winlog.event_data": {"Data_raw": "plain text"}}
    assert "winlog.event_data.Data_raw" in canonical_fields(record)
    assert content_hash(record) != content_hash(
        {"winlog.event_data": {"Data_raw": "other"}}
    )


def test_any_other_change_changes_it():
    for field, value in (("message", "cafe"), ("host.name", "dc02"), ("extra", 1)):
        changed = json.loads(json.dumps(SENT))
        changed[field] = value
        assert content_hash(changed) != content_hash(SENT), field
