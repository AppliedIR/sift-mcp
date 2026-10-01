"""`lookup_ioc` reports `found` only for the IOC itself.

Its search is full text, so the hits include objects that only share a word
with the IOC. The first hit was reported as found, naming another object;
now the first hit that is the IOC is, and when none is, the hits are
returned under `related`. Observable shapes follow pycti 6.9.29's fragment:
a file observable's `name` is the filename and its hashes are in `hashes`.
Values are synthetic.
"""

from __future__ import annotations

import hashlib

import pytest
from opencti_mcp.client import OpenCTIClient

MD5 = hashlib.md5(b"sample").hexdigest()
SHA256 = hashlib.sha256(b"sample").hexdigest()


def _indicator(name: str, confidence: int = 70) -> dict:
    return {
        "id": f"ind-{name}",
        "name": name,
        "pattern_type": "stix",
        "confidence": confidence,
    }


def _lookup(client: OpenCTIClient, ioc: str, indicators=(), observables=()) -> dict:
    client._client.indicator.list.return_value = list(indicators)
    client._client.stix_cyber_observable.list.return_value = list(observables)
    return client.get_indicator_context(ioc)


class TestOnlyTheIOCIsFound:
    def test_an_indicator_sharing_a_word(self, mock_opencti_client):
        result = _lookup(
            mock_opencti_client,
            "dc01.corp-a.test",
            [_indicator("worker-unrelated.invalid")],
        )
        assert result == {
            "found": False,
            "ioc": "dc01.corp-a.test",
            "related": [
                {
                    "name": "worker-unrelated.invalid",
                    "entity_type": "indicator",
                    "confidence": 70,
                }
            ],
        }

    def test_an_observable_sharing_a_word(self, mock_opencti_client):
        hit = {
            "id": "obs-1",
            "entity_type": "Hostname",
            "observable_value": "dc01.other.invalid",
        }
        result = _lookup(mock_opencti_client, "dc01.corp-a.test", observables=[hit])
        assert result["found"] is False
        assert result["related"] == [
            {"name": "dc01.other.invalid", "entity_type": "observable", "confidence": 0}
        ]

    @pytest.mark.parametrize("rank", [0, 1], ids=["first hit", "second hit"])
    def test_the_iocs_own_indicator(self, mock_opencti_client, rank):
        hits = [_indicator("update-check.invalid", 90)]
        hits.insert(1 - rank, _indicator("check.invalid"))
        result = _lookup(mock_opencti_client, "update-check.invalid", hits)
        assert (result["found"], result["entity_type"], result["name"]) == (
            True,
            "indicator",
            "update-check.invalid",
        )
        assert result["confidence"] == 90

    def test_a_hash_in_the_other_case(self, mock_opencti_client):
        result = _lookup(mock_opencti_client, MD5.upper(), [_indicator(MD5)])
        assert (result["found"], result["name"]) == (True, MD5)

    def test_an_ipv6_address_written_another_way(self, mock_opencti_client):
        result = _lookup(
            mock_opencti_client,
            "2606:4700:4700:0:0:0:0:1111",
            [_indicator("2606:4700:4700::1111")],
        )
        assert result["found"] is True

    @pytest.mark.parametrize(
        "ioc", [SHA256, MD5], ids=["its value", "only in its hashes"]
    )
    def test_a_file_observable(self, mock_opencti_client, ioc):
        stix_file = {
            "id": "obs-file",
            "entity_type": "StixFile",
            "name": "a.exe",
            "observable_value": SHA256,
            "hashes": [
                {"algorithm": "MD5", "hash": MD5},
                {"algorithm": "SHA-256", "hash": SHA256},
            ],
        }
        result = _lookup(mock_opencti_client, ioc, observables=[stix_file])
        assert (result["found"], result["entity_type"], result["name"]) == (
            True,
            "observable",
            "a.exe",
        )
