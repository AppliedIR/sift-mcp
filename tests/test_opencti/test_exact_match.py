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

    def test_an_ipv6_observable_behind_a_word_sharing_indicator(
        self, mock_opencti_client
    ):
        """IPv6 text always draws other IPv6 indicators, so observables were
        never searched and an address held only as an observable read not
        found."""
        address = "2606:4700:4700::1111"
        observable = {
            "id": "obs-6",
            "entity_type": "IPv6-Addr",
            "observable_value": address,
            "value": address,
        }
        result = _lookup(
            mock_opencti_client,
            address,
            [_indicator("2606:4700:4700::1001")],
            observables=[observable],
        )
        assert (result["found"], result["entity_type"], result["name"]) == (
            True,
            "observable",
            address,
        )

    def test_a_miss_lists_both_kinds(self, mock_opencti_client):
        observable = {
            "id": "obs-7",
            "entity_type": "Hostname",
            "observable_value": "dc01.other.invalid",
        }
        result = _lookup(
            mock_opencti_client,
            "dc01.corp-a.test",
            [_indicator("worker-unrelated.invalid")],
            observables=[observable],
        )
        assert result["found"] is False
        assert result["related"] == [
            {
                "name": "worker-unrelated.invalid",
                "entity_type": "indicator",
                "confidence": 70,
            },
            {
                "name": "dc01.other.invalid",
                "entity_type": "observable",
                "confidence": 0,
            },
        ]

    @pytest.mark.parametrize(
        "indicators, searched",
        [
            ([_indicator("update-check.invalid", 90)], 0),
            ([_indicator("check.invalid")], 1),
        ],
        ids=["its own indicator", "a word-sharing indicator"],
    )
    def test_observables_are_searched_only_without_its_own_indicator(
        self, mock_opencti_client, indicators, searched
    ):
        _lookup(mock_opencti_client, "update-check.invalid", indicators)
        assert (
            mock_opencti_client._client.stix_cyber_observable.list.call_count
            == searched
        )

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


class TestSurroundingWhitespace:
    """validate_ioc trims its own copy; the raw value reached the comparison."""

    def test_a_padded_ipv4(self, mock_opencti_client):
        result = _lookup(mock_opencti_client, " 8.8.8.8 ", [_indicator("8.8.8.8", 90)])
        assert (result["found"], result["ioc"], result["name"]) == (
            True,
            "8.8.8.8",
            "8.8.8.8",
        )

    def test_a_domain_with_a_trailing_newline(self, mock_opencti_client):
        result = _lookup(
            mock_opencti_client,
            "update-check.invalid\n",
            [_indicator("update-check.invalid", 90)],
        )
        assert (result["found"], result["ioc"]) == (True, "update-check.invalid")

    def test_a_padded_md5_file_observable(self, mock_opencti_client):
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
        result = _lookup(mock_opencti_client, f"  {MD5}\t", observables=[stix_file])
        assert (result["found"], result["entity_type"], result["ioc"]) == (
            True,
            "observable",
            MD5,
        )

    def test_a_padded_private_address(self, mock_opencti_client):
        result = _lookup(mock_opencti_client, " 10.0.0.1 ")
        assert result["found"] is False and "Internal address" in result["note"]
        mock_opencti_client._client.indicator.list.assert_not_called()


class TestAFailedObservableSearchLeavesNotFoundUnconfirmed:
    """Observables are searched when no indicator is the IOC. When that search
    raised, a not-found answer read exactly like a real one, and enrichment
    counted the IOC as a confirmed lookup."""

    NOTE = "Not found is unconfirmed: the observable search failed."

    @staticmethod
    def _failing(client: OpenCTIClient, ioc: str, indicators=()) -> dict:
        client._client.indicator.list.return_value = list(indicators)
        client._client.stix_cyber_observable.list.side_effect = RuntimeError(
            "observable search failed"
        )
        return client.get_indicator_context(ioc)

    def test_no_hits(self, mock_opencti_client):
        result = self._failing(mock_opencti_client, "dc01.corp-a.test")
        assert result == {"found": False, "ioc": "dc01.corp-a.test", "note": self.NOTE}

    def test_indicator_hits_that_are_not_the_ioc(self, mock_opencti_client):
        result = self._failing(
            mock_opencti_client,
            "dc01.corp-a.test",
            [_indicator("worker-unrelated.invalid")],
        )
        assert (result["found"], result.get("note")) == (False, self.NOTE)
        assert [r["name"] for r in result["related"]] == ["worker-unrelated.invalid"]

    def test_a_search_that_did_not_fail_is_a_confirmed_not_found(
        self, mock_opencti_client
    ):
        result = _lookup(mock_opencti_client, "dc01.corp-a.test")
        assert result == {"found": False, "ioc": "dc01.corp-a.test"}

    def test_the_note_belongs_to_one_lookup(self, mock_opencti_client):
        """The client lives for the whole server process: a failed search must
        not mark the lookups after it."""
        assert "note" in self._failing(mock_opencti_client, "dc01.corp-a.test")
        mock_opencti_client._client.stix_cyber_observable.list.side_effect = None
        result = _lookup(mock_opencti_client, "dc02.corp-a.test")
        assert result == {"found": False, "ioc": "dc02.corp-a.test"}
