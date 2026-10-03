"""Joins keep gateway.yaml's key order, so local tools keep the owner's token.

setup-sift writes the owner's key first under api_keys, and local readers
take the first key as the local examiner's token. _atomic_yaml_write (every
join and wintools join) used yaml.dump's default sort, which put a joined
key that sorts first ahead of the owner's.
"""

from __future__ import annotations

import yaml
from sift_gateway.rest import _atomic_yaml_write

OWNER = "vhir_gw_" + "f" * 24  # sorts after the joined key
JOINED = "vhir_gw_" + "0" * 24


def test_a_join_keeps_the_owners_key_first(tmp_path):
    path = tmp_path / "gateway.yaml"
    config = {
        "gateway": {"host": "0.0.0.0", "port": 4508},
        "api_keys": {
            OWNER: {"examiner": "steve", "role": "lead"},
            JOINED: {"examiner": "laptop"},  # what a join adds
        },
        "backends": {"forensic-mcp": {"type": "stdio"}},
    }
    _atomic_yaml_write(path, config)
    written = yaml.safe_load(path.read_text())
    assert list(written["api_keys"]) == [OWNER, JOINED]
    assert list(written) == ["gateway", "api_keys", "backends"]
