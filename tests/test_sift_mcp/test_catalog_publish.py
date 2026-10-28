"""A reader in another thread sees the catalog whole, or not yet.

load_catalog filled its cache one tool at a time, and returned whatever the
cache held once it held anything. With the tools in worker threads, a call
that came in during the first load saw part of the catalog: a catalogued
binary looked uncatalogued. The catalog, and the security policy beside it,
are built aside and published whole.

Threads race a fresh load, each reading as soon as the cache isn't empty.
"""

from __future__ import annotations

import threading
import time

import pytest
from sift_mcp import catalog

ROUNDS, READERS = 10, 4


def _catalog_reads():
    def read():
        return (len(catalog.load_catalog()), catalog.get_tool_def("vol") is not None)

    return lambda: catalog._catalog_cache, catalog.load_catalog, read


def _policy_reads():
    def read():
        return sorted(catalog.load_security_policy()), True

    return lambda: catalog._security_cache, catalog.load_security_policy, read


CACHES = {"catalog": _catalog_reads, "security policy": _policy_reads}


def _race(filled, load, read) -> list:
    """One fresh load, with readers in as soon as it has put anything there."""
    catalog.clear_catalog_cache()
    go, seen = threading.Event(), []

    def reader():
        go.wait()
        deadline = time.monotonic() + 10
        while not filled() and time.monotonic() < deadline:
            pass
        seen.append(read())

    threads = [threading.Thread(target=reader) for _ in range(READERS)]
    threads.append(threading.Thread(target=lambda: (go.wait(), load())))
    for t in threads:
        t.start()
    go.set()
    for t in threads:
        t.join(30)
    return seen


@pytest.mark.parametrize("cache", sorted(CACHES))
def test_concurrent_first_loads_see_it_whole(cache):
    filled, load, read = CACHES[cache]()
    catalog.clear_catalog_cache()
    whole = read()
    assert whole[0] and whole[1], whole
    try:
        for _ in range(ROUNDS):
            assert _race(filled, load, read) == [whole] * READERS
    finally:
        catalog.clear_catalog_cache()
