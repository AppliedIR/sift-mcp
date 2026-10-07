"""Host logs, the fold, get-or-mint and the case lock."""

from __future__ import annotations

import json
import multiprocessing
import os
import time

import pytest
from sift_common import host_identity as hi


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: c\n")
    hi.ensure_host_files(d)
    return d


def _lines(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


# -- files


def test_host_files_are_created_empty_and_never_truncated(tmp_path):
    hi.ensure_host_files(tmp_path)
    for name in (*hi.HOST_FILES, hi.CASE_LOCK):
        assert (tmp_path / name).is_file()
        assert (tmp_path / name).stat().st_size == 0
    (tmp_path / hi.OBSERVATIONS).write_text('{"kind":"case","c12":"abc"}\n')
    hi.ensure_host_files(tmp_path)
    assert (tmp_path / hi.OBSERVATIONS).read_text() == '{"kind":"case","c12":"abc"}\n'


def test_planted_symlink_is_refused(tmp_path):
    target = tmp_path / "elsewhere.jsonl"
    target.write_text("")
    (tmp_path / hi.OBSERVATIONS).symlink_to(target)
    with pytest.raises(hi.HostLogError):
        hi.append_observations(tmp_path, [{"kind": "unit", "unit": "u"}])
    assert target.read_text() == ""


def test_planted_hard_link_is_refused(tmp_path):
    other = tmp_path / "other.jsonl"
    other.write_text("")
    os.link(other, tmp_path / hi.DECISIONS)
    with pytest.raises(hi.HostLogError):
        hi.append_decision(tmp_path, {"action": "confirm"}, 0)
    assert other.read_text() == ""


def test_decision_past_the_observation_log_end_is_refused(case):
    size = hi.append_observations(case, [{"kind": "unit", "unit": "u1"}])
    with pytest.raises(hi.HostLogError, match="past the log's end"):
        hi.append_decision(case, {"action": "confirm"}, size + 1)
    assert (case / hi.DECISIONS).read_text() == ""
    hi.append_decision(case, {"action": "confirm"}, size)
    assert _lines(case / hi.DECISIONS)[0]["offset"] == size


def test_header_records_the_case_identity_latest_wins(case):
    assert hi.recorded_c12(case) is None
    hi.write_case_header(case, "aaaaaaaaaaaa", "case created")
    hi.write_case_header(case, "bbbbbbbbbbbb", "restored as a copy")
    assert hi.recorded_c12(case) == "bbbbbbbbbbbb"


# -- fold


def test_fold_skips_an_unterminated_last_line(case):
    hi.append_observations(case, [{"kind": "case", "c12": "aaaaaaaaaaaa"}])
    with open(case / hi.OBSERVATIONS, "ab") as f:
        f.write(b'{"kind":"case","c12":"bbbbbbbbbbbb"}')
    state = hi.load(case)
    assert state.c12 == "aaaaaaaaaaaa"
    assert state.obs_offset < (case / hi.OBSERVATIONS).stat().st_size


def test_fold_is_deterministic_and_cached_by_offsets(case):
    hi.get_or_mint(case, "u1", "WKS01")
    hi.get_or_mint(case, "u2", "SRV01")
    obs = (case / hi.OBSERVATIONS).read_bytes()
    a = hi.fold(obs, b"")
    b = hi.fold(obs, b"")
    assert {k: m.to_dict() for k, m in a.machines.items()} == {
        k: m.to_dict() for k, m in b.machines.items()
    }
    first = hi.load(case)
    assert hi.load(case) is first
    hi.get_or_mint(case, "u3", "SRV02")
    assert hi.load(case) is not first


def test_a_decision_does_not_see_names_after_its_offset(case):
    hi.append_observations(case, [{"kind": "name", "unit": "u1", "raw": "WKS01"}])
    seen = (case / hi.OBSERVATIONS).stat().st_size
    hi.append_observations(
        case, [{"kind": "name", "unit": "u1", "raw": "wks01.corp.example.test"}]
    )
    key = hi.new_machine_key()
    hi.append_decision(
        case,
        {
            "action": "confirm",
            "args": {
                "machines": [
                    {"key": key, "canonical": "WKS01", "pairs": [["u1", "WKS01"]]}
                ]
            },
        },
        seen,
    )
    state = hi.load(case)
    assert state.machine_of_pair("u1", "WKS01").canonical == "WKS01"
    assert state.pending_pairs() == [("u1", "wks01.corp.example.test")]


# -- get-or-mint


def test_a_new_name_mints_once_and_is_reused(case):
    k1, c1 = hi.get_or_mint(case, "u1", "WKS01")
    k2, c2 = hi.get_or_mint(case, "u1", "WKS01")
    assert (k1, c1) == (k2, c2) == (k1, "WKS01")
    assert len(k1) == 16
    assert hi.load(case).machine_of_key(k1).state == hi.NEW


def _mint_worker(case_dir, unit, raw, q, start):
    start.wait(10)  # every worker reaches the name at once
    q.put(hi.get_or_mint(case_dir, unit, raw))


def test_two_workers_meeting_one_new_name_mint_one_machine(case):
    ctx = multiprocessing.get_context("fork")
    q = ctx.Queue()
    start = ctx.Barrier(24)
    procs = [
        ctx.Process(target=_mint_worker, args=(str(case), "u1", "DC01", q, start))
        for _ in range(24)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    keys = {q.get(timeout=5)[0] for _ in procs}
    assert len(keys) == 1
    assert len(hi.load(case).machines) == 1


def test_a_name_joins_the_one_confirmed_machine_it_equals(case):
    key = hi.new_machine_key()
    hi.append_decision(
        case,
        {
            "action": "confirm",
            "args": {
                "machines": [
                    {"key": key, "canonical": "WKS01", "pairs": [["u1", "WKS01"]]}
                ]
            },
        },
        0,
    )
    k, c = hi.get_or_mint(case, "u2", "wks01.")
    assert (k, c) == (key, "WKS01")
    state = hi.load(case)
    assert hi.FLAG_MATCHED_DURING_INGEST in state.pair_flags[("u2", "wks01.")]


def test_a_name_from_another_domain_does_not_join(case):
    key = hi.new_machine_key()
    hi.append_decision(
        case,
        {
            "action": "confirm",
            "args": {
                "machines": [
                    {
                        "key": key,
                        "canonical": "DC01",
                        "pairs": [["u1", "DC01"], ["u1", "dc01.corp-a.example.test"]],
                    }
                ]
            },
        },
        0,
    )
    k, c = hi.get_or_mint(case, "u2", "dc01.corp-b.example.test")
    assert k != key
    assert c == "dc01.corp-b.example.test"


def test_an_ai_origin_name_never_joins_and_is_flagged(case):
    key = hi.new_machine_key()
    hi.append_decision(
        case,
        {
            "action": "confirm",
            "args": {
                "machines": [
                    {"key": key, "canonical": "DC01", "pairs": [["u1", "DC01"]]}
                ]
            },
        },
        0,
    )
    k, c = hi.get_or_mint(case, "u2", "DC01", origin="argument")
    assert k != key
    m = hi.load(case).machine_of_key(k)
    assert hi.FLAG_AI_ORIGIN in m.flags
    assert c == "DC01 (2)" and hi.FLAG_CANONICAL_CLASH in m.flags


def test_unconfirmed_machines_never_share_a_canonical(case):
    k1, c1 = hi.get_or_mint(case, "u1", "WKS01")
    k2, c2 = hi.get_or_mint(case, "u2", "wks01")
    assert k1 != k2
    assert (c1, c2) == ("WKS01", "wks01 (2)")


# -- decisions


def _confirm(case, key, canonical, pairs):
    hi.append_decision(
        case,
        {
            "action": "confirm",
            "args": {
                "machines": [
                    {
                        "key": key,
                        "canonical": canonical,
                        "pairs": [list(p) for p in pairs],
                    }
                ]
            },
        },
        (case / hi.OBSERVATIONS).stat().st_size,
    )


def test_merge_relabels_and_split_restores(case):
    ka, _ = hi.get_or_mint(case, "u1", "WKS01")
    kb, _ = hi.get_or_mint(case, "u2", "wks01.corp.example.test")
    _confirm(case, ka, "WKS01", [("u1", "WKS01")])
    hi.append_decision(case, {"action": "merge", "args": {"into": ka, "from": [kb]}}, 0)
    state = hi.load(case)
    m = state.machine_of_key(kb)
    assert m.id == ka and m.keys == [ka, kb]
    assert state.bindings[("u2", "wks01.corp.example.test")] == kb
    assert "wks01.corp.example.test" in m.former

    hi.append_decision(
        case,
        {
            "action": "split",
            "args": {
                "machine": ka,
                "keys": [kb],
                "canonical": "wks01.corp.example.test",
            },
        },
        0,
    )
    state = hi.load(case)
    assert state.machine_of_key(ka).keys == [ka]
    assert state.machine_of_key(kb).canonical == "wks01.corp.example.test"
    assert state.machine_of_key(kb).pairs == [("u2", "wks01.corp.example.test")]


def test_rename_keeps_the_former_canonical(case):
    k, _ = hi.get_or_mint(case, "u1", "WKS01")
    seen = (case / hi.OBSERVATIONS).stat().st_size
    hi.append_decision(
        case,
        {"action": "rename", "args": {"machine": k, "canonical": "FIN-WS-01"}},
        seen,
    )
    m = hi.load(case).machine_of_key(k)
    assert (
        m.canonical == "FIN-WS-01" and m.former == ["WKS01"] and m.state == hi.CONFIRMED
    )


def test_an_examiner_name_already_used_is_refused_and_offered_as_a_merge(case):
    ka, _ = hi.get_or_mint(case, "u1", "DC01")
    kb, cb = hi.get_or_mint(case, "u2", "dc01")
    assert cb == "dc01 (2)"  # a proposal is made unique automatically
    seen = (case / hi.OBSERVATIONS).stat().st_size
    before = (case / hi.DECISIONS).read_bytes()
    for rec in (
        {"action": "rename", "args": {"machine": kb, "canonical": "DC01"}},
        {
            "action": "confirm",
            "args": {
                "machines": [
                    {"key": kb, "canonical": "dc01.", "pairs": [["u2", "dc01"]]}
                ]
            },
        },
        {"action": "split", "args": {"machine": ka, "keys": [ka], "canonical": "DC01"}},
    ):
        with pytest.raises(hi.HostLogError, match="merge the two machines instead"):
            hi.append_decision(case, rec, seen)
    assert (case / hi.DECISIONS).read_bytes() == before
    # Its own name, re-entered, is not a clash.
    hi.append_decision(
        case,
        {
            "action": "confirm",
            "args": {
                "machines": [
                    {"key": ka, "canonical": "DC01", "pairs": [["u1", "DC01"]]}
                ]
            },
        },
        seen,
    )
    state = hi.load(case)
    assert {m.canonical for m in state.machines.values()} == {"DC01", "dc01 (2)"}


# -- pre-0.7 cases


def test_v1_import_seeds_canonicals_from_the_stamped_host_id_and_flags_merges(case):
    hosts = {
        "WKS01": {"aliases": ["WKS01", "wks01.corp.example.test"]},
        "SRV01": {"aliases": ["SRV01"]},
    }
    pairs = [
        ("case-acme-evtx-wks01", "WKS01", "WKS01"),
        ("case-acme-evtx-wks01", "wks01.corp.example.test", "WKS01"),
        ("case-acme-evtx-srv01", "SRV01", "SRV01"),
    ]
    assert hi.import_v1(case, hosts, pairs) is True
    assert hi.import_v1(case, hosts, pairs) is False
    state = hi.load(case)
    by_name = {m.canonical: m for m in state.machines.values()}
    assert set(by_name) == {"WKS01", "SRV01"}
    assert by_name["WKS01"].state == hi.CONFIRMED
    assert hi.FLAG_V1_MERGED in by_name["WKS01"].flags
    assert hi.FLAG_V1_MERGED not in by_name["SRV01"].flags
    assert len(by_name["WKS01"].pairs) == 2
    # A new collection of the same machine joins it.
    k, c = hi.get_or_mint(case, "new-unit", "WKS01")
    assert c == "WKS01" and state.machine_of_key(k) is not None


# -- concurrency and scale


def _append_worker(case_dir, tag, n, decide):
    for i in range(n):
        if decide:
            hi.append_decision(
                case_dir, {"action": "note", "args": {"i": i, "tag": tag}}, 0
            )
        else:
            hi.append_observations(
                case_dir, [{"kind": "name", "unit": tag, "raw": f"H{i}"}]
            )


def test_concurrent_appends_lose_nothing(case):
    ctx = multiprocessing.get_context("fork")
    procs = [
        ctx.Process(target=_append_worker, args=(str(case), "ingest-a", 200, False)),
        ctx.Process(target=_append_worker, args=(str(case), "ingest-b", 200, False)),
        ctx.Process(target=_append_worker, args=(str(case), "decide", 200, True)),
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
    obs = _lines(case / hi.OBSERVATIONS)
    dec = _lines(case / hi.DECISIONS)
    assert len(obs) == 400 and len(dec) == 200
    state = hi.load(case)
    assert len(state.names) == 400


def test_five_thousand_units_append_fast_and_fold_quickly(case):
    recs = []
    for i in range(5000):
        u = hi.unit_key(f"hosts/H{i:05d}")
        recs += [
            {"kind": "unit", "unit": u, "locator": f"hosts/H{i:05d}"},
            {"kind": "name", "unit": u, "raw": f"H{i:05d}", "origin": "artifact"},
            {
                "kind": "bind",
                "unit": u,
                "raw": f"H{i:05d}",
                "key": f"{i:016x}",
                "canonical": f"H{i:05d}",
                "state": "new",
            },
        ]
    hi.append_observations(case, recs)
    t0 = time.perf_counter()
    hi.append_observations(case, [{"kind": "name", "unit": "x", "raw": "late"}])
    assert time.perf_counter() - t0 <= 0.005 * 4  # one append, with slack for CI
    t0 = time.perf_counter()
    state = hi.load(case)
    assert time.perf_counter() - t0 <= 2.0
    assert len(state.machines) == 5000


# -- the case lock


def test_shared_holders_coexist_and_exclude_an_exclusive_request(case):
    with hi.case_lock(case, shared=True), hi.case_lock(case, shared=True):
        with pytest.raises(hi.CaseLockBusy, match="another task in this process"):
            with hi.case_lock(case, shared=False):
                pass
    with hi.case_lock(case, shared=False):
        with pytest.raises(hi.CaseLockBusy):
            with hi.case_lock(case, shared=True):
                pass


def _hold_shared(case_dir, ready, stop):
    with hi.case_lock(case_dir, shared=True):
        ready.set()
        stop.wait(30)


def test_another_process_holding_the_lock_blocks_an_exclusive_request(case):
    ctx = multiprocessing.get_context("fork")
    ready, stop = ctx.Event(), ctx.Event()
    p = ctx.Process(target=_hold_shared, args=(str(case), ready, stop))
    p.start()
    try:
        assert ready.wait(10)
        hi._inproc.clear()
        with pytest.raises(hi.CaseLockBusy, match="a process holds the case lock"):
            with hi.case_lock(case, shared=False):
                pass
    finally:
        stop.set()
        p.join(10)
    with hi.case_lock(case, shared=False):
        pass


def test_a_killed_holder_releases_the_lock(case):
    ctx = multiprocessing.get_context("fork")
    ready, stop = ctx.Event(), ctx.Event()
    p = ctx.Process(target=_hold_shared, args=(str(case), ready, stop))
    p.start()
    assert ready.wait(10)
    p.kill()
    p.join(10)
    with hi.case_lock(case, shared=False):
        pass


def test_unfinished_op_reads_the_journal(case):
    assert hi.unfinished_op(case) is None
    (case / hi.OPS).write_text(
        json.dumps({"ops": {"op1": {"state": "done"}, "op2": {"state": "incomplete"}}})
    )
    assert hi.unfinished_op(case)["id"] == "op2"


def test_v1_canonical_is_the_host_id_the_records_carry_not_the_dictionary_spelling(
    case,
):
    """A v1 host.id fixed by hand after ingest differs from the dictionary key."""
    hosts = {"wks01": {"aliases": ["wks01"]}}
    pairs = [("case-acme-evtx-wks01", "wks01", "WKS01-FIN")] * 3
    hi.import_v1(case, hosts, pairs)
    (machine,) = hi.load(case).machines.values()
    assert machine.canonical == "WKS01-FIN"


def test_a_lock_file_replaced_under_a_holder_is_locked_again(case, monkeypatch):
    """A holder that opened the file just before it was replaced must not keep
    a lock nobody else sees: it re-opens the file now at the path."""
    path = case / hi.CASE_LOCK
    real_open = hi.os.open
    swapped = []

    def opening(p, flags, *a):
        fd = real_open(p, flags, *a)
        if str(p) == str(path) and not swapped:
            fresh = case / "fresh.lock"
            fresh.write_text("")
            hi.os.replace(fresh, path)
            swapped.append(True)
        return fd

    monkeypatch.setattr(hi.os, "open", opening)
    ctx = multiprocessing.get_context("fork")
    with hi.case_lock(case, shared=False):
        monkeypatch.setattr(hi.os, "open", real_open)
        q = ctx.Queue()
        proc = ctx.Process(target=_try_exclusive, args=(str(case), q))
        proc.start()
        proc.join(10)
        assert q.get(timeout=5) == "busy"


def _try_exclusive(case_dir, q):
    hi._inproc.clear()
    try:
        with hi.case_lock(case_dir, shared=False):
            q.put("locked")
    except hi.CaseLockBusy:
        q.put("busy")


def test_a_name_joining_a_confirmed_machine_later_leaves_its_name_as_confirmed(case):
    """Each decision applies at the point of the log the examiner saw: a name
    that joins the machine afterwards doesn't become its canonical first."""
    key = hi.new_machine_key()
    _confirm(case, key, "DC01", [("u1", "DC01")])
    joined, canonical = hi.get_or_mint(case, "u2", "dc01")
    m = hi.load(case).machine_of_key(key)
    assert (joined, canonical) == (key, "DC01")
    assert m.canonical == "DC01" and m.former == []
