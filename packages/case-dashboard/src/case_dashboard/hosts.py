"""The Hosts tab's API: the case's machines and the host names awaiting the
examiner, read from the host logs, and the examiner's decisions on them.

Decisions need no password (a host decision is logistical); each carries the
examiner of the request, origin "portal" and the observation-log offset the
page was built from, and is written to the case's dashboard audit log.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from sift_common import file_identity as fi
from sift_common import host_gate as hg
from sift_common import host_identity as hi
from sift_common import host_proposal as hp
from starlette.requests import Request
from starlette.responses import JSONResponse

_PAGE_DEFAULT = 50
_PAGE_MAX = 200
_LIST_MAX = 1_000_000  # bytes of an uploaded host list
_STATES = (hi.CONFIRMED, hi.STARTED_NOW, hi.NEW)


def _routes():
    from case_dashboard import routes

    return routes


def _case_or_error():
    routes = _routes()
    case_dir = routes._resolve_case_dir()
    return case_dir, (None if case_dir else routes._no_case_response())


def _names(state: hi.HostState, pairs) -> list[dict]:
    out = []
    for unit, raw in pairs:
        info = state.names.get((unit, raw)) or {}
        out.append(
            {
                "unit": unit,
                "raw": raw,
                "locator": (state.units.get(unit) or {}).get("locator", ""),
                "evidence": list(info.get("evidence") or []),
                "origins": sorted(info.get("origins") or []),
                "flags": list(state.pair_flags.get((unit, raw)) or []),
            }
        )
    return out


def _spellings(text: str) -> set[str]:
    """A host text in compare form, and its short name when it has a domain."""
    full = hi.spelling(text)
    short, _ = hi.split_name(text)
    return {s for s in (full, hi.spelling(short) if short else "") if s}


def _text_index(state: hi.HostState) -> dict[str, set[str]]:
    """Compare form -> machine ids, over each machine's canonical, raw names
    and former canonicals."""
    index: dict[str, set[str]] = {}
    for m in state.machines.values():
        for text in [m.canonical, *m.former, *(raw for _, raw in m.pairs)]:
            for s in _spellings(text):
                index.setdefault(s, set()).add(m.id)
    return index


def _pivots(case_dir: Path, state: hi.HostState) -> dict[str, list[dict]]:
    """Machine id -> the findings and timeline items whose host text names it.
    A text that names several machines is listed under each, with the others."""
    routes = _routes()
    index = _text_index(state)
    out: dict[str, list[dict]] = {}
    for kind, name in (("finding", "findings.json"), ("timeline", "timeline.json")):
        for item in routes._load_json(case_dir / name) or []:
            text = item.get("host") if isinstance(item, dict) else None
            if not isinstance(text, str) or not text.strip():
                continue
            ids: set[str] = set()
            for s in _spellings(text):
                ids |= index.get(s, set())
            for mid in sorted(ids):
                others = sorted(state.machines[o].canonical for o in ids if o != mid)
                out.setdefault(mid, []).append(
                    {
                        "kind": kind,
                        "id": item.get("id", ""),
                        "title": item.get("title") or item.get("description") or "",
                        "host": text,
                        "ambiguous_with": others,
                    }
                )
    return out


def _machine_row(state: hi.HostState, m: hi.Machine, pivots: dict) -> dict:
    row = m.to_dict()
    row["names"] = _names(state, m.pairs)
    row["units"] = sorted({u for u, _ in m.pairs})
    row["pivots"] = pivots.get(m.id, [])
    row["query"] = f'host.id:"{m.canonical}"'
    return row


def _matches(m: hi.Machine, q: str) -> bool:
    wanted = hi.spelling(q)
    texts = [m.canonical, *m.former, *(raw for _, raw in m.pairs)]
    return any(wanted in hi.spelling(t) for t in texts)


# The GET routes are plain defs: Starlette runs them in a worker thread, so a
# slow host-log read never holds the gateway's event loop.
def get_hosts(request: Request) -> JSONResponse:
    case_dir, error = _case_or_error()
    if error:
        return error
    state = hi.load(case_dir)
    all_groups = hp.cached_propose(case_dir, state)  # once per state of the logs
    # Every group waiting for the examiner, including one that joins a machine.
    # A name marked not a host is decided, though it stays unbound.
    groups = [
        g
        for g in all_groups
        if any(
            p not in state.bindings
            and hi.FLAG_NOT_A_HOST not in state.pair_flags.get(p, ())
            for p in g.pairs
        )
    ]
    counts = {s: 0 for s in _STATES}
    for m in state.machines.values():
        counts[m.state] = counts.get(m.state, 0) + 1
    counts["proposed"] = len(groups)

    wanted_state = request.query_params.get("state", "")
    q = request.query_params.get("q", "")
    try:
        page = max(1, int(request.query_params.get("page", 1)))
        per_page = min(
            _PAGE_MAX, max(1, int(request.query_params.get("per_page", _PAGE_DEFAULT)))
        )
    except ValueError:
        return JSONResponse(
            {"error": "page and per_page must be numbers"}, status_code=400
        )
    machines = sorted(
        state.machines.values(), key=lambda m: (hi.spelling(m.canonical), m.id)
    )
    if wanted_state:
        machines = [m for m in machines if m.state == wanted_state]
    if q:
        machines = [m for m in machines if _matches(m, q)]
    shown = machines[(page - 1) * per_page : page * per_page]
    try:
        ppage = max(1, int(request.query_params.get("proposed_page", 1)))
    except ValueError:
        return JSONResponse(
            {"error": "proposed_page must be a number"}, status_code=400
        )
    proposed_shown = groups[(ppage - 1) * per_page : ppage * per_page]
    pivots = _pivots(case_dir, state) if shown else {}
    listed = state.host_list or None
    return JSONResponse(
        {
            "obs_offset": state.obs_offset,
            "dec_offset": state.dec_offset,
            "counts": counts,
            "total": len(machines),
            "page": page,
            "per_page": per_page,
            "machines": [_machine_row(state, m, pivots) for m in shown],
            "proposed": [
                {
                    **g.to_dict(),
                    "names": _names(state, g.pairs),
                    "joins": state.machines[g.machine].canonical if g.machine else "",
                }
                for g in proposed_shown
            ],
            "proposed_total": len(groups),
            "proposed_page": ppage,
            "host_list": (
                {
                    "entries": len(listed.get("entries") or []),
                    "sha256": listed.get("sha256", ""),
                    "examiner": listed.get("examiner", ""),
                    "t": listed.get("t", ""),
                }
                if listed
                else None
            ),
            "host_list_hint": "" if listed else hg.HOST_LIST_HINT,
            "listed_without_data": (
                hp.listed_without_data(state, all_groups) if listed else []
            ),
        }
    )


def get_runs(request: Request) -> JSONResponse:
    """Ingest runs waiting for their hosts, each with what holds it."""
    case_dir, error = _case_or_error()
    if error:
        return error
    state = hi.load(case_dir)
    runs = []
    for run_id, units in sorted(state.waits.items()):
        if run_id in state.cancelled:
            continue
        waiting = hg.unresolved(state, units)
        if waiting:
            runs.append({"run_id": run_id, "units": len(units), "unresolved": waiting})
    return JSONResponse({"obs_offset": state.obs_offset, "runs": runs})


def get_host(request: Request) -> JSONResponse:
    """One machine, with the decisions that name it."""
    case_dir, error = _case_or_error()
    if error:
        return error
    state = hi.load(case_dir)
    mid = request.path_params["m16"]
    m = state.machines.get(mid) or state.machine_of_key(mid)
    if m is None:
        return JSONResponse({"error": "no such machine"}, status_code=404)
    keys = set(m.keys) | {m.id}
    history = []
    try:  # non-blocking, the descriptor checked, each line capped (a refusal: 409)
        for raw in fi.capped_lines(Path(case_dir) / hi.DECISIONS, follow=False):
            text = raw.decode("utf-8")  # split as text mode split: a lone CR too
            for line in io.StringIO(text, newline=None) if "\r" in text else (text,):
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and keys & set(_keys_named(rec.get("args"))):
                    history.append(
                        {
                            k: rec.get(k)
                            for k in ("t", "examiner", "origin", "action", "args")
                        }
                    )
    except OSError:
        pass
    pivots = _pivots(case_dir, state)
    return JSONResponse({**_machine_row(state, m, pivots), "history": history})


def _keys_named(args) -> list[str]:
    """Every machine key a decision's arguments name."""
    if not isinstance(args, dict):
        return []
    keys = [args.get(k) for k in ("machine", "into", "key")]
    keys += list(args.get("from") or []) + list(args.get("keys") or [])
    keys += [i.get("key") for i in args.get("machines") or () if isinstance(i, dict)]
    return [k for k in keys if isinstance(k, str)]


def _audit(
    case_dir: Path, examiner: str, action: str, params: dict, result: str
) -> None:
    from sift_common.audit import AuditWriter

    AuditWriter("case-dashboard", audit_dir=str(Path(case_dir) / "audit")).log(
        tool=f"host_{action}",
        params=params,
        result_summary=result,
        source="portal",
        extra={"examiner": examiner, "origin": "portal"},
    )


def _known_pairs(state: hi.HostState, raw_pairs) -> list[list[str]] | None:
    """The pairs, when every one is a host name the case has seen."""
    pairs = []
    for p in raw_pairs or ():
        if not (isinstance(p, (list, tuple)) and len(p) == 2):
            return None
        unit, raw = str(p[0]), str(p[1])
        if (unit, raw) not in state.names:
            return None
        pairs.append([unit, raw])
    return pairs or None


class _Refused(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _confirm_items(state: hi.HostState, args: dict) -> list[dict]:
    """`confirm` decision items for the groups the page sent. A group names
    new pairs, a machine in use (`machine`), or both (pairs that join it).

    One check for every form: a group that touches a machine in use (named,
    or through a pair already bound to it) is confirmed under that machine's
    own name only; renaming it is done with rename, and joining two machines
    is a merge."""
    items = []
    named: set[tuple[str, str]] = set()
    machines: set[str] = set()
    for g in args.get("groups") or ():
        if not isinstance(g, dict):
            raise _Refused(400, "each group must be an object")
        canonical = str(g.get("canonical") or "").strip()
        if not hi.spelling(canonical):
            raise _Refused(400, "a host name can't be empty")
        pairs = _known_pairs(state, g.get("pairs")) if g.get("pairs") else []
        if pairs is None:
            raise _Refused(400, "every pair must be a host name the case has seen")
        in_use = {m.id: m for m in (state.machine_of_pair(*p) for p in pairs) if m}
        if g.get("machine"):
            m = state.machines.get(str(g["machine"]))
            if m is None:
                raise _Refused(400, "no such machine")
            in_use[m.id] = m
        if not pairs and not in_use:
            raise _Refused(400, "nothing to confirm")
        # One confirmation is all or nothing: a name or machine in two groups
        # would be confirmed twice, the second over the first
        if named & {tuple(p) for p in pairs} or machines & set(in_use):
            raise _Refused(400, "a name or machine appears in more than one group")
        named |= {tuple(p) for p in pairs}
        machines |= set(in_use)
        if len(in_use) > 1:
            names = ", ".join(sorted(m.canonical for m in in_use.values()))
            raise _Refused(
                409,
                f"these names belong to more than one machine ({names}): merge them instead",
            )
        if in_use:
            (m,) = in_use.values()
            if hi.spelling(canonical) != hi.spelling(m.canonical):
                raise _Refused(
                    409,
                    f"{m.canonical} is already in use; renaming a machine in use is done "
                    "with rename",
                )
            items.append({"key": m.keys[0], "canonical": m.canonical, "pairs": pairs})
        else:
            items.append(
                {"key": hi.new_machine_key(), "canonical": canonical, "pairs": pairs}
            )
    if not items:
        raise _Refused(400, "nothing to confirm")
    return items


def _state_at(case_dir: Path, state: hi.HostState, obs_at, dec_at) -> hi.HostState:
    """The host logs as the page saw them: the fold of each log up to the
    page's offsets."""
    if (
        not (isinstance(obs_at, int) and isinstance(dec_at, int))
        or min(obs_at, dec_at) < 0
    ):
        raise _Refused(400, "confirm all needs the page's two log offsets")
    if (obs_at, dec_at) == (state.obs_offset, state.dec_offset):
        return state
    _, obs = hi._read(Path(case_dir) / hi.OBSERVATIONS)
    _, dec = hi._read(Path(case_dir) / hi.DECISIONS)
    if obs_at > len(obs) or dec_at > len(dec):
        raise _Refused(409, "the page refers to log offsets past the logs' end")
    return hi.fold(obs[:obs_at], dec[:dec_at])


def _confirm_all(
    case_dir: Path, state: hi.HostState, examiner: str, args: dict, seen
) -> dict:
    """Confirm every group proposed on the page, as proposed then: each one
    unflagged, named from an artifact and unchanged since. One request of
    items; a group that can't be confirmed is skipped with the reason, and
    the others go ahead."""
    page = _state_at(case_dir, state, seen, args.get("seen_decisions"))
    confirmed, skipped, items = [], [], []
    for g in hp.cached_propose(case_dir, page):
        if all(p in page.bindings for p in g.pairs):
            continue  # nothing waiting in it on the page
        name = page.machines[g.machine].canonical if g.machine else g.canonical
        reason = ""
        if g.flags or g.conflicts:
            reason = "needs the examiner: " + "; ".join([*g.flags, *g.conflicts])
        elif not all(
            hi.ARTIFACT in (page.names.get(p) or {}).get("origins", ()) for p in g.pairs
        ):
            reason = "not every name was read from evidence"
        elif any(state.bindings.get(p) != page.bindings.get(p) for p in g.pairs) or (
            g.machine
            and (
                g.machine not in state.machines
                or state.machines[g.machine].canonical != name
            )
        ):
            reason = "changed since the page"
        if reason:
            skipped.append(
                {
                    "canonical": name,
                    "pairs": [list(p) for p in g.pairs],
                    "reason": reason,
                }
            )
            continue
        waiting = [list(p) for p in g.pairs if p not in state.bindings]
        key = state.machines[g.machine].keys[0] if g.machine else hi.new_machine_key()
        items.append({"key": key, "canonical": name, "pairs": waiting})
    if items:
        # One request: the guard checks each item in order under the log lock,
        # appends those it accepts and reports the others
        out = hi.append_decision_items(
            case_dir,
            {
                "action": "confirm",
                "examiner": examiner,
                "origin": "portal",
                "args": {"machines": items, "proposed": True},
            },
            seen,
        )
        refused = {r["index"]: r["reason"] for r in out.get("refused", [])}
        for i, item in enumerate(items):
            if i in refused:
                skipped.append(
                    {
                        "canonical": item["canonical"],
                        "pairs": item["pairs"],
                        "reason": refused[i],
                    }
                )
            else:
                confirmed.append(item["canonical"])
    summary = f"{len(confirmed)} confirmed" + (
        f", {len(skipped)} skipped" if skipped else ""
    )
    return {"confirmed": confirmed, "skipped": skipped, "summary": summary}


async def post_host_decision(request: Request) -> JSONResponse:
    routes = _routes()
    case_dir, error = _case_or_error()
    if error:
        return error
    examiner = routes._resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    raw = await request.body()
    if len(raw) > _LIST_MAX + 4096:
        return JSONResponse({"error": "request too large"}, status_code=413)
    try:
        body = json.loads(raw)
    except ValueError:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "invalid request"}, status_code=400)
    action = body.get("action")
    args = body.get("args") if isinstance(body.get("args"), dict) else {}
    seen = body.get("seen_offset")
    state = hi.load(case_dir)

    try:
        if action == "list":
            text = args.get("text")
            if not isinstance(text, str) or not text.strip():
                return JSONResponse(
                    {"error": "the host list is empty"}, status_code=400
                )
            result = hp.upload_host_list(case_dir, text, examiner)
            summary = f"{result.get('entries', 0)} listed, {len(result.get('confirmed', []))} confirmed"
            _audit(
                case_dir,
                examiner,
                action,
                {"sha256": result.get("sha256", "")},
                summary,
            )
            return JSONResponse({"ok": True, **result})
        if action in ("start_now", "cancel_run"):
            run_id = str(args.get("run_id") or "")
            if action == "start_now":
                result = hg.start_now(case_dir, run_id, examiner, seen_offset=seen)
                summary = (
                    f"{len(result.get('machines', []))} started now for run {run_id}"
                )
                if result.get("refused"):
                    summary += f", {len(result['refused'])} refused"
                    result["skipped"] = [
                        {
                            "canonical": (r.get("machine") or {}).get("canonical", ""),
                            "reason": r.get("reason", ""),
                        }
                        for r in result["refused"]
                    ]
            else:
                if run_id not in state.waits or run_id in state.cancelled:
                    raise hi.HostLogError(
                        f"no run {run_id!r} is waiting for host confirmation"
                    )
                hg.cancel(case_dir, run_id, examiner)
                result, summary = {}, f"run {run_id} cancelled"
            _audit(case_dir, examiner, action, {"run_id": run_id}, summary)
            return JSONResponse({"ok": True, "summary": summary, **result})
        if action == "confirm_all":
            result = _confirm_all(case_dir, state, examiner, args, seen)
            _audit(
                case_dir,
                examiner,
                "confirm_all",
                {"skipped": len(result["skipped"])},
                result["summary"],
            )
            return JSONResponse({"ok": True, **result})
        if action == "confirm":
            items = _confirm_items(state, args)
            record_args = {"machines": items}
            summary = f"{len(items)} confirmed"
        elif action == "not_a_host":
            pairs = _known_pairs(state, args.get("pairs"))
            if pairs is None:
                return JSONResponse(
                    {"error": "every pair must be a host name the case has seen"},
                    status_code=400,
                )
            record_args = {"pairs": pairs}
            summary = f"{len(pairs)} marked not a host"
        else:
            return JSONResponse(
                {"error": f"unknown host decision: {str(action)[:40]!r}"},
                status_code=400,
            )
        at = hi.append_decision(
            case_dir,
            {
                "action": action,
                "examiner": examiner,
                "origin": "portal",
                "args": record_args,
            },
            seen,
        )
    except _Refused as e:
        return JSONResponse({"error": str(e)}, status_code=e.status)
    except hi.HostLogError as e:
        return JSONResponse({"error": str(e)}, status_code=409)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    _audit(case_dir, examiner, action, {"count": summary.split()[0]}, summary)
    return JSONResponse({"ok": True, "decisions_offset": at, "summary": summary})


# --------------------------------------------------------------------------
# Host operations: rename, merge and split, run by opensearch-mcp's job.
# The job runs as its own process (it can take minutes): it takes the case
# lock exclusively, keeps its journal in host-ops.json, and writes the
# decision line itself once the docs carry the new names. The tab launches
# it and shows the journal; an operation left unfinished is resumed.

OP_KINDS = ("rename", "merge", "split")
_FIRST_ANSWER_SECONDS = 2.0  # a refusal or a quick op answers within this
_launches: dict[str, dict] = {}  # case dir -> the last launch from this gateway


def r_command(
    case_dir: Path,
    examiner: str,
    op: dict | None,
    resume: str | None,
    expect: dict | None = None,
):
    """The job's command line. `expect`: machine id -> the name the examiner
    saw, which the job checks under its lock (a resume carries none)."""
    import sys

    which = ["--resume", resume] if resume else ["--op", json.dumps(op)]
    if expect is not None and not resume:
        which += ["--expect", json.dumps(expect)]
    return [sys.executable, "-m", "opensearch_mcp.host_ops", "--case-dir",
            str(case_dir), "--examiner", examiner, *which]  # fmt: skip


def _r_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("opensearch_mcp") is not None


def _op_problem(body: dict) -> str | None:
    op, resume = body.get("op"), body.get("resume")
    if (op is None) == (resume is None):
        return "give either an operation or the id of one to resume"
    if resume is not None:
        return None if isinstance(resume, str) and resume else "resume needs an id"
    if not isinstance(op, dict) or op.get("kind") not in OP_KINDS:
        return f"an operation is one of {', '.join(OP_KINDS)}"
    if not isinstance(body.get("seen"), dict):
        return "an operation carries the names of the machines as the page showed them"
    return None


def _as_seen(state: hi.HostState, op: dict, seen: dict) -> tuple[dict, dict, str]:
    """The operation the job runs, what it expects to find, and why it can't
    be asked for at all ("" when it can). A machine merged in may be named as
    typed (`from_name`), resolved here to its id. `expect` maps each machine
    the operation names to the name the examiner saw (`seen`) or, for a
    typed name, the name it resolved to: the job checks it under the case
    lock it holds while it works, and refuses if any differs (or is gone)."""
    op = dict(op)
    typed = op.pop("from_name", None)
    expect: dict[str, str] = {}
    if op["kind"] == "merge" and typed is not None:
        owner = state.canonical_owner(str(typed))
        if owner is None:
            return op, expect, f"no machine is named {str(typed)[:80]!r} in this case"
        op["from"] = [owner.id]
        expect[owner.id] = owner.canonical
    named = [op.get("machine"), op.get("into")]
    if typed is None:
        named += list(op.get("from") or [])
    for key in (str(k) for k in named if k is not None):
        expect[key] = str(seen.get(key, ""))
    return op, expect, ""


def ops_view(case_dir: Path) -> dict:
    """The journal's unfinished operation (running or incomplete), the last
    one, and this gateway's last launch for the case."""
    journal = hi.read_ops(case_dir)["ops"]
    entries = [{"id": k, **v} for k, v in journal.items() if isinstance(v, dict)]
    last = max(entries, key=lambda e: str(e.get("updated", "")), default=None)
    unfinished = hi.unfinished_op(case_dir)
    for e in (last, unfinished):
        if e:
            e["to_relabel"] = _total(e.get("before"))
    launch = _launches.get(str(case_dir))
    return {"unfinished": unfinished, "last": last,
            "launch": {k: v for k, v in launch.items() if k != "task"} if launch else None}  # fmt: skip


def _total(before) -> int:
    if not isinstance(before, dict):
        return 0
    return sum(
        int(n)
        for part in ("keys", "v1")
        for n in (before.get(part) or {}).values()
        if isinstance(n, int)
    )


def get_ops(request: Request) -> JSONResponse:
    case_dir, error = _case_or_error()
    if error:
        return error
    try:
        return JSONResponse(ops_view(case_dir))
    except hi.HostLogError as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def post_op(request: Request) -> JSONResponse:
    """Launch a host operation, or resume an unfinished one. Answers with
    its outcome when the job ends at once (a refusal, a quick op), else 202
    while it runs; `GET /api/hosts/ops` follows it."""
    import asyncio
    from datetime import datetime, timezone

    routes = _routes()
    case_dir, error = _case_or_error()
    if error:
        return error
    examiner = routes._resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "invalid request"}, status_code=400)
    problem = _op_problem(body)
    if problem:
        return JSONResponse({"error": problem}, status_code=400)
    if not _r_available():
        return JSONResponse(
            {
                "error": "host operations need opensearch-mcp, which isn't installed here"
            },
            status_code=503,
        )
    key = str(case_dir)
    running = _launches.get(key)
    if running and running.get("state") == "running":
        return JSONResponse(
            {"error": "a host operation launched from the portal is still running"},
            status_code=409,
        )
    op, resume, expect = body.get("op"), body.get("resume"), None
    if op is not None:
        try:
            op, expect, unknown = _as_seen(hi.load(case_dir), op, body["seen"])
        except hi.HostLogError as e:
            return JSONResponse({"error": str(e)}, status_code=500)
        if unknown:
            return JSONResponse({"error": unknown}, status_code=400)
    proc = await asyncio.create_subprocess_exec(
        *r_command(case_dir, examiner, op, resume, expect),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,  # it finishes even if the gateway restarts
    )
    launch = {"pid": proc.pid, "examiner": examiner, "state": "running",
              "asked": op if op is not None else {"resume": resume},
              "started": datetime.now(timezone.utc).isoformat()}  # fmt: skip
    _launches[key] = launch
    _audit(case_dir, examiner, "op", {"op": launch["asked"]}, "launched")

    async def finish() -> None:
        out, err = await proc.communicate()
        lines = [x for x in out.decode("utf-8", "replace").splitlines() if x.strip()]
        try:
            result = json.loads(lines[-1]) if lines else {}
        except ValueError:
            result = {}
        if not isinstance(result, dict) or "state" not in result:
            tail = err.decode("utf-8", "replace").strip().splitlines()[-1:] or [
                "no output"
            ]
            result = {"state": "failed", "reason": f"the job exited {proc.returncode}: {tail[0][:300]}"}  # fmt: skip
        launch.update(state=result.get("state"), result=result)
        _audit(case_dir, examiner, "op", {"op": launch["asked"]},
               f"{result.get('state')}: {str(result.get('reason') or result.get('id') or '')[:200]}")  # fmt: skip

    launch["task"] = task = asyncio.ensure_future(finish())
    try:
        await asyncio.wait_for(asyncio.shield(task), _FIRST_ANSWER_SECONDS)
    except asyncio.TimeoutError:
        return JSONResponse({"state": "running", **ops_view(case_dir)}, status_code=202)
    result = launch["result"]
    status = {"refused": 409, "failed": 500}.get(result.get("state"), 200)
    return JSONResponse({**result, **ops_view(case_dir)}, status_code=status)
