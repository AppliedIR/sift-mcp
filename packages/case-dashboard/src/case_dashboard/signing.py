"""Signed decisions from the Examiner Portal: the browser signs, the gateway checks.

One commit dialog runs:
1. `POST /api/commit/plan` (the session token only): the entries the examiner
   is signing are planned against the case files, with a pinned time and
   ledger head, into the exact body strings that will be signed. A challenge
   holds that plan for 120 s.
2. `POST /api/commit/key`: the login response. Once it verifies, the
   examiner's wrapped signing key. The browser unwraps it with the
   passphrase and signs each body string as handed.
3. `POST /api/commit`: under the case lock, the plan is made again from the
   challenge's entries; a moved head or any changed body refuses it, with
   nothing written. vhir's ledger writer checks every signature and appends;
   then the case files are saved and exactly the signed entries leave
   pending-reviews.json.

Every writer of pending-reviews.json and the case files here holds the case
lock from load to save, in a worker thread, off the event loop. The gateway
derives nothing from the passphrase and never holds a private key.
"""

from __future__ import annotations

import copy
import getpass
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse
from vhir_cli import approval_auth, approval_checks, credentials, decide, keys, ledger
from vhir_cli.case_io import (
    case_id_of,
    compute_content_hash,
    load_case_meta,
    set_status,
    signed_text,
    write_approval_log,
)
from vhir_cli.identity import valid_name

logger = logging.getLogger(__name__)

CHALLENGE_SECONDS = 120
LOCK_SECONDS = 10
_MAX_OPEN_CHALLENGES = 4  # per examiner; the oldest open one is dropped
_KEEP_SECONDS = 900  # how long a used or expired challenge can be named by `retry_of`

# What a staged entry may carry. `staged_by`, `saved_unsigned` and
# `review_again` are the server's and the CLI's stamps: a client may send
# them back as it loaded them, but its values are never stored.
ENTRY_KEYS = frozenset(
    {
        "id", "type", "action", "content_hash_at_review", "modifications",
        "rejection_reason", "note", "todo_description", "todo_priority",
        "todo_assignee", "staged_by", "saved_unsigned", "review_again",
    }
)  # fmt: skip
_STAMPS = ("staged_by", "saved_unsigned", "review_again")
_ACTIONS = ("approve", "reject", "edit", "todo")
_STATUS_AFTER = {"approve": "APPROVED", "reject": "REJECTED"}
# An IOC's value and type are what the examiner decides; its tags and
# description are the only fields the portal edits
_IOC_EDITABLE = frozenset({"tags", "description"})

# A typed approval override reason: at most this many characters
_REASON_CHARS = 2000

_challenges: dict[str, dict] = {}


def _error(code: str, message: str, status: int, **extra) -> JSONResponse:
    return JSONResponse({"code": code, "error": message, **extra}, status_code=status)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _config_path() -> Path:
    return Path.home() / ".vhir" / "config.yaml"


# --- Who signs -------------------------------------------------------------------------


def _signer(request: Request) -> tuple[str | None, JSONResponse | None]:
    """The examiner whose gateway token made this request. Without gateway
    API keys every request is "anonymous", so nobody can sign here."""
    examiner = getattr(request.state, "examiner", None)
    if not examiner or examiner == "anonymous":
        return None, _error(
            "NO_API_KEYS",
            "Portal approvals need gateway API keys, so that each examiner signs in "
            "with their own token. Sign at the SIFT terminal with "
            "`vhir approve --review`.",
            403,
        )
    if not valid_name(examiner):
        return None, _error("NO_EXAMINER", f"Invalid examiner name: {examiner!r}", 401)
    return examiner, None


def no_key_text(examiner: str, state: str) -> str:
    if state == "legacy":
        return (
            f"{examiner} has a 0.6 passphrase and no signing key yet. At the SIFT "
            f"terminal run `vhir enrol --name {examiner} --upgrade` (or "
            "`vhir config --upgrade-key` for this box's own examiner), or sign the "
            "staged reviews there with `vhir approve --review`."
        )
    return (
        f"{examiner} has no signing key. At the SIFT terminal run "
        f"`vhir enrol --name {examiner}`; the person named types their own "
        "passphrase there."
    )


def signing_state(examiner: str | None, case_dir: Path | None = None) -> dict:
    """For `GET /api/case`: whether this examiner can sign here, and why not."""
    if not examiner or examiner == "anonymous":
        return {"signing_available": False, "reason": "NO_API_KEYS", "schema": None,
                "fingerprint": None, "examiner": None,
                "message": "Portal approvals need gateway API keys; sign at the "
                           "SIFT terminal with `vhir approve --review`."}  # fmt: skip
    out = {"examiner": examiner, "schema": None, "fingerprint": None}
    if not valid_name(examiner):
        return {**out, "signing_available": False, "reason": "NO_EXAMINER",
                "message": f"Invalid examiner name: {examiner!r}"}  # fmt: skip
    folders = credentials.signing_folders_problem()
    if folders:
        return {**out, "signing_available": False, "reason": "UPDATE_UNFINISHED",
                "message": folders}  # fmt: skip
    in_a_copy = decide.copy_problem(case_dir) if case_dir else ""
    if in_a_copy:
        return {**out, "signing_available": False, "reason": _copy_code(in_a_copy),
                "message": in_a_copy}  # fmt: skip
    try:
        state = credentials.state(examiner, _config_path())
    except keys.KeysFileInvalid as e:
        return {**out, "signing_available": False, "reason": "KEYS_FILE_INVALID",
                "message": _keys_invalid_text(examiner, e)}  # fmt: skip
    if state != "schema3":
        return {**out, "signing_available": False, "reason": "NO_SIGNING_KEY",
                "schema": "0.6" if state == "legacy" else None,
                "message": no_key_text(examiner, state)}  # fmt: skip
    entry = keys.active(keys.load(examiner))
    return {**out, "signing_available": True, "reason": None, "schema": 3,
            "fingerprint": keys.key_fingerprint(entry), "message": ""}  # fmt: skip


def _copy_code(problem: str) -> str:
    return "CHAIN_UNREADABLE" if problem == ledger.CHAIN_UNREADABLE else "CASE_COPY"


def _keys_invalid_text(examiner: str, e: Exception) -> str:
    return (
        f"KEYS_FILE_INVALID: {e}. At the SIFT terminal run "
        f"`vhir enrol --name {examiner} --forgot`."
    )


def _credential(examiner: str) -> tuple[dict | None, JSONResponse | None]:
    """The examiner's schema-3 credential, or the refusal to send."""
    try:
        state = credentials.state(examiner, _config_path())
    except keys.KeysFileInvalid as e:
        return None, _error("KEYS_FILE_INVALID", _keys_invalid_text(examiner, e), 409)
    if state != "schema3":
        return None, _error("NO_SIGNING_KEY", no_key_text(examiner, state), 409)
    return keys.load(examiner), None


def _lockout_left(examiner: str) -> int:
    """Seconds left on the shared passphrase lockout (the CLI's), or 0."""
    now = time.time()
    failures = approval_auth._load_failures().get(examiner, [])
    recent = [
        t
        for t in (failures if isinstance(failures, list) else [])
        if isinstance(t, (int, float)) and now - t < approval_auth._LOCKOUT_SECONDS
    ]
    if len(recent) < approval_auth._MAX_PASSWORD_ATTEMPTS:
        return 0
    return max(int(approval_auth._LOCKOUT_SECONDS - (now - min(recent))), 1)


# --- Staged entries --------------------------------------------------------------------


def entry_problem(entry: object) -> str | None:
    """Why a posted entry isn't one, or None."""
    if not isinstance(entry, dict):
        return "Each item must be an object"
    unknown = set(entry) - ENTRY_KEYS
    if unknown:
        return f"Unknown fields in delta item: {', '.join(sorted(unknown))}"
    missing = {"id", "type", "action"} - set(entry)
    if missing:
        return f"Missing required fields in delta item: {', '.join(sorted(missing))}"
    if not isinstance(entry["id"], str) or not entry["id"]:
        return "A delta item's id must be a non-empty string"
    if str(entry["action"]).lower() not in _ACTIONS:
        return f"Unknown action in delta item {entry['id']}: {entry['action']!r}"
    mods = entry.get("modifications", {})
    if mods is not None and not (
        isinstance(mods, dict) and all(isinstance(m, dict) for m in mods.values())
    ):
        return f"Delta item {entry['id']}: modifications must map fields to objects"
    for name in ("staged_by",):
        if entry.get(name) is not None and not isinstance(entry.get(name), str):
            return f"Delta item {entry['id']}: {name} must be a string"
    return None


def stripped(entry: dict) -> dict:
    """An entry without the stamps: what two copies of it share."""
    return {k: v for k, v in entry.items() if k not in _STAMPS}


def _delta_path(case_dir: Path) -> Path:
    return case_dir / "pending-reviews.json"


def merge_processing(case_dir: Path) -> None:
    """A `.processing` file left by 0.6: each entry whose id isn't in
    pending-reviews.json is merged in, unstamped ("staged by unknown"), and
    the file is kept as `.processing.merged-<UTC>`. The caller holds the case
    lock. Never deleted or overwritten."""
    processing = case_dir / "pending-reviews.processing"
    if not processing.exists():
        return
    try:
        old = json.loads(processing.read_text())
    except (OSError, ValueError):
        old = {}
    path = _delta_path(case_dir)
    delta = decide.read_delta(path) or {"case_id": case_id_of(case_dir), "items": []}
    have = {e.get("id") for e in delta.get("items", []) if isinstance(e, dict)}
    for e in old.get("items", []) if isinstance(old, dict) else []:
        if isinstance(e, dict) and e.get("id") not in have:
            delta.setdefault("items", []).append(
                {k: v for k, v in e.items() if k not in _STAMPS}
            )
    decide._write_delta(path, delta)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    processing.rename(
        processing.with_name(f"pending-reviews.processing.merged-{stamp}")
    )


def _load_delta_locked(case_dir: Path) -> dict:
    """pending-reviews.json, with a 0.6 `.processing` file merged in; a
    corrupt file is set aside, never overwritten. The caller holds the lock."""
    merge_processing(case_dir)
    delta = decide.read_delta(_delta_path(case_dir)) or {}
    delta.setdefault("case_id", case_id_of(case_dir))
    delta["items"] = [e for e in delta.get("items", []) if isinstance(e, dict)]
    return delta


def _own_key(entry: dict) -> tuple:
    # one decision per id; TODO entries are kept each
    clean = stripped(entry)
    todo = str(clean.get("action")).lower() == "todo"
    return (clean.get("id"), json.dumps(clean, sort_keys=True) if todo else "")


def merge_post(stored: list[dict], posted: list[dict], poster: str):
    """The stored entries after `poster` posts `posted`: a posted entry of
    the poster's replaces their stored one for the same id (a TODO is kept
    each); their stored entries the post doesn't name are kept, as is
    everyone else's and any with no `staged_by` (an entry leaves only by
    DELETE or by being signed). A posted copy equal to a stored entry of the
    poster's keeps its stamps; any other posted entry of the poster's is
    stamped as theirs. A posted entry carrying someone else's `staged_by`,
    or equal to an unstamped stored entry, is dropped. Returns (entries,
    dropped)."""
    kept = [s for s in stored if s.get("staged_by") != poster]
    unknown = [stripped(s) for s in stored if not s.get("staged_by")]
    mine = [s for s in stored if s.get("staged_by") == poster]
    dropped: list[dict] = []
    own: dict[tuple, dict] = {_own_key(s): s for s in mine}
    for p in posted:
        who = p.get("staged_by")
        if who not in (None, "", poster):
            dropped.append({"id": p.get("id"), "staged_by": who})
            continue
        clean = stripped(p)
        if not who and clean in unknown:
            dropped.append({"id": p.get("id"), "staged_by": None})
            continue
        same = next((s for s in mine if stripped(s) == clean), None)
        own[_own_key(p)] = same if same is not None else {**clean, "staged_by": poster}
    return kept + list(own.values()), dropped


def remove_signed(stored: list[dict], signed: list[dict], examiner: str) -> list[dict]:
    """The stored entries without those just signed: each matched by id,
    `staged_by` and equal fields apart from the stamps. A stored entry that
    differs from what was signed was changed after it was read, so it stays."""

    def signed_one(s: dict) -> bool:
        for p in signed:
            if stripped(s) != stripped(p):
                continue
            who = p.get("staged_by")
            if s.get("staged_by") == who or (
                who in (None, "", examiner) and s.get("staged_by") == examiner
            ):
                return True
        return False

    return [s for s in stored if not signed_one(s)]


# --- The plan --------------------------------------------------------------------------


@dataclass
class Plan:
    every: list[decide.Decision] = field(default_factory=list)
    items: list[dict] = field(default_factory=list)
    bodies: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    refused: list[dict] = field(default_factory=list)
    held: list[dict] = field(default_factory=list)

    def texts(self) -> list[str]:
        return [ledger.canonical(b).decode("ascii") for b in self.bodies]


def _direct(entries, lists, examiner: str, now: str):
    """The direct decisions of `entries` against `lists`, each item with its
    edits and note applied, as the CLI's review applies them. Returns
    (decisions, refusals)."""
    direct: list[decide.Decision] = []
    refused: list[dict] = []
    for e in entries:
        item_id, action = e["id"], str(e["action"]).lower()
        kind = decide.item_type(item_id)
        current = decide._find(lists, kind, item_id)
        if current is None:
            refused.append({"id": item_id, "reason": "not found"})
            continue
        at_review = e.get("content_hash_at_review") or ""
        if at_review and at_review != compute_content_hash(current):
            refused.append({"id": item_id, "reason": "changed after it was reviewed"})
            continue
        mods = e.get("modifications") or {}
        editable = _IOC_EDITABLE if kind == "ioc" else decide.DELTA_EDITABLE_FIELDS
        bad = sorted(f for f in mods if f not in editable)
        if bad:
            refused.append(
                {"id": item_id, "reason": f"can't be edited: {', '.join(bad)}"}
            )
            continue
        conflict = next(
            (f for f, m in mods.items() if current.get(f) != m.get("original")), None
        )
        if conflict:
            refused.append({"id": item_id, "reason": f"field '{conflict}' changed since review"})  # fmt: skip
            continue
        item = copy.deepcopy(current)
        for f, m in mods.items():
            item[f] = copy.deepcopy(m.get("modified"))
            item.setdefault("examiner_modifications", {})[f] = {
                "original": m.get("original"), "modified": m.get("modified"),
                "modified_by": examiner, "modified_at": now,
            }  # fmt: skip
        if e.get("note"):
            item.setdefault("examiner_notes", []).append(
                {"note": e["note"], "by": examiner, "at": now}
            )
        if kind == "ioc" and action in _STATUS_AFTER:
            item["manually_reviewed"] = True
        after = (
            current.get("status", "DRAFT")
            if action == "edit"
            else _STATUS_AFTER[action]
        )
        direct.append(
            decide.Decision(item, kind, action, after, loaded=copy.deepcopy(current),
                            reason=e.get("rejection_reason", "") or "",
                            note=e.get("note", "") or "", modifications=mods,
                            delta_entry=e)
        )  # fmt: skip
    return direct, refused


def make_plan(case_dir, case_id, entries, lists, examiner, public, now, head,
              approval_override_reasons=None) -> Plan:  # fmt: skip
    """The bodies `entries` give against `lists` (which this edits in place,
    as the commit applies them), chained from `head` and dated `now`. Each
    direct approval runs the approval checks; one that failed needs its
    reason in `approval_override_reasons` ({item id: {reason,
    failed_sha256}}), given for exactly the failed checks it now has (their
    `approval_checks.failed_sha256`); else it is refused as CHECKS_FAILED with
    its checks. A large root is hashed in the background meanwhile."""
    from vhir_cli.ledger_verify import chain_references

    direct, refused = _direct(entries, lists, examiner, now)
    if refused:
        return Plan(refused=refused)
    reasons = approval_override_reasons or {}
    checked = [
        d for d in direct
        if d.decision == "approve" and d.type in ("finding", "timeline")
    ]  # fmt: skip
    # the audit trail is read once for every item in the plan
    trail = approval_checks.PlanTrail(case_dir, [(d.item, d.type) for d in checked])
    for d in checked:
        try:
            d.checks = approval_checks.check_item(
                case_dir, d.item, d.type, background=True, trail=trail
            )
        except (
            approval_checks.AuditUnreadable
        ) as e:  # nothing to override: refused whole
            raise _Refused(_error("AUDIT_UNREADABLE", str(e), 409)) from e
        if d.checks["result"] != "failed":
            continue
        given = reasons.get(d.id) or {}
        if given.get("failed_sha256") == approval_checks.failed_sha256(d.checks):
            d.approval_override_reason = given["reason"]
        else:  # none, or given for other failures than these
            refused.append({"id": d.id, "reason": "CHECKS_FAILED", "checks": d.checks})
    if refused:
        return Plan(refused=refused)
    for d in direct:  # the reloaded record with only this decision on it
        lst = lists[d.type]
        for i, x in enumerate(lst):
            if isinstance(x, dict) and x.get("id") == d.id:
                lst[i] = decide._spliced(x, d)
    planned, held = decide.split_cascades(
        direct, lists["finding"], lists["timeline"], lists["ioc"]
    )
    every = direct + planned
    items = [decide._find(lists, d.type, d.id) for d in every]
    decisions = [
        {"item_id": d.id, "type": d.type, "decision": d.decision,
         "status_after": d.status_after, "coupled_from": d.coupled_from,
         "content_snapshot": signed_text(item, d.type),
         **({"checks": d.checks} if d.checks is not None else {}),
         **({"approval_override_reason": d.approval_override_reason}
            if d.approval_override_reason is not None else {})}
        for d, item in zip(every, items, strict=True)
    ]  # fmt: skip
    refs, notes = chain_references(case_dir, case_id)
    bodies = ledger.prepare(
        case_id, decisions, examiner, public, "portal", now, head=head,
        retired=credentials.retired_fingerprints(examiner), prior_chains=refs or None,
        case_uuid=load_case_meta(case_dir).get("case_uuid"),
    )  # fmt: skip
    # an event held back: id and finding; an IOC left DRAFT: also its citing findings
    held = [
        {"id": h[0], "coupled_from": h[1],
         **({"citing": [{"id": f, "status_after": a} for f, a in h.citing]}
            if getattr(h, "citing", ()) else {})}
        for h in held
    ]  # fmt: skip
    return Plan(every=every, items=items, bodies=bodies, notes=notes, held=held)


def _selection(entries, include_others, stored, examiner):
    """The entries to sign: todo entries are left out (only `vhir approve
    --review` makes TODOs). An entry carrying another examiner's
    `staged_by`, equal to that examiner's stored entry, is signed only when
    its id is in `include_others`. Returns (entries, refusal or None)."""
    chosen, foreign = [], []
    for e in entries:
        if str(e.get("action")).lower() == "todo":
            continue
        who = e.get("staged_by")
        theirs = (
            who not in (None, "", examiner)
            and any(s.get("staged_by") == who and stripped(s) == stripped(e) for s in stored)
        )  # fmt: skip
        if theirs and e["id"] not in include_others:
            foreign.append({"id": e["id"], "staged_by": who})
            continue
        chosen.append(e)
    if foreign:
        return chosen, _error(
            "NOT_INCLUDED",
            "Entries staged by another examiner are signed only when you include them: "
            + ", ".join(f"{f['id']} (staged by {f['staged_by']})" for f in foreign),
            409,
            items=foreign,
        )
    ids = [e["id"] for e in chosen]
    twice = sorted({i for i in ids if ids.count(i) > 1})
    if twice:
        return chosen, _error(
            "DUPLICATE_ITEM",
            f"{', '.join(twice)} selected twice; nothing was signed. Keep one entry for each.",
            409,
            items=twice,
        )
    return chosen, None


def _read_lists(case_dir: Path):
    lists, bad = decide._reload(case_dir)
    if bad:
        return None, _error(
            "CASE_FILE_UNREADABLE",
            f"{', '.join(bad)} couldn't be read as case data; nothing was signed.",
            409,
        )
    return lists, None


# --- Challenges ------------------------------------------------------------------------


def _prune(now: float) -> None:
    for cid in [
        c for c, ch in _challenges.items() if now - ch["created"] > _KEEP_SECONDS
    ]:
        del _challenges[cid]


def _open(ch: dict, now: float) -> bool:
    return not ch["used"] and now < ch["expires"]


def _add_challenge(ch: dict) -> str:
    now = time.time()
    _prune(now)
    mine = sorted(
        (c for c in _challenges.items() if c[1]["examiner"] == ch["examiner"] and _open(c[1], now)),
        key=lambda c: c[1]["created"],
    )  # fmt: skip
    while len(mine) >= _MAX_OPEN_CHALLENGES:
        del _challenges[mine.pop(0)[0]]
    cid = secrets.token_hex(16)
    _challenges[cid] = ch
    return cid


def _challenge(body: dict, examiner: str, *, need_login: bool):
    """The open challenge `body` names, or the refusal."""
    cid = body.get("challenge_id") if isinstance(body, dict) else None
    ch = _challenges.get(cid) if isinstance(cid, str) else None
    now = time.time()
    if ch is None or ch["examiner"] != examiner or ch["used"]:
        return None, _error("CHALLENGE_INVALID", "This signing request is no longer valid. Close the dialog and commit again.", 401)  # fmt: skip
    if now >= ch["expires"]:
        return None, _error("CHALLENGE_EXPIRED", "This signing request expired.", 401)
    if need_login and not ch["login_ok"]:
        return None, _error(
            "CHALLENGE_INVALID", "Sign in with your passphrase first.", 401
        )
    return ch, None


async def _json(request: Request):
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - any unparseable body is a 400
        return None, _error("BAD_REQUEST", "Invalid JSON", 400)
    if not isinstance(body, dict):
        return None, _error("BAD_REQUEST", "Expected a JSON object", 400)
    return body, None


def _resolve_case_dir() -> Path | None:
    from case_dashboard.routes import _resolve_case_dir as resolve

    return resolve()


def _no_case() -> JSONResponse:
    return _error("NO_CASE", "No active case. Run `vhir case activate` first.", 404)


async def post_commit_plan(request: Request) -> JSONResponse:
    """`{entries, include_others?, retry_of?}` → the bodies to sign and a
    challenge. Needs the session token only: no passphrase, no key."""
    examiner, refusal = _signer(request)
    if refusal:
        return refusal
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case()
    body, refusal = await _json(request)
    if refusal:
        return refusal
    folders = credentials.signing_folders_problem()
    if folders:  # a box updated once from 0.6, or a folder that isn't ours
        return _error("UPDATE_UNFINISHED", folders, 409)
    in_a_copy = decide.copy_problem(case_dir)
    if in_a_copy:  # another folder's chain, or one that can't be read
        return _error(_copy_code(in_a_copy), in_a_copy, 409)
    data, refusal = _credential(examiner)
    if refusal:
        return refusal
    left = _lockout_left(examiner)
    if left:
        return _error(
            "LOCKED_OUT", f"Too many failed attempts. Try again in {left}s.", 429
        )
    entries = body.get("entries")
    if not isinstance(entries, list) or not entries:
        return _error("BAD_REQUEST", "No entries to sign.", 400)
    for e in entries:
        problem = entry_problem(e)
        if problem:
            return _error("BAD_REQUEST", problem, 400)
    include = body.get("include_others") or []
    if not isinstance(include, list):
        return _error("BAD_REQUEST", "include_others must be a list of ids", 400)
    reasons = body.get("approval_override_reasons") or {}
    problem = _reasons_problem(reasons, entries)
    if problem:
        return _error("BAD_REQUEST", problem, 400)
    retries_left = 1
    retry_of = body.get("retry_of")
    if retry_of is not None:
        prior = _challenges.get(retry_of) if isinstance(retry_of, str) else None
        if prior is None or prior["examiner"] != examiner or prior["retries_left"] < 1:
            return _error(
                "RETRY_REFUSED",
                "This dialog has already planned again once. Close it and review again.",
                409,
            )
        prior["retries_left"] = 0
        retries_left = 0
    case_id = case_id_of(case_dir)
    public = keys.active(data)["public_key"]
    try:  # a case with no identity yet gets it now, so the commit's replan binds it
        await anyio.to_thread.run_sync(decide.mint_identity, case_dir)
    except ledger.CaseCopy as e:
        return _error("CASE_IDENTITY", str(e), 409)
    try:
        out = await anyio.to_thread.run_sync(
            _plan_unlocked, case_dir, case_id, entries, set(map(str, include)),
            examiner, public, reasons,
        )  # fmt: skip
    except _Refused as r:
        return r.response
    except ledger.LedgerBusy as e:
        return _error("LEDGER_BUSY", str(e), 503)
    except ledger.LockDirMissing as e:
        return _error("LOCK_DIR_MISSING", str(e), 500)
    except ledger.CaseCopy as e:
        return _error("CASE_COPY", f"{e} Nothing was signed.", 409)
    except ledger.CaseRecordUnwritable as e:
        return _error("CASE_RECORD_UNWRITABLE", str(e), 500)
    except ledger.LedgerError as e:
        return _error("LEDGER_UNREADABLE", str(e), 409)
    chosen, plan, now, head = out
    ch = {
        "examiner": examiner, "case_dir": str(case_dir), "case_id": case_id,
        "nonce": secrets.token_hex(32), "now": now, "head": head,
        "entries": copy.deepcopy(chosen), "texts": plan.texts(),
        "approval_override_reasons": dict(reasons),
        "created": time.time(), "expires": time.time() + CHALLENGE_SECONDS,
        "login_ok": False, "used": False, "retries_left": retries_left,
    }  # fmt: skip
    cid = _add_challenge(ch)
    return JSONResponse(
        {
            "challenge_id": cid,
            "nonce": ch["nonce"],
            "salt_auth": data["salt_auth"],
            "iterations": data["kdf"]["iterations"],
            "expires_in": CHALLENGE_SECONDS,
            "examiner": examiner,
            "case_id": case_id,
            "now": now,
            "head": {"seq": head[0], "hash": head[1]} if head else None,
            "bodies": [
                {
                    "item_id": b["item_id"],
                    "type": b["type"],
                    "coupled_from": b.get("coupled_from"),
                    "body": text,
                }
                for b, text in zip(plan.bodies, ch["texts"], strict=True)
            ],  # fmt: skip
            "notes": plan.notes,
            "needs_decision": plan.held,
        }
    )


def _reasons_problem(reasons, entries) -> str:
    """Why an `approval_override_reasons` map is refused ("" when it isn't):
    {entry id: {"reason": a typed reason of at most 2000 characters,
    "failed_sha256": the failed checks it was given for}}."""
    if not isinstance(reasons, dict):
        return "approval_override_reasons must be a map of item id to reason"
    ids = {e.get("id") for e in entries if isinstance(e, dict)}
    for item_id, given in reasons.items():
        if item_id not in ids:
            return f"approval_override_reasons names {item_id!r}, which isn't an entry"
        if not isinstance(given, dict) or not isinstance(
            given.get("failed_sha256"), str
        ):
            return f"the approval override reason for {item_id} names no failed checks"
        reason = given.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            return f"the approval override reason for {item_id} is empty"
        if len(reason) > _REASON_CHARS:
            return (
                f"the approval override reason for {item_id} is longer than "
                f"{_REASON_CHARS} characters"
            )
    return ""


def _plan_unlocked(case_dir, case_id, entries, include, examiner, public, reasons=None):
    """The plan `/plan` returns: read without the lock (nothing is written;
    the commit plans again under it)."""
    stored = _stored_entries(case_dir)
    chosen, refusal = _selection(entries, include, stored, examiner)
    if refusal:
        raise _Refused(refusal)
    if not chosen:
        raise _Refused(_error(
            "BAD_REQUEST",
            "No decisions to sign (TODO entries are made by `vhir approve --review`).",
            400,
        ))  # fmt: skip
    now, head = _now(), ledger.current_head(case_id)
    lists, refusal = _read_lists(case_dir)
    if refusal:
        raise _Refused(refusal)
    plan = make_plan(case_dir, case_id, chosen, lists, examiner, public, now, head,
                     approval_override_reasons=reasons)  # fmt: skip
    if plan.refused:
        raise _Refused(_plan_changed(plan.refused))
    return chosen, plan, now, head


def _checks_failed(items: list[dict]) -> JSONResponse:
    return _error(
        "CHECKS_FAILED",
        "An approval check failed for "
        + ", ".join(i["id"] for i in items)
        + ". Type why you approve each anyway, or close this dialog. Nothing was signed.",
        409,
        items=[
            {
                "id": i["id"],
                "checks": i["checks"],
                "failed_sha256": approval_checks.failed_sha256(i["checks"]),
            }
            for i in items
        ],  # fmt: skip
    )


def _plan_changed(items: list[dict]) -> JSONResponse:
    failed = [i for i in items if i.get("reason") == "CHECKS_FAILED"]
    if failed:
        return _checks_failed(failed)
    return _error(
        "PLAN_CHANGED",
        "What would be signed changed after you reviewed it: "
        + ", ".join(f"{i['id']} ({i['reason']})" for i in items)
        + ". Close this dialog and review again. Nothing was signed.",
        409,
        items=items,
    )


def _stored_entries(case_dir: Path) -> list[dict]:
    with ledger.case_lock(case_id_of(case_dir), timeout=LOCK_SECONDS):
        return _load_delta_locked(case_dir)["items"]


async def post_commit_key(request: Request) -> JSONResponse:
    """`{challenge_id, response}` → the wrapped signing key, after the login
    response verifies. A failure counts toward the shared lockout."""
    examiner, refusal = _signer(request)
    if refusal:
        return refusal
    body, refusal = await _json(request)
    if refusal:
        return refusal
    ch, refusal = _challenge(body, examiner, need_login=False)
    if refusal:
        return refusal
    left = _lockout_left(examiner)
    if left:
        return _error(
            "LOCKED_OUT", f"Too many failed attempts. Try again in {left}s.", 429
        )
    data, refusal = _credential(examiner)
    if refusal:
        return refusal
    response = body.get("response")
    expected = hmac.new(
        bytes.fromhex(data["auth_hash"]), ch["nonce"].encode("ascii"), hashlib.sha256
    ).hexdigest()
    if not isinstance(response, str) or not hmac.compare_digest(expected, response):
        approval_auth._record_failure(examiner)
        remaining = approval_auth._MAX_PASSWORD_ATTEMPTS - approval_auth._recent_failure_count(examiner)  # fmt: skip
        msg = (
            f"Incorrect passphrase. {remaining} attempt(s) remaining."
            if remaining > 0
            else f"Too many failed attempts. Locked for {approval_auth._LOCKOUT_SECONDS}s."
        )
        return _error("BAD_PASSWORD", msg, 401)
    approval_auth._clear_failures(examiner)
    ch["login_ok"] = True
    entry = keys.active(data)
    return JSONResponse(
        {
            "wrapped_private": entry["wrapped_private"],
            "public_key": entry["public_key"],
            "salt_ledger": data["salt_ledger"],
            "iterations": data["kdf"]["iterations"],
            "examiner": examiner,
            "fingerprint": keys.key_fingerprint(entry),
        }
    )


class _Refused(Exception):
    def __init__(self, response: JSONResponse):
        self.response = response


def _commit_locked(ch: dict, sigs: dict, examiner: str) -> dict:
    """Under the case lock: re-plan from the challenge's entries with its
    pinned time and head, append the signed lines, apply them to the
    reloaded items, save, and take the signed entries out of
    pending-reviews.json. Raises _Refused with nothing written, except where
    the response says otherwise."""
    case_dir, case_id = Path(ch["case_dir"]), ch["case_id"]
    data = keys.load(examiner)
    public = keys.active(data)["public_key"] if data and keys.active(data) else ""
    with ledger.case_lock(case_id, timeout=LOCK_SECONDS) as lock:
        if ledger.current_head(case_id) != ch["head"]:
            raise _Refused(_error("LEDGER_MOVED", "The ledger moved since this was planned.", 409))  # fmt: skip
        lists, refusal = _read_lists(case_dir)
        if refusal:
            raise _Refused(refusal)
        plan = make_plan(case_dir, case_id, ch["entries"], lists, examiner, public,
                         ch["now"], ch["head"],
                         approval_override_reasons=ch.get("approval_override_reasons"))  # fmt: skip
        if plan.refused:
            raise _Refused(_plan_changed(plan.refused))
        if plan.texts() != ch["texts"]:
            changed = [
                {"id": b["item_id"], "reason": "its signed content changed"}
                for b, t in zip(plan.bodies, plan.texts(), strict=False)
                if t not in ch["texts"]
            ] or [{"id": "-", "reason": "the set to be signed changed"}]
            raise _Refused(_plan_changed(changed))
        lines = []
        for b in plan.bodies:
            sig = sigs.get(b["item_id"])
            if not isinstance(sig, str):
                raise _Refused(_error("BAD_SIGNATURE", f"No signature for {b['item_id']}; nothing was signed.", 401))  # fmt: skip
            lines.append(ledger.canonical({**b, "sig": sig}).decode("ascii"))
        try:
            head = ledger.commit(
                lock, plan.bodies, lines, public,
                before_write=lambda: decide.record_folder(case_dir),  # once they verify
            )  # fmt: skip
        except ledger.BadSignature as e:
            raise _Refused(
                _error("BAD_SIGNATURE", f"{e}; nothing was signed.", 401)
            ) from e
        except ledger.LedgerTorn as e:
            raise _Refused(_error(
                "LEDGER_TORN",
                f"{e} Some of these decisions may already be signed: `vhir review "
                "--verify` at the SIFT terminal lists each one as a failure, with its fix.",
                500,
            )) from e  # fmt: skip
        for d, item, body in zip(plan.every, plan.items, plan.bodies, strict=True):
            set_status(item, d.decision, d.status_after, body["examiner"], body["at"],
                       reason=d.reason)  # fmt: skip
        save_error = decide._save_twice(case_dir, lists, {d.type for d in plan.every})
        delta_error = None
        todos = 0
        if save_error is None:
            try:  # exactly the signed entries leave pending-reviews.json
                delta = _load_delta_locked(case_dir)
                delta["items"] = remove_signed(delta["items"], ch["entries"], examiner)
                delta["modified_at"] = _now()
                decide._write_delta(_delta_path(case_dir), delta)
                todos = sum(
                    1 for e in delta["items"] if str(e.get("action")).lower() == "todo"
                )
            except OSError as e:
                delta_error = e
    return {"plan": plan, "head": head, "public": public, "save_error": save_error,
            "delta_error": delta_error, "todos": todos}  # fmt: skip


async def post_commit(request: Request) -> JSONResponse:
    """`{challenge_id, sigs: {item_id: base64}}` → the decisions signed and
    applied, or a refusal with nothing written."""
    examiner, refusal = _signer(request)
    if refusal:
        return refusal
    body, refusal = await _json(request)
    if refusal:
        return refusal
    ch, refusal = _challenge(body, examiner, need_login=True)
    if refusal:
        return refusal
    sigs = body.get("sigs")
    if not isinstance(sigs, dict):
        return _error("BAD_SIGNATURE", "No signatures; nothing was signed.", 401)
    ch["used"] = True  # single use; a moved or busy ledger is retried by a new plan
    retry = ch["retries_left"]
    ch["retries_left"] = 0  # only a moved or busy ledger keeps the one retry
    try:
        out = await anyio.to_thread.run_sync(_commit_locked, ch, sigs, examiner)
    except _Refused as r:
        if json.loads(r.response.body).get("code") == "LEDGER_MOVED":
            ch["retries_left"] = retry
        return r.response
    except ledger.LedgerBusy as e:
        ch["retries_left"] = retry
        return _error("LEDGER_BUSY", str(e), 503)
    except ledger.LockDirMissing as e:
        return _error("LOCK_DIR_MISSING", str(e), 500)
    except ledger.CaseCopy as e:
        return _error("CASE_COPY", f"{e} Nothing was signed.", 409)
    except ledger.CaseRecordUnwritable as e:
        return _error("CASE_RECORD_UNWRITABLE", str(e), 500)
    except ledger.LedgerError as e:
        return _error("LEDGER_UNREADABLE", f"{e} Nothing was signed.", 409)
    plan, head = out["plan"], out["head"]
    identity = {"examiner": examiner, "examiner_source": "dashboard",
                "os_user": getpass.getuser()}  # fmt: skip
    for d, item in zip(plan.every, plan.items, strict=True):
        try:  # the unsigned activity log; best effort, after the signed commit
            write_approval_log(Path(ch["case_dir"]), d.id, d.status_after, identity,
                               reason=d.reason, mode="dashboard",
                               content_hash=item.get("content_hash", ""),
                               coupled_from=d.coupled_from or "")  # fmt: skip
        except Exception:  # noqa: BLE001
            logger.warning("activity log not written for %s", d.id)
    counts = {"approve": 0, "reject": 0, "edit": 0}
    for d in plan.every:
        counts[d.decision] = counts.get(d.decision, 0) + 1
    fp = keys.fingerprint(keys.unb64(out["public"]))
    result = {
        "approved": sum(1 for d in plan.every if d.status_after == "APPROVED" and d.decision == "approve"),
        "rejected": counts["reject"],
        "edited": counts["edit"],
        "signed": [d.id for d in plan.every if not d.coupled_from],
        "cascades": [{"id": d.id, "decision": d.decision, "coupled_from": d.coupled_from}
                     for d in plan.every if d.coupled_from],
        "head": {"seq": head[0], "hash": head[1]},
        "head_line": f"{ledger.format_head(ch['case_id'], head)} | {examiner} {fp}",
        "fingerprint": fp,
        "notes": plan.notes,
        "needs_decision": plan.held,
    }  # fmt: skip
    refs = (plan.bodies[0].get("prior_chains") or []) if plan.bodies else []
    result["references"] = [
        f"This approval references chain {r['chain_id']} (head seq {r['head_seq']} "
        f"sha256:{r['head_hash']})"
        for r in refs
    ]
    if out["todos"]:
        result["todo_note"] = (
            f"{out['todos']} TODO entries are still staged; `vhir approve --review` creates them."
        )
    if out["save_error"] is not None:
        return _error(
            "SAVE_FAILED",
            f"Signed decisions were recorded; case data was not saved ({out['save_error']}). "
            f"Commit the same reviews again for: {', '.join(d.id for d in plan.every)}",
            500,
            **result,
        )
    if out["delta_error"] is not None:
        result["warning"] = (
            f"The signed entries couldn't be removed from pending-reviews.json "
            f"({out['delta_error']}); remove them in the portal."
        )
    return JSONResponse(result)


# --- Staged entries: POST and DELETE ---------------------------------------------------


def _post_locked(case_dir: Path, posted: list[dict], poster: str) -> list[dict]:
    with ledger.case_lock(case_id_of(case_dir), timeout=LOCK_SECONDS):
        delta = _load_delta_locked(case_dir)
        delta["items"], dropped = merge_post(delta["items"], posted, poster)
        delta["modified_at"] = _now()
        decide._write_delta(_delta_path(case_dir), delta)
    return dropped


def _delete_locked(case_dir: Path, item_id: str, caller: str) -> int | None:
    with ledger.case_lock(case_id_of(case_dir), timeout=LOCK_SECONDS):
        delta = _load_delta_locked(case_dir)
        items = delta["items"]
        mine = [
            e for e in items if e.get("id") == item_id and e.get("staged_by") == caller
        ]
        if not mine:
            mine = [
                e for e in items if e.get("id") == item_id and not e.get("staged_by")
            ]
        if not mine:
            return None
        delta["items"] = [e for e in items if not any(e is m for m in mine)]
        delta["modified_at"] = _now()
        decide._write_delta(_delta_path(case_dir), delta)
        return len(delta["items"])


async def locked(fn, *args) -> tuple[object, JSONResponse | None]:
    """Run a locked writer in a worker thread; a busy lock is 503."""
    try:
        return await anyio.to_thread.run_sync(fn, *args), None
    except ledger.LedgerBusy as e:
        return None, _error("LEDGER_BUSY", str(e), 503)
    except ledger.LockDirMissing as e:
        return None, _error("LOCK_DIR_MISSING", str(e), 500)
    except OSError as e:
        logger.error("Failed to write the delta file: %s", e)
        return None, _error("WRITE_FAILED", "Write failed", 500)


def is_symlink(case_dir: Path) -> bool:
    return os.path.islink(_delta_path(case_dir))
