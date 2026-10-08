"""A portal on a scratch case, with vhir's credential and ledger folders
redirected, and a stand-in for the browser's signing steps."""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json
from pathlib import Path

import pytest

vhir = pytest.importorskip("vhir_cli.ledger")

from starlette.applications import Starlette  # noqa: E402
from starlette.middleware import Middleware  # noqa: E402
from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402
from starlette.routing import Mount  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402
from vhir_cli import approval_auth, keys, ledger, verification  # noqa: E402

NOW0 = "2026-10-03T07:00:00+00:00"
PASSWORD = "correct horse battery staple"


class _AsExaminer(BaseHTTPMiddleware):
    """What the gateway's auth middleware does: the token names the examiner."""

    async def dispatch(self, request, call_next):
        request.state.examiner = request.headers.get("x-examiner", "anonymous")
        return await call_next(request)


@pytest.fixture
def box(tmp_path, monkeypatch):
    """vhir's /var/lib/vhir folders and the lockout file, in tmp_path."""
    root = tmp_path / "var-lib-vhir"
    for name in ("keys", "ledger", "passwords", "verification"):
        (root / name).mkdir(parents=True)
    monkeypatch.setattr(keys, "KEYS_DIR", root / "keys")
    monkeypatch.setattr(ledger, "LEDGER_DIR", root / "ledger")
    monkeypatch.setattr(approval_auth, "_PASSWORDS_DIR", root / "passwords")
    monkeypatch.setattr(verification, "VERIFICATION_DIR", root / "verification")
    monkeypatch.setattr(approval_auth, "_LOCKOUT_FILE", tmp_path / "lockout.json")
    from case_dashboard import routes, signing

    monkeypatch.setattr(signing, "_challenges", {})
    monkeypatch.setattr(routes, "_view_cache", {"key": None, "value": None})
    return root


def enrol(name: str, password: str = PASSWORD) -> dict:
    data = keys.new_credential(name, password)
    keys.save(name, data)
    return data


def finding(fid: str, **extra) -> dict:
    f = {
        "id": fid,
        "type": "finding",
        "title": f"title {fid}",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "MEDIUM",
        "status": "DRAFT",
        "examiner": "steve",
        "created_by": "steve",
        "staged": NOW0,
        "modified_at": NOW0,
        "audit_ids": ["x-1"],
    }
    f.update(extra)
    return f


def event(tid: str, src: str, **extra) -> dict:
    t = {
        "id": tid,
        "timestamp": NOW0,
        "description": f"ev {tid}",
        "event_type": "other",
        "related_findings": [src],
        "auto_created_from": src,
        "status": "DRAFT",
        "staged": NOW0,
        "modified_at": NOW0,
        "created_by": "steve",
        "examiner": "steve",
        "audit_ids": ["x-1"],
    }
    t.update(extra)
    return t


class Portal:
    """A scratch case served by the portal, and the browser's signing steps."""

    def __init__(self, case_dir: Path):
        from case_dashboard.routes import create_dashboard_v2_app

        self.dir = case_dir
        app = Starlette(
            routes=[Mount("/", app=create_dashboard_v2_app())],
            middleware=[Middleware(_AsExaminer)],
        )
        self.client = TestClient(app)

    # --- files ---
    def write(self, name: str, data) -> None:
        path = self.dir / name
        if path.exists():
            path.chmod(0o644)  # case files are saved read-only
        path.write_text(json.dumps(data, indent=2))

    def read(self, name: str):
        path = self.dir / name
        return json.loads(path.read_text()) if path.exists() else None

    def item(self, item_id: str) -> dict:
        for name in ("findings.json", "timeline.json", "iocs.json"):
            for x in self.read(name) or []:
                if x.get("id") == item_id:
                    return x
        raise KeyError(item_id)

    def stage(self, *entries: dict) -> None:
        self.write("pending-reviews.json", {"case_id": "C-1", "items": list(entries)})

    def chain(self) -> list[dict]:
        path = ledger.chain_path("C-1")
        if not path.exists():
            return []
        return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]

    # --- requests ---
    def post(self, path: str, body, examiner: str = "steve"):
        return self.client.post(path, json=body, headers={"x-examiner": examiner})

    def get(self, path: str, examiner: str = "steve"):
        return self.client.get(path, headers={"x-examiner": examiner})

    def plan(self, entries, examiner="steve", include=(), retry_of=None):
        body = {"entries": entries, "include_others": list(include)}
        if retry_of:
            body["retry_of"] = retry_of
        return self.post("/api/commit/plan", body, examiner)

    def login(self, plan: dict, examiner="steve", password=PASSWORD):
        auth = _derive_auth(password, plan["salt_auth"])
        response = hmac.new(
            bytes.fromhex(auth), plan["nonce"].encode("ascii"), hashlib.sha256
        ).hexdigest()
        return self.post(
            "/api/commit/key",
            {"challenge_id": plan["challenge_id"], "response": response},
            examiner,
        )

    def sign(self, plan: dict, key: dict, examiner="steve", password=PASSWORD) -> dict:
        kek = _derive_kek(password, key["salt_ledger"])
        private = keys.unwrap(
            {
                "wrapped_private": key["wrapped_private"],
                "public_key": key["public_key"],
            },
            kek,
            examiner,
        )
        return {
            b["item_id"]: base64.b64encode(
                private.sign(b["body"].encode("ascii"))
            ).decode()
            for b in plan["bodies"]
        }

    def commit(self, plan: dict, sigs: dict, examiner="steve"):
        return self.post(
            "/api/commit",
            {"challenge_id": plan["challenge_id"], "sigs": sigs},
            examiner,
        )

    def sign_all(self, entries, examiner="steve", include=(), password=PASSWORD):
        """Plan, sign in, sign and commit, as the dialog does. Returns the
        commit response (or the first refusal)."""
        r = self.plan(entries, examiner, include)
        if r.status_code != 200:
            return r
        plan = r.json()
        k = self.login(plan, examiner, password)
        if k.status_code != 200:
            return k
        return self.commit(
            plan, self.sign(plan, k.json(), examiner, password), examiner
        )


@functools.cache
def _derive_auth(password: str, salt: str) -> str:
    return keys.derive_auth(password, salt)


@functools.cache
def _derive_kek(password: str, salt: str) -> bytes:
    return keys.derive_kek(password, salt)


@pytest.fixture
def portal(box, tmp_path, monkeypatch):
    d = tmp_path / "C-1"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: C-1\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return Portal(d)


def entry(item_id: str, action: str = "approve", **extra) -> dict:
    """A staged entry as the page posts it."""
    kind = "ioc" if item_id.startswith("IOC-") else (
        "timeline" if item_id.startswith("T-") else "finding")  # fmt: skip
    return {"id": item_id, "type": kind, "action": action, "modifications": {}, **extra}


def reviewed(portal: Portal, item_id: str, action: str = "approve", **extra) -> dict:
    """An entry recording the hash of the item as it is now."""
    from vhir_cli.case_io import compute_content_hash

    now = compute_content_hash(portal.item(item_id))
    return entry(item_id, action, content_hash_at_review=now, **extra)
