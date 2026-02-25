"""Tests for auth middleware and analyst identity resolution."""

from sift_gateway.auth import AuthMiddleware, resolve_examiner
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient


def _make_app(api_keys: dict | None = None) -> Starlette:
    """Build a minimal Starlette app with auth middleware for testing."""

    async def protected_endpoint(request: Request):
        identity = resolve_examiner(request)
        return JSONResponse(
            {"examiner": identity["examiner"], "role": identity["role"]}
        )

    async def health_endpoint(request: Request):
        return JSONResponse({"status": "ok"})

    app = Starlette(
        routes=[
            Route("/api/test", protected_endpoint, methods=["GET"]),
            Route("/health", health_endpoint, methods=["GET"]),
        ]
    )
    app.add_middleware(AuthMiddleware, api_keys=api_keys)
    return app


class TestAuthMiddleware:
    def test_valid_key(self):
        api_keys = {"good_key": {"examiner": "alice", "role": "lead"}}
        app = _make_app(api_keys)
        client = TestClient(app)
        resp = client.get("/api/test", headers={"Authorization": "Bearer good_key"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["examiner"] == "alice"
        assert data["role"] == "lead"

    def test_valid_key_legacy_analyst(self):
        """Backward-compat: 'analyst' key in config maps to examiner."""
        api_keys = {"good_key": {"analyst": "alice", "role": "lead"}}
        app = _make_app(api_keys)
        client = TestClient(app)
        resp = client.get("/api/test", headers={"Authorization": "Bearer good_key"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["examiner"] == "alice"
        assert data["role"] == "lead"

    def test_invalid_key_returns_403(self):
        api_keys = {"good_key": {"examiner": "alice", "role": "lead"}}
        app = _make_app(api_keys)
        client = TestClient(app)
        resp = client.get("/api/test", headers={"Authorization": "Bearer bad_key"})
        assert resp.status_code == 403
        assert "Invalid API key" in resp.json()["error"]

    def test_missing_auth_header_returns_401(self):
        api_keys = {"good_key": {"examiner": "alice", "role": "lead"}}
        app = _make_app(api_keys)
        client = TestClient(app)
        resp = client.get("/api/test")
        assert resp.status_code == 401

    def test_no_api_keys_disables_auth(self):
        app = _make_app(api_keys={})
        client = TestClient(app)
        resp = client.get("/api/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["examiner"] == "anonymous"
        assert data["role"] == "examiner"

    def test_none_api_keys_disables_auth(self):
        app = _make_app(api_keys=None)
        client = TestClient(app)
        resp = client.get("/api/test")
        assert resp.status_code == 200
        assert resp.json()["examiner"] == "anonymous"

    def test_health_exempt_from_auth(self):
        api_keys = {"secret": {"examiner": "admin", "role": "lead"}}
        app = _make_app(api_keys)
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_bearer_case_insensitive(self):
        api_keys = {"my_key": {"examiner": "bob", "role": "examiner"}}
        app = _make_app(api_keys)
        client = TestClient(app)
        resp = client.get("/api/test", headers={"Authorization": "bearer my_key"})
        assert resp.status_code == 200
        assert resp.json()["examiner"] == "bob"
