import json

from fastapi.testclient import TestClient
import pytest

from authz_service import main
from authz_service.security import (
    AgentPrincipal,
    AuthenticationError,
    AuthorizationUnavailable,
)


client = TestClient(main.app)


class FakeValidator:
    def __init__(
        self,
        result: AgentPrincipal | AuthenticationError | AuthorizationUnavailable,
    ) -> None:
        self.result = result

    def validate_authorization_header(self, header: str | None) -> AgentPrincipal:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def use_validator(
    monkeypatch: pytest.MonkeyPatch,
    result: AgentPrincipal | AuthenticationError | AuthorizationUnavailable,
) -> None:
    monkeypatch.setattr(main, "validator", FakeValidator(result))


def test_health_is_public() -> None:
    response = client.get("/health", headers={"x-request-id": "health-request"})

    assert response.status_code == 200


def test_missing_token_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    use_validator(monkeypatch, AuthenticationError("missing_token"))

    response = client.get("/api/users", headers={"x-request-id": "request-1"})

    assert response.status_code == 401
    assert response.json()["reason"] == "missing_token"
    assert "resource_metadata=" in response.headers["www-authenticate"]
    assert 'scope="users:read"' in response.headers["www-authenticate"]


def test_reader_can_read_users(monkeypatch: pytest.MonkeyPatch) -> None:
    use_validator(
        monkeypatch,
        AgentPrincipal("agent-reader", frozenset({"users:read"})),
    )

    response = client.get(
        "/api/users",
        headers={"Authorization": "Bearer test-token", "x-request-id": "request-2"},
    )

    assert response.status_code == 200
    assert response.headers["x-agent-id"] == "agent-reader"


def test_reader_cannot_read_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    use_validator(
        monkeypatch,
        AgentPrincipal("agent-reader", frozenset({"users:read"})),
    )

    response = client.get(
        "/api/admin",
        headers={"Authorization": "Bearer test-token", "x-request-id": "request-3"},
    )

    assert response.status_code == 403
    assert response.json()["reason"] == "insufficient_scope"
    assert 'scope="admin:read"' in response.headers["www-authenticate"]


def test_admin_can_read_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    use_validator(
        monkeypatch,
        AgentPrincipal(
            "agent-admin",
            frozenset({"users:read", "admin:read"}),
        ),
    )

    response = client.get(
        "/api/admin",
        headers={"Authorization": "Bearer test-token", "x-request-id": "request-4"},
    )

    assert response.status_code == 200
    assert response.headers["x-agent-id"] == "agent-admin"


def test_unlisted_route_is_denied_by_default() -> None:
    response = client.get("/api/unlisted", headers={"x-request-id": "request-5"})

    assert response.status_code == 403
    assert response.json()["reason"] == "route_not_allowed"


def test_jwks_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    use_validator(monkeypatch, AuthorizationUnavailable("jwks_unavailable"))

    response = client.get(
        "/api/users",
        headers={"Authorization": "Bearer test-token", "x-request-id": "request-6"},
    )

    assert response.status_code == 503
    assert response.json()["reason"] == "jwks_unavailable"


def test_audit_log_is_json_and_omits_token(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    use_validator(
        monkeypatch,
        AgentPrincipal("agent-reader", frozenset({"users:read"})),
    )
    secret_token = "highly-sensitive-access-token"

    client.get(
        "/api/users",
        headers={
            "Authorization": f"Bearer {secret_token}",
            "x-request-id": "audit-request",
        },
    )

    output = capsys.readouterr().out.strip()
    record = json.loads(output)
    assert record == {
        "request_id": "audit-request",
        "agent_id": "agent-reader",
        "method": "GET",
        "path": "/api/users",
        "decision": "allow",
        "reason": "required_scope_present",
    }
    assert secret_token not in output
