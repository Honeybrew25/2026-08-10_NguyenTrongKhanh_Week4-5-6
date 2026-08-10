import json

from fastapi.testclient import TestClient
import pytest

from authz_service import main
from authz_service.policy import SafeApiKeyPolicy, SafeApiPolicy
from authz_service.security import (
    AgentPrincipal,
    ApiKeyConfigurationError,
    ApiKeyValidator,
    AuthenticationError,
    AuthorizationUnavailable,
    FixedWindowRateLimiter,
)


client = TestClient(main.app)
SAFE_API_KEY = "safe-api-unit-test-key-0000000000000001"


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


def use_safe_api_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    requests_per_minute: int = 2,
    clock: object | None = None,
) -> None:
    policy = SafeApiPolicy(
        api_key=SafeApiKeyPolicy(
            header_name="x-api-key",
            environment_variable="SAFE_API_TOOL_API_KEY",
            principal_id="safe-api-tool",
        ),
        requests_per_minute=requests_per_minute,
        routes=frozenset(
            {
                ("GET", "/api/test/status"),
                ("POST", "/api/test/validate"),
            }
        ),
    )
    key_validator = ApiKeyValidator(SAFE_API_KEY, principal="safe-api-tool")
    limiter_arguments = {}
    if clock is not None:
        limiter_arguments["clock"] = clock
    limiter = FixedWindowRateLimiter(requests_per_minute, **limiter_arguments)
    monkeypatch.setattr(main, "safe_api_policy", policy)
    monkeypatch.setattr(main, "safe_api_key_validator", key_validator)
    monkeypatch.setattr(main, "safe_api_rate_limiter", limiter)
    monkeypatch.setattr(main, "safe_api_configuration_error", None)


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


def test_safe_api_key_allows_only_exact_policy_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_safe_api_runtime(monkeypatch)

    response = client.get(
        "/api/test/status",
        headers={
            "x-api-key": SAFE_API_KEY,
            "x-request-id": "safe-api-allowed",
        },
    )

    assert response.status_code == 200
    assert response.headers["x-agent-id"] == "safe-api-tool"
    assert response.headers["x-envoy-auth-headers-to-remove"] == "x-api-key"


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ({}, "missing_api_key"),
        ({"x-api-key": "incorrect-key"}, "invalid_api_key"),
    ],
)
def test_safe_api_missing_or_wrong_key_is_denied(
    monkeypatch: pytest.MonkeyPatch,
    headers: dict[str, str],
    reason: str,
) -> None:
    use_safe_api_runtime(monkeypatch)

    response = client.get("/api/test/status", headers=headers)

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized", "reason": reason}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/test/status"),
        ("GET", "/api/test/validate"),
        ("GET", "/api/test/unlisted"),
    ],
)
def test_safe_api_method_and_path_are_deny_by_default(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
) -> None:
    use_safe_api_runtime(monkeypatch)

    response = client.request(
        method,
        path,
        headers={"x-api-key": SAFE_API_KEY},
    )

    assert response.status_code == 403
    assert response.json()["reason"] == "route_not_allowed"


def test_safe_api_query_is_not_an_exact_allowlisted_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_safe_api_runtime(monkeypatch)

    response = client.get(
        "/api/test/status?redirect=https://example.invalid",
        headers={"x-api-key": SAFE_API_KEY},
    )

    assert response.status_code == 403
    assert response.json()["reason"] == "non_canonical_route"


def test_safe_api_rate_limit_is_per_method_and_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_safe_api_runtime(monkeypatch, requests_per_minute=1)
    headers = {"x-api-key": SAFE_API_KEY}

    first_get = client.get("/api/test/status", headers=headers)
    second_get = client.get("/api/test/status", headers=headers)
    first_post = client.post("/api/test/validate", headers=headers)

    assert first_get.status_code == 200
    assert second_get.status_code == 429
    assert second_get.json() == {
        "error": "rate_limited",
        "reason": "rate_limit_exceeded",
    }
    assert second_get.headers["retry-after"].isdigit()
    assert second_get.headers["x-ratelimit-limit"] == "1"
    assert second_get.headers["x-ratelimit-remaining"] == "0"
    assert first_post.status_code == 200


def test_safe_api_rate_limit_resets_deterministically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [59.0]
    use_safe_api_runtime(
        monkeypatch,
        requests_per_minute=1,
        clock=lambda: now[0],
    )
    headers = {"x-api-key": SAFE_API_KEY}

    assert client.get("/api/test/status", headers=headers).status_code == 200
    assert client.get("/api/test/status", headers=headers).status_code == 429
    now[0] = 60.0
    assert client.get("/api/test/status", headers=headers).status_code == 200


def test_safe_api_configuration_failure_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main, "safe_api_policy", None)
    monkeypatch.setattr(main, "safe_api_key_validator", None)
    monkeypatch.setattr(main, "safe_api_rate_limiter", None)
    monkeypatch.setattr(main, "safe_api_configuration_error", "policy_unreadable")

    response = client.get(
        "/api/test/status",
        headers={"x-api-key": SAFE_API_KEY},
    )

    assert response.status_code == 503
    assert response.json() == {
        "error": "authorization_unavailable",
        "reason": "safe_api_configuration_unavailable",
    }


def test_safe_api_audit_omits_key(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    use_safe_api_runtime(monkeypatch)

    client.get(
        "/api/test/status",
        headers={
            "x-api-key": SAFE_API_KEY,
            "x-request-id": "safe-api-audit",
        },
    )

    output = capsys.readouterr().out.strip()
    assert json.loads(output) == {
        "request_id": "safe-api-audit",
        "agent_id": "safe-api-tool",
        "method": "GET",
        "path": "/api/test/status",
        "decision": "allow",
        "reason": "api_key_valid",
    }
    assert SAFE_API_KEY not in output


@pytest.mark.parametrize(
    "key",
    [
        None,
        "short",
        " x" * 20,
        "x" * 513,
        "replace-with-long-random-safe-api-tool-key",
    ],
)
def test_malformed_configured_api_key_is_rejected(key: str | None) -> None:
    with pytest.raises(ApiKeyConfigurationError):
        ApiKeyValidator(key, principal="safe-api-tool")
