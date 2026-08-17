from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any

import httpx
import jwt
import pytest


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("RUN_INTEGRATION_TESTS") != "1",
        reason="run with python scripts/run_all_tests.py",
    ),
]

GATEWAY_URL = "http://localhost:8080"
TOKEN_URL = "http://localhost:8081/realms/staging/protocol/openid-connect/token"
EXPECTED_USERS = [
    {"id": 1, "name": "Ada", "role": "student"},
    {"id": 2, "name": "Grace", "role": "instructor"},
]


@pytest.fixture
def http() -> httpx.Client:
    with httpx.Client(timeout=3, trust_env=False) as client:
        yield client


def secret(name: str) -> str:
    value = os.getenv(name)
    assert value, f"{name} was not provided by the integration test runner"
    return value


def obtain_token(http: httpx.Client, client_id: str, secret_name: str) -> str:
    response = http.post(
        TOKEN_URL,
        auth=(client_id, secret(secret_name)),
        data={"grant_type": "client_credentials"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"].lower() == "bearer"
    assert isinstance(body["expires_in"], int) and body["expires_in"] > 0
    assert isinstance(body["access_token"], str)
    return body["access_token"]


def call_gateway(
    http: httpx.Client,
    path: str,
    request_id: str,
    token: str | None = None,
) -> httpx.Response:
    headers = {"x-request-id": request_id}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = http.get(f"{GATEWAY_URL}{path}", headers=headers)
    assert response.headers["x-request-id"] == request_id
    return response


def compose(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *arguments],
        check=check,
        capture_output=True,
        text=True,
    )


def audit_event(request_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        output = compose("logs", "--no-color", "authz-service").stdout
        for line in reversed(output.splitlines()):
            json_start = line.find("{")
            if json_start == -1:
                continue
            try:
                record = json.loads(line[json_start:])
            except json.JSONDecodeError:
                continue
            if record.get("request_id") == request_id:
                return record
        time.sleep(0.1)
    pytest.fail(f"No authorization audit event found for {request_id}")


def assert_audit(
    request_id: str,
    *,
    agent_id: str,
    path: str,
    decision: str,
    reason: str,
) -> None:
    assert audit_event(request_id) == {
        "request_id": request_id,
        "agent_id": agent_id,
        "method": "GET",
        "path": path,
        "decision": decision,
        "reason": reason,
    }


def test_no_token_to_users_returns_401(http: httpx.Client) -> None:
    request_id = "integration-no-token"
    response = call_gateway(http, "/api/users", request_id)

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized", "reason": "missing_token"}
    assert 'scope="users:read"' in response.headers["www-authenticate"]
    assert_audit(
        request_id,
        agent_id="unknown",
        path="/api/users",
        decision="deny",
        reason="missing_token",
    )


def test_malformed_token_returns_401(http: httpx.Client) -> None:
    request_id = "integration-malformed-token"
    response = call_gateway(http, "/api/users", request_id, "not-a-jwt")

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized", "reason": "invalid_token"}
    assert 'error="invalid_token"' in response.headers["www-authenticate"]
    assert_audit(
        request_id,
        agent_id="unknown",
        path="/api/users",
        decision="deny",
        reason="invalid_token",
    )


def test_expired_keycloak_token_returns_401(http: httpx.Client) -> None:
    token = obtain_token(
        http,
        "integration-expired-token",
        "INTEGRATION_EXPIRED_CLIENT_SECRET",
    )
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["aud"] == "staging-api"
    assert claims["exp"] - claims["iat"] == 2

    while time.time() <= claims["exp"]:
        time.sleep(0.05)

    request_id = "integration-expired-token"
    response = call_gateway(http, "/api/users", request_id, token)

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized", "reason": "expired_token"}
    assert_audit(
        request_id,
        agent_id="unknown",
        path="/api/users",
        decision="deny",
        reason="expired_token",
    )


def test_wrong_audience_keycloak_token_returns_401(http: httpx.Client) -> None:
    token = obtain_token(
        http,
        "integration-wrong-audience",
        "INTEGRATION_WRONG_AUDIENCE_CLIENT_SECRET",
    )
    claims = jwt.decode(token, options={"verify_signature": False})
    audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    assert "not-staging-api" in audiences
    assert "staging-api" not in audiences

    request_id = "integration-wrong-audience"
    response = call_gateway(http, "/api/users", request_id, token)

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized", "reason": "wrong_audience"}
    assert_audit(
        request_id,
        agent_id="unknown",
        path="/api/users",
        decision="deny",
        reason="wrong_audience",
    )


def test_reader_can_read_users(http: httpx.Client) -> None:
    token = obtain_token(http, "agent-reader", "AGENT_READER_CLIENT_SECRET")
    request_id = "integration-reader-users"
    response = call_gateway(http, "/api/users", request_id, token)

    assert response.status_code == 200
    assert response.json() == EXPECTED_USERS
    assert_audit(
        request_id,
        agent_id="agent-reader",
        path="/api/users",
        decision="allow",
        reason="required_scope_present",
    )


def test_reader_cannot_read_admin(http: httpx.Client) -> None:
    token = obtain_token(http, "agent-reader", "AGENT_READER_CLIENT_SECRET")
    request_id = "integration-reader-admin"
    response = call_gateway(http, "/api/admin", request_id, token)

    assert response.status_code == 403
    assert response.json() == {"error": "forbidden", "reason": "insufficient_scope"}
    assert 'scope="admin:read"' in response.headers["www-authenticate"]
    assert_audit(
        request_id,
        agent_id="agent-reader",
        path="/api/admin",
        decision="deny",
        reason="insufficient_scope",
    )


def test_admin_can_read_admin(http: httpx.Client) -> None:
    token = obtain_token(http, "agent-admin", "AGENT_ADMIN_CLIENT_SECRET")
    request_id = "integration-admin-admin"
    response = call_gateway(http, "/api/admin", request_id, token)

    assert response.status_code == 200
    assert response.json() == {
        "message": "Administrative demonstration endpoint",
        "authorization_boundary": "envoy_ext_authz",
        "required_scope": "admin:read",
    }
    assert_audit(
        request_id,
        agent_id="agent-admin",
        path="/api/admin",
        decision="allow",
        reason="required_scope_present",
    )


def test_unknown_protected_route_is_denied(http: httpx.Client) -> None:
    token = obtain_token(http, "agent-admin", "AGENT_ADMIN_CLIENT_SECRET")
    request_id = "integration-unknown-route"
    response = call_gateway(http, "/api/unknown", request_id, token)

    assert response.status_code == 403
    assert response.json() == {"error": "forbidden", "reason": "route_not_allowed"}
    assert_audit(
        request_id,
        agent_id="unknown",
        path="/api/unknown",
        decision="deny",
        reason="route_not_allowed",
    )


def test_direct_backend_access_from_host_is_unavailable(http: httpx.Client) -> None:
    try:
        response = http.get("http://localhost:8000/health")
    except httpx.RequestError:
        return
    pytest.fail(f"Backend host port unexpectedly returned HTTP {response.status_code}")


def test_authorization_service_failure_denies_request(http: httpx.Client) -> None:
    token = obtain_token(http, "agent-admin", "AGENT_ADMIN_CLIENT_SECRET")
    request_id = "integration-authz-unavailable"
    compose("stop", "authz-service")
    try:
        response = call_gateway(http, "/api/admin", request_id, token)
        assert response.status_code == 503
        assert "Administrative demonstration endpoint" not in response.text
    finally:
        compose("up", "--detach", "--wait", "authz-service")

    output = compose("logs", "--no-color", "authz-service").stdout
    assert request_id not in output
