from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any

import httpx
import pytest


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("RUN_INTEGRATION_TESTS") != "1",
        reason="run with python scripts/run_all_tests.py",
    ),
]

GATEWAY_URL = "http://localhost:8080"


@pytest.fixture
def http() -> httpx.Client:
    with httpx.Client(timeout=3, trust_env=False, follow_redirects=False) as client:
        yield client


def safe_api_key() -> str:
    value = os.getenv("SAFE_API_TOOL_API_KEY")
    assert value, "SAFE_API_TOOL_API_KEY was not provided by the integration runner"
    return value


def compose(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *arguments],
        check=True,
        capture_output=True,
        text=True,
    )


def audit_event(request_id: str) -> tuple[dict[str, Any], str]:
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
                return record, output
        time.sleep(0.1)
    pytest.fail(f"No authorization audit event found for {request_id}")


def test_valid_api_key_calls_exact_get_route_through_gateway(
    http: httpx.Client,
) -> None:
    request_id = "safe-api-integration-get"
    response = http.get(
        f"{GATEWAY_URL}/api/test/status",
        headers={"x-api-key": safe_api_key(), "x-request-id": request_id},
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "stateless": True,
        "max_input_characters": 4096,
        "max_preview_characters": 256,
    }
    assert response.headers["x-request-id"] == request_id
    assert "x-envoy-auth-headers-to-remove" not in response.headers


def test_valid_api_key_calls_exact_post_route_through_gateway(
    http: httpx.Client,
) -> None:
    request_id = "safe-api-integration-post"
    response = http.post(
        f"{GATEWAY_URL}/api/test/validate",
        headers={"x-api-key": safe_api_key(), "x-request-id": request_id},
        json={"value": "benign-special-characters-[]{}"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "accepted": True,
        "received_length": 30,
        "preview": "benign-special-characters-[]{}",
        "truncated": False,
    }
    assert response.headers["x-request-id"] == request_id


def test_oversized_post_is_rejected_before_authorization_and_app(
    http: httpx.Client,
) -> None:
    request_id = "safe-api-integration-oversized-body"
    # The application accepts 4,096 value characters, but the complete JSON
    # request exceeds the gateway's 4,096-byte policy. A 413 therefore proves
    # the gateway rejected it instead of relying on application validation.
    response = http.post(
        f"{GATEWAY_URL}/api/test/validate",
        headers={"x-api-key": safe_api_key(), "x-request-id": request_id},
        json={"value": "A" * 4096},
    )

    assert response.status_code == 413
    assert request_id not in compose("logs", "--no-color", "authz-service").stdout


@pytest.mark.parametrize(
    ("key", "reason"),
    [(None, "missing_api_key"), ("incorrect-api-key", "invalid_api_key")],
)
def test_missing_or_wrong_api_key_is_denied_at_gateway(
    http: httpx.Client,
    key: str | None,
    reason: str,
) -> None:
    headers = {"x-request-id": f"safe-api-integration-{reason}"}
    if key is not None:
        headers["x-api-key"] = key

    response = http.get(f"{GATEWAY_URL}/api/test/status", headers=headers)

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized", "reason": reason}


def test_api_key_cannot_authorize_admin_or_unlisted_test_route(
    http: httpx.Client,
) -> None:
    headers = {"x-api-key": safe_api_key()}

    admin = http.get(f"{GATEWAY_URL}/api/admin", headers=headers)
    unlisted = http.get(f"{GATEWAY_URL}/api/test/unlisted", headers=headers)

    assert admin.status_code == 401
    assert admin.json()["reason"] == "missing_token"
    assert "Administrative demonstration endpoint" not in admin.text
    assert unlisted.status_code == 403
    assert unlisted.json()["reason"] == "route_not_allowed"


def test_safe_api_audit_receipt_identifies_tool_without_secret(
    http: httpx.Client,
) -> None:
    request_id = "safe-api-integration-audit"
    key = safe_api_key()

    response = http.get(
        f"{GATEWAY_URL}/api/test/status",
        headers={"x-api-key": key, "x-request-id": request_id},
    )
    assert response.status_code == 200

    record, logs = audit_event(request_id)
    assert record == {
        "request_id": request_id,
        "agent_id": "safe-api-tool",
        "method": "GET",
        "path": "/api/test/status",
        "decision": "allow",
        "reason": "api_key_valid",
    }
    assert key not in logs


def test_safe_api_rate_limit_returns_typed_429(http: httpx.Client) -> None:
    headers = {"x-api-key": safe_api_key()}
    rate_limited: httpx.Response | None = None

    try:
        # Earlier cases may already have consumed part of this exact route bucket.
        for _ in range(13):
            response = http.get(f"{GATEWAY_URL}/api/test/status", headers=headers)
            if response.status_code == 429:
                rate_limited = response
                break
    finally:
        # Do not leak limiter state into integration files collected after this one.
        compose("restart", "authz-service")
        compose("up", "--detach", "--wait", "authz-service")

    assert rate_limited is not None
    assert rate_limited.json() == {
        "error": "rate_limited",
        "reason": "rate_limit_exceeded",
    }
    assert rate_limited.headers["retry-after"].isdigit()
    assert rate_limited.headers["x-ratelimit-limit"] == "12"
    assert rate_limited.headers["x-ratelimit-remaining"] == "0"
