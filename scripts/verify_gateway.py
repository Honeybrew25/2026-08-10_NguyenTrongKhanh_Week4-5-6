from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


GATEWAY_URL = "http://localhost:8080"
BACKEND_URL = "http://localhost:8000"
TOKEN_URL = "http://localhost:8081/realms/staging/protocol/openid-connect/token"
REQUEST_TIMEOUT_SECONDS = 3
STARTUP_TIMEOUT_SECONDS = 90


def load_local_secrets() -> dict[str, str]:
    values: dict[str, str] = {}
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            values[key.strip()] = value.strip().strip("\"'")
    for key in ("AGENT_READER_CLIENT_SECRET", "AGENT_ADMIN_CLIENT_SECRET"):
        if os.getenv(key):
            values[key] = os.environ[key]
    return values


def send(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, Any, str | None]:
    request = Request(
        url,
        data=body,
        headers=headers or {},
        method="POST" if body is not None else "GET",
    )
    try:
        response = urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS)
    except HTTPError as error:
        response = error

    with response:
        raw_body = response.read().decode("utf-8")
        try:
            parsed_body: Any = json.loads(raw_body)
        except json.JSONDecodeError:
            parsed_body = raw_body
        return response.status, parsed_body, response.headers.get("x-request-id")


def wait_for_services() -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            gateway_status, _, _ = send(f"{GATEWAY_URL}/health")
            keycloak_status, _, _ = send(
                "http://localhost:8081/realms/staging/.well-known/openid-configuration"
            )
            if gateway_status == 200 and keycloak_status == 200:
                return
        except (OSError, URLError):
            pass
        time.sleep(1)
    raise RuntimeError("IAM services did not become ready within 90 seconds")


def get_token(client_id: str, client_secret: str) -> str:
    credentials = base64.b64encode(
        f"{client_id}:{client_secret}".encode("utf-8")
    ).decode("ascii")
    status, body, _ = send(
        TOKEN_URL,
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body=urlencode({"grant_type": "client_credentials"}).encode("ascii"),
    )
    assert status == 200, f"Token request for {client_id} failed with HTTP {status}"
    assert isinstance(body, dict) and isinstance(body.get("access_token"), str)
    return body["access_token"]


def gateway_get(path: str, token: str | None = None) -> tuple[int, Any, str | None]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return send(f"{GATEWAY_URL}{path}", headers=headers)


def verify_public_routes() -> None:
    status, body, request_id = gateway_get("/health")
    assert status == 200
    assert body == {"status": "ok"}
    assert request_id

    status, metadata, _ = gateway_get("/.well-known/oauth-protected-resource")
    assert status == 200
    assert metadata["resource"] == GATEWAY_URL


def verify_agent_policies(reader_token: str, admin_token: str) -> None:
    status, _, _ = gateway_get("/api/users")
    assert status == 401

    status, users, _ = gateway_get("/api/users", reader_token)
    assert status == 200
    assert len(users) == 2

    status, _, _ = gateway_get("/api/admin", reader_token)
    assert status == 403

    status, _, _ = gateway_get("/api/users", admin_token)
    assert status == 200

    status, _, _ = gateway_get("/api/admin", admin_token)
    assert status == 200

    status, _, _ = gateway_get("/api/unlisted", admin_token)
    assert status == 403


def verify_backend_is_private() -> None:
    try:
        status, _, _ = send(f"{BACKEND_URL}/health")
    except (OSError, URLError):
        return
    raise AssertionError(
        f"FastAPI is directly reachable from the host and returned HTTP {status}"
    )


def main() -> None:
    secrets = load_local_secrets()
    reader_secret = secrets.get("AGENT_READER_CLIENT_SECRET", "")
    admin_secret = secrets.get("AGENT_ADMIN_CLIENT_SECRET", "")
    if (
        not reader_secret
        or not admin_secret
        or reader_secret.startswith("replace-with-")
        or admin_secret.startswith("replace-with-")
    ):
        raise RuntimeError("Set non-placeholder Agent secrets in .env before verifying")

    wait_for_services()
    reader_token = get_token("agent-reader", reader_secret)
    admin_token = get_token("agent-admin", admin_secret)
    verify_public_routes()
    verify_agent_policies(reader_token, admin_token)
    verify_backend_is_private()

    print("PASS: public routes are reachable through Envoy")
    print("PASS: missing tokens return 401")
    print("PASS: reader and admin scope policies are enforced")
    print("PASS: unlisted routes are denied by default")
    print("PASS: FastAPI is not reachable directly from the host")


if __name__ == "__main__":
    main()
