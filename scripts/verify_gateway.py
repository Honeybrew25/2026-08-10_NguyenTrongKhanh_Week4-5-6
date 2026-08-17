from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from safe_api_tool.approval import InteractiveApprovalProvider
from safe_api_tool.audit import AuditLogWriter
from safe_api_tool.client import SafeApiClient
from safe_api_tool.models import RequestProposal
from safe_api_tool.planner import DeterministicSafeRequestPlanner
from safe_api_tool.policy import PolicyEngine


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
    for key in (
        "AGENT_READER_CLIENT_SECRET",
        "AGENT_ADMIN_CLIENT_SECRET",
        "SAFE_API_TOOL_API_KEY",
    ):
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


def verify_safe_api_tool(api_key: str) -> None:
    proposal = RequestProposal(
        endpoint_id="input-validation",
        test_case_id="special-characters",
        rationale="Manual Gateway verification with a curated safe profile.",
        source_finding_ids=["manual-gateway-check"],
        requested_headers={"x-test-purpose": "manual-verification"},
    )
    forbidden = RequestProposal(
        endpoint_id="admin",
        test_case_id="empty",
        rationale="Negative control.",
        source_finding_ids=[],
        requested_headers={},
    )
    with tempfile.TemporaryDirectory(prefix="safe-api-verification-") as directory:
        audit_path = Path(directory) / "receipts.jsonl"
        with SafeApiClient(
            PolicyEngine.from_files(),
            api_key=api_key,
            audit_writer=AuditLogWriter(audit_path),
            approval_provider=InteractiveApprovalProvider(),
        ) as client:
            status = client.execute(
                DeterministicSafeRequestPlanner().status_proposal()
            )
            validation = client.execute(proposal)
            denied = client.execute(forbidden)

        assert status.status_code == 200
        assert validation.status_code == 200
        assert denied.outcome == "policy_denied"
        assert api_key not in audit_path.read_text(encoding="utf-8")


def main() -> None:
    secrets = load_local_secrets()
    reader_secret = secrets.get("AGENT_READER_CLIENT_SECRET", "")
    admin_secret = secrets.get("AGENT_ADMIN_CLIENT_SECRET", "")
    safe_api_key = secrets.get("SAFE_API_TOOL_API_KEY", "")
    if (
        not reader_secret
        or not admin_secret
        or not safe_api_key
        or reader_secret.startswith("replace-with-")
        or admin_secret.startswith("replace-with-")
        or safe_api_key.startswith("replace-with-")
    ):
        raise RuntimeError(
            "Set non-placeholder Agent and Safe API secrets in .env before verifying"
        )

    wait_for_services()
    reader_token = get_token("agent-reader", reader_secret)
    admin_token = get_token("agent-admin", admin_secret)
    verify_public_routes()
    verify_agent_policies(reader_token, admin_token)
    verify_safe_api_tool(safe_api_key)
    verify_backend_is_private()

    print("PASS: public routes are reachable through Envoy")
    print("PASS: missing tokens return 401")
    print("PASS: reader and admin scope policies are enforced")
    print("PASS: unlisted routes are denied by default")
    print("PASS: Safe API Tool GET/POST execute through Envoy")
    print("PASS: forbidden Safe API capability is denied before network")
    print("PASS: Safe API receipts omit the API key")
    print("PASS: FastAPI is not reachable directly from the host")


if __name__ == "__main__":
    main()
