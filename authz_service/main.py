import json
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from authz_service.config import Settings
from authz_service.security import (
    AuthenticationError,
    AuthorizationUnavailable,
    TokenValidator,
)


settings = Settings.from_environment()
validator = TokenValidator(settings)

PUBLIC_ROUTES = {
    ("GET", "/health"),
    ("GET", "/.well-known/oauth-protected-resource"),
}
REQUIRED_SCOPES = {
    ("GET", "/api/users"): "users:read",
    ("GET", "/api/admin"): "admin:read",
}
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

app = FastAPI(title="Agent IAM Authorization Service", version="0.1.0")


def write_audit_log(
    *,
    request_id: str,
    agent_id: str,
    method: str,
    path: str,
    decision: Literal["allow", "deny", "error"],
    reason: str,
) -> None:
    record = {
        "request_id": request_id,
        "agent_id": agent_id,
        "method": method,
        "path": path,
        "decision": decision,
        "reason": reason,
    }
    print(json.dumps(record, separators=(",", ":")), flush=True)


def challenge(required_scope: str | None = None) -> str:
    metadata_url = (
        f"{settings.resource_url.rstrip('/')}/.well-known/oauth-protected-resource"
    )
    fields = [
        'Bearer realm="staging-api"',
        f'resource_metadata="{metadata_url}"',
    ]
    if required_scope:
        fields.append(f'scope="{required_scope}"')
    return ", ".join(fields)


def denial(status_code: int, reason: str, required_scope: str | None = None) -> Response:
    error = "unauthorized" if status_code == 401 else "forbidden"
    headers = {"WWW-Authenticate": challenge(required_scope)}
    if status_code == 403 and required_scope:
        headers["WWW-Authenticate"] += ', error="insufficient_scope"'
    elif status_code == 401:
        headers["WWW-Authenticate"] += ', error="invalid_token"'
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "reason": reason},
        headers=headers,
    )


@app.api_route("/{path:path}", methods=HTTP_METHODS)
async def authorize(request: Request, path: str) -> Response:
    method = request.method.upper()
    request_path = request.url.path
    request_id = request.headers.get("x-request-id", "missing")

    if (method, request_path) in PUBLIC_ROUTES:
        write_audit_log(
            request_id=request_id,
            agent_id="anonymous",
            method=method,
            path=request_path,
            decision="allow",
            reason="public_route",
        )
        return Response(status_code=200, headers={"x-agent-id": "anonymous"})

    required_scope = REQUIRED_SCOPES.get((method, request_path))
    if not required_scope:
        write_audit_log(
            request_id=request_id,
            agent_id="unknown",
            method=method,
            path=request_path,
            decision="deny",
            reason="route_not_allowed",
        )
        return denial(403, "route_not_allowed")

    try:
        principal = validator.validate_authorization_header(
            request.headers.get("authorization")
        )
    except AuthenticationError as error:
        write_audit_log(
            request_id=request_id,
            agent_id="unknown",
            method=method,
            path=request_path,
            decision="deny",
            reason=error.reason,
        )
        return denial(401, error.reason, required_scope)
    except AuthorizationUnavailable:
        write_audit_log(
            request_id=request_id,
            agent_id="unknown",
            method=method,
            path=request_path,
            decision="error",
            reason="jwks_unavailable",
        )
        return JSONResponse(
            status_code=503,
            content={
                "error": "authorization_unavailable",
                "reason": "jwks_unavailable",
            },
        )

    if required_scope not in principal.scopes:
        write_audit_log(
            request_id=request_id,
            agent_id=principal.agent_id,
            method=method,
            path=request_path,
            decision="deny",
            reason="insufficient_scope",
        )
        return denial(403, "insufficient_scope", required_scope)

    write_audit_log(
        request_id=request_id,
        agent_id=principal.agent_id,
        method=method,
        path=request_path,
        decision="allow",
        reason="required_scope_present",
    )
    return Response(status_code=200, headers={"x-agent-id": principal.agent_id})
