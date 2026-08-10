import json
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from authz_service.config import Settings
from authz_service.policy import (
    SAFE_API_KEY_HEADER,
    PolicyConfigurationError,
    SafeApiPolicy,
    load_safe_api_policy,
)
from authz_service.security import (
    ApiKeyAuthenticationError,
    ApiKeyConfigurationError,
    ApiKeyValidator,
    AuthenticationError,
    AuthorizationUnavailable,
    FixedWindowRateLimiter,
    TokenValidator,
)


settings = Settings.from_environment()
validator = TokenValidator(settings)


def load_safe_api_runtime() -> tuple[
    SafeApiPolicy | None,
    ApiKeyValidator | None,
    FixedWindowRateLimiter | None,
    str | None,
]:
    try:
        policy = load_safe_api_policy(settings.safe_api_policy_path)
        api_key_validator = ApiKeyValidator(
            settings.safe_api_tool_api_key,
            principal=policy.api_key.principal_id,
        )
    except (PolicyConfigurationError, ApiKeyConfigurationError) as error:
        return None, None, None, error.reason
    return (
        policy,
        api_key_validator,
        FixedWindowRateLimiter(policy.requests_per_minute),
        None,
    )


(
    safe_api_policy,
    safe_api_key_validator,
    safe_api_rate_limiter,
    safe_api_configuration_error,
) = load_safe_api_runtime()

PUBLIC_ROUTES = {
    ("GET", "/health"),
    ("GET", "/.well-known/oauth-protected-resource"),
}
PUBLIC_UI_METHODS = frozenset({"GET", "HEAD"})
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


def safe_api_denial(
    status_code: int,
    *,
    error: str,
    reason: str,
    headers: dict[str, str] | None = None,
) -> Response:
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "reason": reason},
        headers=headers,
    )


def allow(agent_id: str) -> Response:
    return Response(
        status_code=200,
        headers={
            "x-agent-id": agent_id,
            # HTTP ext_authz consumes this control header and removes the API
            # key before the original request is dispatched upstream.
            "x-envoy-auth-headers-to-remove": SAFE_API_KEY_HEADER,
        },
    )


def is_safe_api_surface(path: str) -> bool:
    return path.startswith("/api/test/")


def is_public_ui_surface(path: str) -> bool:
    return path in {"/", "/ui"} or path.startswith("/ui/")


def has_canonical_public_ui_target(request: Request) -> bool:
    raw_path = request.scope.get("raw_path")
    if not isinstance(raw_path, bytes):
        return False
    try:
        decoded_raw_path = raw_path.decode("ascii")
    except UnicodeDecodeError:
        return False
    return (
        decoded_raw_path == request.url.path
        and "%" not in decoded_raw_path
        and "\\" not in decoded_raw_path
        and "//" not in decoded_raw_path
        and not any(part in {".", ".."} for part in decoded_raw_path.split("/"))
    )


def has_canonical_safe_api_target(request: Request) -> bool:
    raw_path = request.scope.get("raw_path")
    if not isinstance(raw_path, bytes):
        return False
    try:
        decoded_raw_path = raw_path.decode("ascii")
    except UnicodeDecodeError:
        return False
    return (
        not request.url.query
        and decoded_raw_path == request.url.path
        and "%" not in decoded_raw_path
        and "\\" not in decoded_raw_path
        and "//" not in decoded_raw_path
    )


@app.api_route("/{path:path}", methods=HTTP_METHODS)
async def authorize(request: Request, path: str) -> Response:
    method = request.method.upper()
    request_path = request.url.path
    request_id = request.headers.get("x-request-id", "missing")

    if is_safe_api_surface(request_path):
        if (
            safe_api_configuration_error is not None
            or safe_api_policy is None
            or safe_api_key_validator is None
            or safe_api_rate_limiter is None
        ):
            write_audit_log(
                request_id=request_id,
                agent_id="unknown",
                method=method,
                path=request_path,
                decision="error",
                reason="safe_api_configuration_unavailable",
            )
            return safe_api_denial(
                503,
                error="authorization_unavailable",
                reason="safe_api_configuration_unavailable",
            )

        if not has_canonical_safe_api_target(request):
            write_audit_log(
                request_id=request_id,
                agent_id="unknown",
                method=method,
                path=request_path,
                decision="deny",
                reason="non_canonical_route",
            )
            return safe_api_denial(
                403,
                error="forbidden",
                reason="non_canonical_route",
            )

        if not safe_api_policy.allows(method, request_path):
            write_audit_log(
                request_id=request_id,
                agent_id="unknown",
                method=method,
                path=request_path,
                decision="deny",
                reason="route_not_allowed",
            )
            return safe_api_denial(
                403,
                error="forbidden",
                reason="route_not_allowed",
            )

        try:
            principal = safe_api_key_validator.validate(
                request.headers.get(safe_api_policy.api_key.header_name)
            )
        except ApiKeyAuthenticationError as error:
            write_audit_log(
                request_id=request_id,
                agent_id="unknown",
                method=method,
                path=request_path,
                decision="deny",
                reason=error.reason,
            )
            return safe_api_denial(
                401,
                error="unauthorized",
                reason=error.reason,
            )

        rate_limit = safe_api_rate_limiter.check(
            key_id=safe_api_key_validator.key_id,
            method=method,
            path=request_path,
        )
        if not rate_limit.allowed:
            write_audit_log(
                request_id=request_id,
                agent_id=principal.agent_id,
                method=method,
                path=request_path,
                decision="deny",
                reason="rate_limit_exceeded",
            )
            return safe_api_denial(
                429,
                error="rate_limited",
                reason="rate_limit_exceeded",
                headers={
                    "retry-after": str(rate_limit.retry_after_seconds),
                    "x-ratelimit-limit": str(rate_limit.limit),
                    "x-ratelimit-remaining": "0",
                },
            )

        write_audit_log(
            request_id=request_id,
            agent_id=principal.agent_id,
            method=method,
            path=request_path,
            decision="allow",
            reason="api_key_valid",
        )
        return allow(principal.agent_id)

    if method in PUBLIC_UI_METHODS and is_public_ui_surface(request_path):
        if not has_canonical_public_ui_target(request):
            write_audit_log(
                request_id=request_id,
                agent_id="anonymous",
                method=method,
                path=request_path,
                decision="deny",
                reason="non_canonical_route",
            )
            return safe_api_denial(
                403,
                error="forbidden",
                reason="non_canonical_route",
            )
        write_audit_log(
            request_id=request_id,
            agent_id="anonymous",
            method=method,
            path=request_path,
            decision="allow",
            reason="public_ui_read_only",
        )
        return allow("anonymous")

    if (method, request_path) in PUBLIC_ROUTES:
        write_audit_log(
            request_id=request_id,
            agent_id="anonymous",
            method=method,
            path=request_path,
            decision="allow",
            reason="public_route",
        )
        return allow("anonymous")

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
    return allow(principal.agent_id)
