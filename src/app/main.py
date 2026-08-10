from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field


MAX_TEST_INPUT_CHARACTERS = 4096
MAX_TEST_PREVIEW_CHARACTERS = 256
GATEWAY_CREDENTIAL_HEADER = "x-api-key"
UI_STATIC_DIRECTORY = Path(__file__).resolve().parent / "static"
UI_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; base-uri 'none'; connect-src 'self'; "
    "font-src 'self'; form-action 'none'; frame-ancestors 'none'; "
    "frame-src 'none'; img-src 'self' data:; object-src 'none'; "
    "script-src 'self'; style-src 'self'"
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class HealthResponse(BaseModel):
    status: Literal["ok"]


class User(BaseModel):
    id: int
    name: str
    role: Literal["student", "instructor"]


class AdminResponse(BaseModel):
    message: str
    authentication_enabled: bool


class ProtectedResourceMetadata(BaseModel):
    resource: str
    authorization_servers: list[str]
    scopes_supported: list[str]
    bearer_methods_supported: list[Literal["header"]]


class TestStatusResponse(StrictModel):
    status: Literal["ready"]
    stateless: Literal[True]
    max_input_characters: int = Field(ge=1)
    max_preview_characters: int = Field(ge=1)


class TestValidationRequest(StrictModel):
    value: str = Field(max_length=MAX_TEST_INPUT_CHARACTERS)


class TestValidationResponse(StrictModel):
    accepted: Literal[True]
    received_length: int = Field(ge=0, le=MAX_TEST_INPUT_CHARACTERS)
    preview: str = Field(max_length=MAX_TEST_PREVIEW_CHARACTERS)
    truncated: bool


DEMO_USERS: tuple[User, ...] = (
    User(id=1, name="Ada", role="student"),
    User(id=2, name="Grace", role="instructor"),
)

app = FastAPI(
    title="Educational Security Staging API",
    version="0.1.0",
)


def ensure_gateway_consumed_api_key(request: Request) -> None:
    """Fail closed if a Gateway credential ever reaches the application."""
    if GATEWAY_CREDENTIAL_HEADER in request.headers:
        raise HTTPException(
            status_code=500,
            detail="gateway credential reached the application boundary",
        )


def is_ui_request_path(path: str) -> bool:
    return path in {"/", "/ui"} or path.startswith("/ui/")


@app.middleware("http")
async def reject_gateway_credential_on_ui(request: Request, call_next):
    """Enforce the credential boundary and harden the public static surface."""
    if (
        is_ui_request_path(request.url.path)
        and GATEWAY_CREDENTIAL_HEADER in request.headers
    ):
        response: Response = JSONResponse(
            status_code=500,
            content={"detail": "gateway credential reached the application boundary"},
        )
    else:
        response = await call_next(request)

    if is_ui_request_path(request.url.path):
        response.headers["content-security-policy"] = UI_CONTENT_SECURITY_POLICY
        response.headers["cross-origin-opener-policy"] = "same-origin"
        response.headers["cross-origin-resource-policy"] = "same-origin"
        response.headers["permissions-policy"] = (
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
        )
        response.headers["referrer-policy"] = "no-referrer"
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["x-frame-options"] = "DENY"
    return response


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
def dashboard_redirect() -> RedirectResponse:
    return RedirectResponse(url="/ui/", status_code=307)


app.mount(
    "/ui",
    StaticFiles(directory=UI_STATIC_DIRECTORY, html=True),
    name="ui",
)


@app.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get(
    "/.well-known/oauth-protected-resource",
    response_model=ProtectedResourceMetadata,
    tags=["system"],
)
def protected_resource_metadata() -> ProtectedResourceMetadata:
    return ProtectedResourceMetadata(
        resource="http://localhost:8080",
        authorization_servers=["http://localhost:8081/realms/staging"],
        scopes_supported=["users:read", "admin:read"],
        bearer_methods_supported=["header"],
    )


@app.get("/api/users", response_model=list[User], tags=["users"])
def list_users() -> list[User]:
    return list(DEMO_USERS)


@app.get(
    "/api/test/status",
    response_model=TestStatusResponse,
    tags=["testing"],
)
def test_status(request: Request) -> TestStatusResponse:
    ensure_gateway_consumed_api_key(request)
    return TestStatusResponse(
        status="ready",
        stateless=True,
        max_input_characters=MAX_TEST_INPUT_CHARACTERS,
        max_preview_characters=MAX_TEST_PREVIEW_CHARACTERS,
    )


@app.post(
    "/api/test/validate",
    response_model=TestValidationResponse,
    tags=["testing"],
)
def validate_test_payload(
    payload: TestValidationRequest,
    request: Request,
) -> TestValidationResponse:
    ensure_gateway_consumed_api_key(request)
    preview = payload.value[:MAX_TEST_PREVIEW_CHARACTERS]
    return TestValidationResponse(
        accepted=True,
        received_length=len(payload.value),
        preview=preview,
        truncated=len(payload.value) > len(preview),
    )


@app.get("/api/admin", response_model=AdminResponse, tags=["admin"])
def admin() -> AdminResponse:
    return AdminResponse(
        message="Administrative demonstration endpoint",
        authentication_enabled=False,
    )
