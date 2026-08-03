from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel


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


DEMO_USERS: tuple[User, ...] = (
    User(id=1, name="Ada", role="student"),
    User(id=2, name="Grace", role="instructor"),
)

app = FastAPI(
    title="Educational Security Staging API",
    version="0.1.0",
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


@app.get("/api/admin", response_model=AdminResponse, tags=["admin"])
def admin() -> AdminResponse:
    return AdminResponse(
        message="Administrative demonstration endpoint",
        authentication_enabled=False,
    )
