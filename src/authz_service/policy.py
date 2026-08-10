from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


SAFE_API_KEY_ENVIRONMENT_VARIABLE = "SAFE_API_TOOL_API_KEY"
SAFE_API_KEY_HEADER = "x-api-key"
SAFE_API_PRINCIPAL = "safe-api-tool"


class PolicyConfigurationError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SafeApiKeyPolicy:
    header_name: str
    environment_variable: str
    principal_id: str


@dataclass(frozen=True)
class SafeApiPolicy:
    api_key: SafeApiKeyPolicy
    requests_per_minute: int
    routes: frozenset[tuple[str, str]]

    def allows(self, method: str, path: str) -> bool:
        return (method.upper(), path) in self.routes


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _ApiKeyDocument(_StrictModel):
    header_name: Literal["x-api-key"]
    environment_variable: Literal["SAFE_API_TOOL_API_KEY"]
    principal_id: Literal["safe-api-tool"]


class _LimitsDocument(_StrictModel):
    requests_per_minute: int = Field(ge=1, le=10_000)
    timeout_seconds: float = Field(gt=0, le=30)
    max_request_bytes: int = Field(ge=128, le=1_048_576)
    max_response_bytes: int = Field(ge=128, le=1_048_576)
    max_requested_headers: int = Field(ge=0, le=16)
    max_header_value_bytes: int = Field(ge=1, le=4096)


class _EndpointDocument(_StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    method: Literal["GET", "POST"]
    path: str = Field(pattern=r"^/api/test/[a-z0-9/-]+$")
    allowed_test_case_ids: list[str] = Field(min_length=1)

    @field_validator("allowed_test_case_ids")
    @classmethod
    def validate_test_case_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)) or any(
            not value
            or len(value) > 64
            or not value[0].isalpha()
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in value)
            for value in values
        ):
            raise ValueError("invalid or duplicate test case ID")
        return values


class _PolicyDocument(_StrictModel):
    schema_path: Literal["schemas/safe-api-tool-policy.schema.json"] = Field(
        alias="schema"
    )
    schema_version: Literal["1.0"]
    gateway_origin: Literal["http://localhost:8080"]
    api_key: _ApiKeyDocument
    allowed_request_headers: list[str]
    limits: _LimitsDocument
    endpoints: list[_EndpointDocument] = Field(min_length=1)

    @field_validator("allowed_request_headers")
    @classmethod
    def validate_allowed_headers(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)) or any(
            not value
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in value)
            for value in values
        ):
            raise ValueError("invalid or duplicate allowed request header")
        return values


def _validate_exact_path(path: str) -> str:
    if (
        not path.startswith("/")
        or not path.startswith("/api/test/")
        or "?" in path
        or "#" in path
        or "\\" in path
        or "%" in path
        or "//" in path
        or PurePosixPath(path).as_posix() != path
        or any(part in {".", ".."} for part in path.split("/"))
    ):
        raise PolicyConfigurationError("invalid_endpoint_path")
    return path


def load_safe_api_policy(path: Path) -> SafeApiPolicy:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise PolicyConfigurationError("policy_not_found") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PolicyConfigurationError("policy_unreadable") from error

    try:
        parsed = _PolicyDocument.model_validate(document)
    except ValidationError as error:
        raise PolicyConfigurationError("policy_schema_invalid") from error

    routes: set[tuple[str, str]] = set()
    endpoint_ids: set[str] = set()
    for endpoint in parsed.endpoints:
        if endpoint.id in endpoint_ids:
            raise PolicyConfigurationError("duplicate_endpoint_id")
        endpoint_ids.add(endpoint.id)
        route = (endpoint.method, _validate_exact_path(endpoint.path))
        if route in routes:
            raise PolicyConfigurationError("duplicate_endpoint_route")
        routes.add(route)

    return SafeApiPolicy(
        api_key=SafeApiKeyPolicy(
            header_name=parsed.api_key.header_name,
            environment_variable=parsed.api_key.environment_variable,
            principal_id=parsed.api_key.principal_id,
        ),
        requests_per_minute=parsed.limits.requests_per_minute,
        routes=frozenset(routes),
    )
