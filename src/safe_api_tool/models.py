from __future__ import annotations

import re
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


HttpMethod = Literal["GET", "POST"]
SafeTestCategory = Literal[
    "long-string",
    "special-characters",
    "empty",
    "wrong-type",
]
FindingId = Annotated[str, Field(min_length=1, max_length=160)]
HeaderValue = Annotated[str, Field(max_length=4096)]
_CANONICAL_TEST_PATH = re.compile(r"^/api/test/[a-z0-9/-]+$")
_LOWERCASE_HEADER_NAME = re.compile(r"^[a-z0-9-]+$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)


class ApiKeyPolicy(StrictModel):
    header_name: Literal["x-api-key"]
    environment_variable: Literal["SAFE_API_TOOL_API_KEY"]
    principal_id: Literal["safe-api-tool"]


class PolicyLimits(StrictModel):
    requests_per_minute: int = Field(ge=1, le=10_000)
    timeout_seconds: float = Field(gt=0, le=30)
    max_request_bytes: int = Field(ge=128, le=1_048_576)
    max_response_bytes: int = Field(ge=128, le=1_048_576)
    max_requested_headers: int = Field(ge=0, le=16)
    max_header_value_bytes: int = Field(ge=1, le=4096)


def _is_canonical_test_path(path: str) -> bool:
    if _CANONICAL_TEST_PATH.fullmatch(path) is None:
        return False
    if any(character in path for character in ("?", "#", "\\", "%")):
        return False
    if "//" in path or any(part in {".", ".."} for part in path.split("/")):
        return False
    return True


class EndpointPolicy(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    method: HttpMethod
    path: str
    allowed_test_case_ids: list[str] = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def path_must_be_exact_and_canonical(cls, value: str) -> str:
        if not _is_canonical_test_path(value):
            raise ValueError("endpoint path must be an exact canonical /api/test path")
        return value

    @field_validator("allowed_test_case_ids")
    @classmethod
    def allowed_test_cases_must_be_unique(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("allowed_test_case_ids must be unique")
        return values


class SafeApiPolicy(StrictModel):
    schema_path: Literal["schemas/safe-api-tool-policy.schema.json"] = Field(
        alias="schema"
    )
    schema_version: Literal["1.0"]
    gateway_origin: str
    api_key: ApiKeyPolicy
    allowed_request_headers: list[str]
    limits: PolicyLimits
    endpoints: list[EndpointPolicy] = Field(min_length=1)

    @field_validator("gateway_origin")
    @classmethod
    def gateway_origin_must_be_pinned(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "localhost"
            or parsed.port != 8080
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("gateway_origin must be pinned to http://localhost:8080")
        return value.rstrip("/")

    @field_validator("allowed_request_headers")
    @classmethod
    def allowed_headers_must_be_canonical(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("allowed_request_headers must be unique")
        for value in values:
            if _LOWERCASE_HEADER_NAME.fullmatch(value) is None:
                raise ValueError("allowed request header names must be lowercase")
        return values

    @model_validator(mode="after")
    def endpoints_must_be_unique(self) -> "SafeApiPolicy":
        ids = [endpoint.id for endpoint in self.endpoints]
        routes = [(endpoint.method, endpoint.path) for endpoint in self.endpoints]
        if len(ids) != len(set(ids)):
            raise ValueError("endpoint IDs must be unique")
        if len(routes) != len(set(routes)):
            raise ValueError("endpoint routes must be unique")
        return self


class SafeTestCase(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    category: SafeTestCategory
    description: str = Field(min_length=1, max_length=300)
    payload: dict[str, Any]
    expected_status: int = Field(ge=100, le=599)


class SafeTestCatalog(StrictModel):
    schema_path: Literal["schemas/safe-api-test-cases.schema.json"] = Field(
        alias="schema"
    )
    schema_version: Literal["1.0"]
    test_cases: list[SafeTestCase] = Field(min_length=4, max_length=4)

    @model_validator(mode="after")
    def cases_must_cover_each_safe_category_once(self) -> "SafeTestCatalog":
        ids = [test_case.id for test_case in self.test_cases]
        categories = [test_case.category for test_case in self.test_cases]
        expected = {
            "long-string",
            "special-characters",
            "empty",
            "wrong-type",
        }
        if set(ids) != expected or set(categories) != expected:
            raise ValueError("catalog must contain exactly the four safe profiles")
        if len(ids) != len(set(ids)) or len(categories) != len(set(categories)):
            raise ValueError("test case IDs and categories must be unique")
        return self


class RequestProposal(StrictModel):
    endpoint_id: str = Field(min_length=1, max_length=64)
    test_case_id: str = Field(min_length=1, max_length=64)
    rationale: str = Field(min_length=1, max_length=500)
    source_finding_ids: list[FindingId] = Field(max_length=32)
    requested_headers: dict[str, HeaderValue] = Field(max_length=16)

    @field_validator("rationale")
    @classmethod
    def rationale_must_not_be_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("rationale must not be blank")
        return cleaned

    @field_validator("source_finding_ids")
    @classmethod
    def source_ids_must_be_unique_and_non_blank(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)) or any(not value.strip() for value in values):
            raise ValueError("source_finding_ids must be unique and non-blank")
        return values

    @field_validator("requested_headers")
    @classmethod
    def requested_headers_must_be_canonical(
        cls,
        values: dict[str, str],
    ) -> dict[str, str]:
        for name, value in values.items():
            if _LOWERCASE_HEADER_NAME.fullmatch(name) is None:
                raise ValueError("requested header names must be lowercase")
            if any(ord(character) < 32 or ord(character) > 126 for character in value):
                raise ValueError(
                    "requested header values must contain printable ASCII only"
                )
        return values


class MaterializedRequest(StrictModel):
    endpoint_id: str
    test_case_id: str
    method: HttpMethod
    path: str
    headers: dict[str, str]
    payload: dict[str, Any] | None
    expected_status: int = Field(ge=100, le=599)
    request_bytes: int = Field(ge=0)


class PolicyDecision(StrictModel):
    allowed: bool
    reason: str = Field(min_length=1, max_length=200)
    request: MaterializedRequest | None = None

    @model_validator(mode="after")
    def request_presence_must_match_decision(self) -> "PolicyDecision":
        if self.allowed != (self.request is not None):
            raise ValueError("allowed decisions require one materialized request")
        return self
