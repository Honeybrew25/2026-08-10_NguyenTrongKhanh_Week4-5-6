from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from safe_api_tool.models import (
    MaterializedRequest,
    PolicyDecision,
    RequestProposal,
    SafeApiPolicy,
    SafeTestCatalog,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = ROOT / "config" / "safe-api-tool" / "policy.json"
DEFAULT_TEST_CATALOG_PATH = ROOT / "data" / "safe-api-test-cases.json"

FORBIDDEN_EXACT_HEADERS = frozenset(
    {
        "authorization",
        "connection",
        "content-length",
        "cookie",
        "host",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-api-key",
        "x-request-id",
    }
)
FORBIDDEN_HEADER_PREFIXES = ("proxy-", "sec-", "x-forwarded-")


class PolicyLoadError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise PolicyLoadError(f"file_not_found:{path}") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PolicyLoadError(f"unreadable_json:{path}") from error


def load_policy(path: Path = DEFAULT_POLICY_PATH) -> SafeApiPolicy:
    try:
        return SafeApiPolicy.model_validate(_load_json(path))
    except ValidationError as error:
        raise PolicyLoadError("invalid_policy") from error


def load_test_catalog(path: Path = DEFAULT_TEST_CATALOG_PATH) -> SafeTestCatalog:
    try:
        return SafeTestCatalog.model_validate(_load_json(path))
    except ValidationError as error:
        raise PolicyLoadError("invalid_test_catalog") from error


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class PolicyEngine:
    def __init__(self, policy: SafeApiPolicy, catalog: SafeTestCatalog) -> None:
        self.policy = policy
        self.catalog = catalog
        self._endpoints = {endpoint.id: endpoint for endpoint in policy.endpoints}
        self._test_cases = {test_case.id: test_case for test_case in catalog.test_cases}
        referenced = {
            test_case_id
            for endpoint in policy.endpoints
            for test_case_id in endpoint.allowed_test_case_ids
        }
        unknown = referenced.difference(self._test_cases)
        if unknown:
            raise PolicyLoadError("policy_references_unknown_test_case")
        self.policy_sha256 = hashlib.sha256(
            _canonical_bytes(policy.model_dump(by_alias=True, mode="json"))
        ).hexdigest()

    @classmethod
    def from_files(
        cls,
        policy_path: Path = DEFAULT_POLICY_PATH,
        catalog_path: Path = DEFAULT_TEST_CATALOG_PATH,
    ) -> "PolicyEngine":
        return cls(load_policy(policy_path), load_test_catalog(catalog_path))

    def decide(self, proposal: RequestProposal) -> PolicyDecision:
        endpoint = self._endpoints.get(proposal.endpoint_id)
        if endpoint is None:
            return PolicyDecision(allowed=False, reason="endpoint_not_allowed")

        test_case = self._test_cases.get(proposal.test_case_id)
        if test_case is None or proposal.test_case_id not in endpoint.allowed_test_case_ids:
            return PolicyDecision(allowed=False, reason="test_case_not_allowed")

        if len(proposal.requested_headers) > self.policy.limits.max_requested_headers:
            return PolicyDecision(allowed=False, reason="too_many_requested_headers")

        headers: dict[str, str] = {}
        allowed_headers = set(self.policy.allowed_request_headers)
        for name, value in proposal.requested_headers.items():
            if (
                name in FORBIDDEN_EXACT_HEADERS
                or name.startswith(FORBIDDEN_HEADER_PREFIXES)
                or name not in allowed_headers
            ):
                return PolicyDecision(allowed=False, reason="header_not_allowed")
            if len(value.encode("utf-8")) > self.policy.limits.max_header_value_bytes:
                return PolicyDecision(allowed=False, reason="header_value_too_large")
            headers[name] = value

        payload = None if endpoint.method == "GET" else test_case.payload
        request_bytes = 0 if payload is None else len(_canonical_bytes(payload))
        if request_bytes > self.policy.limits.max_request_bytes:
            return PolicyDecision(allowed=False, reason="request_body_too_large")

        return PolicyDecision(
            allowed=True,
            reason="policy_allowed",
            request=MaterializedRequest(
                endpoint_id=endpoint.id,
                test_case_id=test_case.id,
                method=endpoint.method,
                path=endpoint.path,
                headers=headers,
                payload=payload,
                expected_status=test_case.expected_status,
                request_bytes=request_bytes,
            ),
        )
