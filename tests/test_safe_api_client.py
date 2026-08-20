from __future__ import annotations

import json
from pathlib import Path

import httpx
from jsonschema import Draft202012Validator

from safe_api_tool.approval import StaticApprovalProvider
from safe_api_tool.audit import AuditLogWriter
from safe_api_tool.client import SafeApiClient
from safe_api_tool.models import RequestProposal
from safe_api_tool.policy import PolicyEngine


ROOT = Path(__file__).resolve().parents[1]
API_KEY = "safe-api-client-unit-key-0000000000000001"


def streamed_response(
    status_code: int,
    content: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        status_code,
        headers=headers,
        stream=httpx.ByteStream(content),
    )


def proposal(**changes: object) -> RequestProposal:
    values: dict[str, object] = {
        "endpoint_id": "input-validation",
        "test_case_id": "special-characters",
        "rationale": "Exercise a curated safe profile.",
        "source_finding_ids": ["finding-1"],
        "requested_headers": {"x-test-purpose": "unit-test"},
    }
    values.update(changes)
    return RequestProposal.model_validate(values)


def client(
    handler,
    *,
    audit_path: Path | None = None,
    clock=lambda: 1.0,
) -> SafeApiClient:
    return SafeApiClient(
        PolicyEngine.from_files(),
        api_key=API_KEY,
        audit_writer=AuditLogWriter(audit_path) if audit_path else None,
        approval_provider=StaticApprovalProvider("approve"),
        transport=httpx.MockTransport(handler),
        monotonic_clock=clock,
        request_id_factory=lambda: "safe-client-request-1",
    )


def test_post_is_materialized_only_for_the_pinned_gateway() -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return streamed_response(
            200,
            b'{"accepted":true}',
            headers={"x-request-id": request.headers["x-request-id"]},
        )

    with client(handler) as tool:
        receipt = tool.execute(proposal())

    assert len(observed) == 1
    request = observed[0]
    assert str(request.url) == "http://localhost:8080/api/test/validate"
    assert request.method == "POST"
    assert request.headers["x-api-key"] == API_KEY
    assert request.headers["x-test-purpose"] == "unit-test"
    assert request.headers["accept-encoding"] == "identity"
    assert json.loads(request.content) == {
        "value": "<tag>&\"'\\/\n\t[]{}!?@#$%^*() — tiếng Việt"
    }
    assert receipt.outcome == "success"
    assert receipt.expected_status_matched is True
    assert receipt.request_id == "safe-client-request-1"


def test_unknown_endpoint_is_denied_before_transport() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    with client(handler) as tool:
        receipt = tool.execute(proposal(endpoint_id="http://evil.test/admin"))

    assert calls == 0
    assert receipt.outcome == "policy_denied"
    assert receipt.reason == "endpoint_not_allowed"
    assert receipt.method is None
    assert receipt.path is None


def test_client_does_not_follow_redirects() -> None:
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        return streamed_response(
            302,
            headers={"location": "http://evil.test/collect"},
        )

    with client(handler) as tool:
        receipt = tool.execute(proposal())

    assert urls == ["http://localhost:8080/api/test/validate"]
    assert receipt.status_code == 302
    assert receipt.outcome == "unexpected_status"
    assert receipt.expected_status_matched is False
    assert receipt.reason == "unexpected_status"


def test_timeout_and_connection_errors_are_typed_without_exception_text() -> None:
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(f"timeout leaked {API_KEY}", request=request)

    with client(timeout_handler) as tool:
        timeout_receipt = tool.execute(proposal())

    def connection_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"connection leaked {API_KEY}", request=request)

    with client(connection_handler) as tool:
        connection_receipt = tool.execute(proposal())

    assert timeout_receipt.outcome == "timeout"
    assert timeout_receipt.reason == "gateway_timeout"
    assert connection_receipt.outcome == "connection_error"
    assert connection_receipt.reason == "gateway_connection_error"
    assert API_KEY not in timeout_receipt.model_dump_json()
    assert API_KEY not in connection_receipt.model_dump_json()


def test_response_stream_stops_at_configured_byte_cap() -> None:
    engine = PolicyEngine.from_files()
    engine.policy.limits.max_response_bytes = 128

    def handler(request: httpx.Request) -> httpx.Response:
        return streamed_response(200, b"x" * 512)

    with SafeApiClient(
        engine,
        api_key=API_KEY,
        approval_provider=StaticApprovalProvider("approve"),
        transport=httpx.MockTransport(handler),
        request_id_factory=lambda: "response-cap",
    ) as tool:
        receipt = tool.execute(proposal())

    assert receipt.outcome == "response_truncated"
    assert receipt.response_truncated is True
    assert receipt.response_bytes == 128
    assert receipt.response_excerpt == "x" * 128


def test_truncated_response_does_not_log_a_partial_api_key() -> None:
    engine = PolicyEngine.from_files()
    engine.policy.limits.max_response_bytes = 128
    exposed_prefix_length = 6
    body = (
        b"x" * (128 - exposed_prefix_length)
        + API_KEY.encode()[:exposed_prefix_length]
        + API_KEY.encode()[exposed_prefix_length:]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return streamed_response(200, body)

    with SafeApiClient(
        engine,
        api_key=API_KEY,
        approval_provider=StaticApprovalProvider("approve"),
        transport=httpx.MockTransport(handler),
        request_id_factory=lambda: "partial-secret-cap",
    ) as tool:
        receipt = tool.execute(proposal())

    assert receipt.response_truncated is True
    assert receipt.response_excerpt is not None
    assert API_KEY[:exposed_prefix_length] not in receipt.response_excerpt
    assert receipt.response_excerpt.endswith("[REDACTED_API_KEY]")


def test_local_rate_limit_blocks_before_second_transport_call() -> None:
    engine = PolicyEngine.from_files()
    engine.policy.limits.requests_per_minute = 1
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return streamed_response(200, b'{"accepted":true}')

    with SafeApiClient(
        engine,
        api_key=API_KEY,
        approval_provider=StaticApprovalProvider("approve"),
        transport=httpx.MockTransport(handler),
        monotonic_clock=lambda: 1.0,
        request_id_factory=lambda: "rate-limit",
    ) as tool:
        first = tool.execute(proposal())
        second = tool.execute(proposal())

    assert first.outcome == "success"
    assert second.outcome == "rate_limited"
    assert second.reason == "local_rate_limit_exceeded"
    assert calls == 1


def test_wrong_type_422_is_an_expected_successful_execution() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return streamed_response(422, b'{"detail":[{"type":"string_type"}]}')

    with client(handler) as tool:
        receipt = tool.execute(proposal(test_case_id="wrong-type"))

    assert receipt.outcome == "success"
    assert receipt.status_code == 422
    assert receipt.expected_status == 422
    assert receipt.expected_status_matched is True


def test_audit_jsonl_matches_schema_and_redacts_secret_response(tmp_path: Path) -> None:
    audit_path = tmp_path / "receipt.jsonl"

    def handler(request: httpx.Request) -> httpx.Response:
        return streamed_response(
            200,
            f"api_key={API_KEY} Authorization: Bearer abc.def.ghi".encode(),
        )

    with client(handler, audit_path=audit_path) as tool:
        receipt = tool.execute(proposal())

    text = audit_path.read_text(encoding="utf-8")
    document = json.loads(text)
    schema = json.loads(
        (ROOT / "schemas/safe-api-log.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(document)
    assert API_KEY not in text
    assert "abc.def.ghi" not in text
    assert document == receipt.model_dump(mode="json")
    assert document["requested_header_names"] == ["x-test-purpose"]


def test_response_redaction_happens_before_excerpt_is_bounded() -> None:
    boundary_prefix = "x" * 1018
    expansion = " api_key=x" * 200
    body = (
        f'{boundary_prefix}{API_KEY}{expansion} '
        '{"api_key":"json-secret","password":"json-password"}'
    ).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return streamed_response(200, body)

    with client(handler) as tool:
        receipt = tool.execute(proposal())

    assert receipt.response_excerpt is not None
    assert len(receipt.response_excerpt) <= 1024
    assert API_KEY not in receipt.response_excerpt
    assert API_KEY[:6] not in receipt.response_excerpt


def test_json_query_and_header_style_secrets_are_redacted() -> None:
    body = (
        '{"api_key":"json-secret","password":"json-password"} '
        "access_token=query-secret&next=safe X-Api-Key: header-secret"
    ).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return streamed_response(200, body)

    with client(handler) as tool:
        receipt = tool.execute(proposal())

    serialized = receipt.model_dump_json()
    for secret in ("json-secret", "json-password", "query-secret", "header-secret"):
        assert secret not in serialized


def test_gateway_429_is_distinct_from_local_rate_limit() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return streamed_response(
            429,
            b'{"error":"rate_limited","reason":"rate_limit_exceeded"}',
        )

    with client(handler) as tool:
        receipt = tool.execute(proposal())

    assert receipt.outcome == "rate_limited"
    assert receipt.status_code == 429
    assert receipt.reason == "gateway_rate_limit_exceeded"
