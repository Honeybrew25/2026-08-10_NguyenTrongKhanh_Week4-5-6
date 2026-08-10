from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from pydantic import ValidationError
import pytest

from safe_api_tool.models import RequestProposal, SafeApiPolicy
from safe_api_tool.planner import (
    DeterministicSafeRequestPlanner,
    load_analysis_findings,
    select_finding,
)
from safe_api_tool.policy import PolicyEngine, PolicyLoadError, load_policy


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "safe-api-tool" / "policy.json"
CATALOG_PATH = ROOT / "data" / "safe-api-test-cases.json"
ANALYSIS_PATH = ROOT / "security-results" / "security-analysis.jsonl"
DEMO_PATH = ROOT / "security-results" / "runs" / "week-4" / "safe-api-demo.jsonl"


def proposal(**overrides: object) -> RequestProposal:
    values: dict[str, object] = {
        "endpoint_id": "input-validation",
        "test_case_id": "special-characters",
        "rationale": "Exercise bounded encoding behavior.",
        "source_finding_ids": ["finding-1"],
        "requested_headers": {"x-test-purpose": "week-4"},
    }
    values.update(overrides)
    return RequestProposal.model_validate(values)


def test_committed_documents_match_their_json_schemas() -> None:
    documents = [
        (POLICY_PATH, ROOT / "schemas" / "safe-api-tool-policy.schema.json"),
        (CATALOG_PATH, ROOT / "schemas" / "safe-api-test-cases.schema.json"),
    ]
    for document_path, schema_path in documents:
        document = json.loads(document_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)


def test_generated_proposal_and_committed_demo_match_strict_contracts() -> None:
    request_schema = json.loads(
        (ROOT / "schemas" / "safe-api-request.schema.json").read_text(
            encoding="utf-8"
        )
    )
    log_schema = json.loads(
        (ROOT / "schemas" / "safe-api-log.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(request_schema)
    Draft202012Validator.check_schema(log_schema)

    finding = select_finding(load_analysis_findings(ANALYSIS_PATH), None)
    generated = DeterministicSafeRequestPlanner().propose(finding)
    Draft202012Validator(request_schema).validate(generated.model_dump(mode="json"))

    receipts = [
        json.loads(line)
        for line in DEMO_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(receipts) == 3
    validator = Draft202012Validator(log_schema)
    for receipt in receipts:
        validator.validate(receipt)


def test_policy_materializes_only_curated_identifiers() -> None:
    engine = PolicyEngine.from_files()

    decision = engine.decide(proposal())

    assert decision.allowed is True
    assert decision.reason == "policy_allowed"
    assert decision.request is not None
    assert decision.request.method == "POST"
    assert decision.request.path == "/api/test/validate"
    assert decision.request.headers == {"x-test-purpose": "week-4"}
    assert decision.request.payload is not None
    assert decision.request.expected_status == 200
    assert len(engine.policy_sha256) == 64


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"endpoint_id": "/api/admin"}, "endpoint_not_allowed"),
        ({"endpoint_id": "http://evil.test"}, "endpoint_not_allowed"),
        ({"test_case_id": "destructive-delete"}, "test_case_not_allowed"),
        ({"requested_headers": {"authorization": "Bearer no"}}, "header_not_allowed"),
        ({"requested_headers": {"x-api-key": "override"}}, "header_not_allowed"),
        ({"requested_headers": {"host": "evil.test"}}, "header_not_allowed"),
        ({"requested_headers": {"x-forwarded-host": "evil.test"}}, "header_not_allowed"),
    ],
)
def test_policy_denies_unlisted_capabilities(
    changes: dict[str, object],
    reason: str,
) -> None:
    decision = PolicyEngine.from_files().decide(proposal(**changes))

    assert decision.allowed is False
    assert decision.reason == reason
    assert decision.request is None


def test_proposal_rejects_url_or_raw_payload_fields() -> None:
    raw = proposal().model_dump()
    raw["url"] = "http://localhost:8000/api/test/validate"
    raw["payload"] = {"value": "arbitrary"}

    with pytest.raises(ValidationError):
        RequestProposal.model_validate(raw)


def test_proposal_rejects_control_characters_in_header_values() -> None:
    for unsafe_value in ("safe\r\ninjected: yes", "Unicode tiếng Việt"):
        with pytest.raises(ValidationError):
            proposal(requested_headers={"x-test-purpose": unsafe_value})


def test_proposal_runtime_contract_matches_ascii_and_length_schema() -> None:
    with pytest.raises(ValidationError):
        proposal(requested_headers={"tést": "unicode header name"})
    with pytest.raises(ValidationError):
        proposal(source_finding_ids=["x" * 161])


def test_policy_rejects_encoded_or_traversal_routes() -> None:
    raw = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    for malicious_path in (
        "/api/test/%2e%2e/admin",
        "/api/test/../admin",
        "/api/test//status",
        "/api/test\\status",
    ):
        candidate = copy.deepcopy(raw)
        candidate["endpoints"][0]["path"] = malicious_path
        with pytest.raises(ValidationError):
            SafeApiPolicy.model_validate(candidate)


def test_malformed_policy_file_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(PolicyLoadError, match="unreadable_json"):
        load_policy(path)


def test_unknown_catalog_reference_fails_closed() -> None:
    policy = load_policy()
    changed = policy.model_copy(deep=True)
    changed.endpoints[0].allowed_test_case_ids.append("not-curated")

    with pytest.raises(PolicyLoadError, match="unknown_test_case"):
        PolicyEngine(changed, PolicyEngine.from_files().catalog)


def test_get_status_materializes_without_a_request_body() -> None:
    decision = PolicyEngine.from_files().decide(
        proposal(
            endpoint_id="test-status",
            test_case_id="empty",
            source_finding_ids=[],
            requested_headers={},
        )
    )

    assert decision.allowed is True
    assert decision.request is not None
    assert decision.request.method == "GET"
    assert decision.request.payload is None
    assert decision.request.request_bytes == 0
