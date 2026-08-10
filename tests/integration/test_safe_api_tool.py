from __future__ import annotations

import os

import pytest

from safe_api_tool.audit import AuditLogWriter
from safe_api_tool.client import SafeApiClient
from safe_api_tool.models import RequestProposal
from safe_api_tool.planner import DeterministicSafeRequestPlanner
from safe_api_tool.policy import PolicyEngine


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("RUN_INTEGRATION_TESTS") != "1",
        reason="run with python scripts/run_all_tests.py",
    ),
]


def api_key() -> str:
    value = os.getenv("SAFE_API_TOOL_API_KEY")
    assert value
    return value


def test_real_tool_executes_get_and_post_through_envoy(tmp_path) -> None:
    audit_path = tmp_path / "safe-api-tool.jsonl"
    planner = DeterministicSafeRequestPlanner()
    post = RequestProposal(
        endpoint_id="input-validation",
        test_case_id="wrong-type",
        rationale="Controlled wrong-type integration case.",
        source_finding_ids=["integration-finding"],
        requested_headers={"x-test-purpose": "integration"},
    )

    with SafeApiClient(
        PolicyEngine.from_files(),
        api_key=api_key(),
        audit_writer=AuditLogWriter(audit_path),
    ) as client:
        status_receipt = client.execute(planner.status_proposal())
        post_receipt = client.execute(post)

    assert status_receipt.status_code == 200
    assert status_receipt.expected_status_matched is True
    assert post_receipt.status_code == 422
    assert post_receipt.expected_status_matched is True
    assert status_receipt.request_id != post_receipt.request_id
    audit = audit_path.read_text(encoding="utf-8")
    assert api_key() not in audit
    assert audit.count("\n") == 2


def test_real_tool_denies_admin_capability_before_network(tmp_path) -> None:
    proposal = RequestProposal(
        endpoint_id="admin",
        test_case_id="empty",
        rationale="Negative integration control.",
        source_finding_ids=[],
        requested_headers={},
    )
    with SafeApiClient(
        PolicyEngine.from_files(),
        api_key=api_key(),
        audit_writer=AuditLogWriter(tmp_path / "denied.jsonl"),
    ) as client:
        receipt = client.execute(proposal)

    assert receipt.outcome == "policy_denied"
    assert receipt.reason == "endpoint_not_allowed"
    assert receipt.method is None
    assert receipt.path is None
