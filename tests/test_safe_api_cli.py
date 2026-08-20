from __future__ import annotations

import json
from pathlib import Path

import pytest

from safe_api_tool import __main__ as cli_module
from safe_api_tool.__main__ import main
from safe_api_tool.audit import ExecutionReceipt
from safe_api_tool.models import RequestProposal


ROOT = Path(__file__).resolve().parents[1]
ANALYSIS = ROOT / "security-results/security-analysis.jsonl"


def test_propose_then_default_dry_run_never_needs_a_secret(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.delenv("SAFE_API_TOOL_API_KEY", raising=False)
    proposal_path = tmp_path / "proposal.json"

    assert main(
        [
            "propose",
            "--analysis",
            str(ANALYSIS),
            "--output",
            str(proposal_path),
        ]
    ) == 0
    capsys.readouterr()

    assert main(["run", str(proposal_path)]) == 0
    output = json.loads(capsys.readouterr().out)

    assert output["mode"] == "dry-run"
    assert output["allowed"] is True
    assert output["path"] == "/api/test/validate"
    assert "payload" not in output
    assert "api_key" not in json.dumps(output).lower()


def test_cli_rejects_extra_url_field(tmp_path: Path, capsys) -> None:
    path = tmp_path / "unsafe.json"
    path.write_text(
        json.dumps(
            {
                "endpoint_id": "input-validation",
                "test_case_id": "empty",
                "rationale": "unsafe extra field",
                "source_finding_ids": [],
                "requested_headers": {},
                "url": "http://localhost:8000/api/test/validate",
            }
        ),
        encoding="utf-8",
    )

    assert main(["run", str(path)]) == 2
    assert "strict schema" in capsys.readouterr().err


def test_cli_returns_distinct_denial_code_before_network(
    tmp_path: Path,
    capsys,
) -> None:
    path = tmp_path / "denied.json"
    proposal = RequestProposal(
        endpoint_id="admin",
        test_case_id="empty",
        rationale="negative control",
        source_finding_ids=[],
        requested_headers={},
    )
    path.write_text(proposal.model_dump_json(), encoding="utf-8")

    assert main(["run", str(path)]) == 3
    output = json.loads(capsys.readouterr().out)
    assert output["allowed"] is False
    assert output["reason"] == "endpoint_not_allowed"
    assert output["path"] is None


def test_demo_dry_run_has_two_allowed_steps_and_one_negative_control(
    capsys,
) -> None:
    assert main(["demo", "--analysis", str(ANALYSIS)]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["demo"] == "dry-run"
    assert [step["allowed"] for step in output["steps"]] == [True, True, False]
    assert output["steps"][2]["reason"] == "endpoint_not_allowed"


@pytest.mark.parametrize("status_code", [302, 500])
def test_execute_returns_failure_when_http_status_breaks_contract(
    status_code: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    proposal_path = tmp_path / "proposal.json"
    proposal = RequestProposal(
        endpoint_id="input-validation",
        test_case_id="empty",
        rationale="Verify an unexpected response never passes the CLI gate.",
        source_finding_ids=[],
        requested_headers={},
    )
    proposal_path.write_text(proposal.model_dump_json(), encoding="utf-8")
    receipt = ExecutionReceipt(
        timestamp="2026-08-10T00:00:00Z",
        proposal_id="0123456789abcdef",
        request_id="unexpected-status-test",
        policy_sha256="a" * 64,
        endpoint_id="input-validation",
        test_case_id="empty",
        method="POST",
        path="/api/test/validate",
        requested_header_names=[],
        request_bytes=2,
        request_sha256="b" * 64,
        expected_status=200,
        expected_status_matched=False,
        outcome="unexpected_status",
        status_code=status_code,
        duration_ms=1.0,
        response_bytes=0,
        response_sha256=None,
        response_truncated=False,
        response_excerpt=None,
        reason="unexpected_status",
    )
    monkeypatch.setattr(cli_module, "_execute_one", lambda *args, **kwargs: receipt)

    assert main(["run", str(proposal_path), "--execute"]) == 4
    output = json.loads(capsys.readouterr().out)
    assert output["outcome"] == "unexpected_status"
    assert output["expected_status_matched"] is False


def test_cli_error_path_sanitizes_sensitive_exception_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    proposal_path = tmp_path / "proposal.json"
    proposal_path.write_text(
        RequestProposal(
            endpoint_id="input-validation",
            test_case_id="empty",
            rationale="Exercise the curated empty profile.",
            source_finding_ids=[],
            requested_headers={},
        ).model_dump_json(),
        encoding="utf-8",
    )

    def fail(*args, **kwargs):
        raise ValueError("owner@example.test password=exception-secret")

    monkeypatch.setattr(cli_module, "_execute_one", fail)
    assert main(["run", str(proposal_path), "--execute"]) == 2
    error = capsys.readouterr().err
    assert "owner@example.test" not in error
    assert "exception-secret" not in error
    assert "[REDACTED_EMAIL]" in error
    assert "[REDACTED_PASSWORD]" in error
