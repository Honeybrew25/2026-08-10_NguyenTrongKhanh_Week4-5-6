from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from pydantic import ValidationError

from safe_api_tool.approval import (
    ContractJsonlWriter,
    InteractiveApprovalProvider,
)
from safe_api_tool.audit import AuditLogWriter, ExecutionReceipt
from safe_api_tool.client import (
    ClientConfigurationError,
    SafeApiClient,
    load_api_key,
    proposal_id,
)
from safe_api_tool.models import PolicyDecision, RequestProposal
from safe_api_tool.planner import (
    DEFAULT_ANALYSIS_PATH,
    DeterministicSafeRequestPlanner,
    PlannerInputError,
    load_analysis_findings,
    select_finding,
    write_proposal,
)
from safe_api_tool.policy import (
    DEFAULT_POLICY_PATH,
    DEFAULT_TEST_CATALOG_PATH,
    PolicyEngine,
    PolicyLoadError,
)
from sentinel_guardrails.redaction import sanitize_text


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROPOSAL_PATH = (
    ROOT / "security-results" / "runs" / "week-4" / "request-proposal.json"
)
DEFAULT_AUDIT_PATH = (
    ROOT / "security-results" / "runs" / "week-5" / "safe-api-receipts.jsonl"
)
DEFAULT_APPROVAL_PATH = (
    ROOT / "security-results" / "runs" / "week-5" / "approval-decisions.jsonl"
)
DEFAULT_GUARDED_RESPONSE_PATH = (
    ROOT / "security-results" / "runs" / "week-5" / "guarded-responses.jsonl"
)
DEFAULT_EVENT_PATH = (
    ROOT / "security-results" / "runs" / "week-5" / "run-events.jsonl"
)


def _add_sources(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument(
        "--test-cases",
        type=Path,
        default=DEFAULT_TEST_CATALOG_PATH,
    )


def _add_execution_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT_PATH)
    parser.add_argument(
        "--approval-log", type=Path, default=DEFAULT_APPROVAL_PATH
    )
    parser.add_argument(
        "--guarded-response-log",
        type=Path,
        default=DEFAULT_GUARDED_RESPONSE_PATH,
    )
    parser.add_argument("--event-log", type=Path, default=DEFAULT_EVENT_PATH)
    parser.add_argument(
        "--runtime-profile",
        choices=("host", "compose"),
        default="host",
        help="Select a trusted runtime origin; proposals cannot provide an origin.",
    )
    parser.add_argument(
        "--approval-timeout",
        type=float,
        default=60.0,
        help="Seconds before an unanswered approval defaults to Reject.",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m safe_api_tool",
        description="Propose and execute bounded staging API requests through Envoy.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    propose = subparsers.add_parser(
        "propose",
        help="Create a strict request proposal from grounded Week 3 analysis.",
    )
    propose.add_argument("--analysis", type=Path, default=DEFAULT_ANALYSIS_PATH)
    propose.add_argument("--finding-id")
    propose.add_argument("--output", type=Path, default=DEFAULT_PROPOSAL_PATH)

    run = subparsers.add_parser(
        "run",
        help="Validate a proposal; add --execute for the only network-capable mode.",
    )
    run.add_argument("proposal", type=Path)
    _add_sources(run)
    _add_execution_options(run)
    run.add_argument("--execute", action="store_true")

    demo = subparsers.add_parser(
        "demo",
        help="Show Agent proposal, allowed execution and a denied capability.",
    )
    demo.add_argument("--analysis", type=Path, default=DEFAULT_ANALYSIS_PATH)
    demo.add_argument("--finding-id")
    _add_sources(demo)
    _add_execution_options(demo)
    demo.add_argument("--execute", action="store_true")
    return parser


def _print_json(value: object) -> None:
    print(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
    )


def _load_proposal(path: Path) -> RequestProposal:
    try:
        return RequestProposal.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise PlannerInputError(f"proposal file not found: {path}") from error
    except (OSError, UnicodeError) as error:
        raise PlannerInputError(f"proposal file is unreadable: {path}") from error
    except ValidationError as error:
        raise PlannerInputError("proposal does not match the strict schema") from error


def _decision_view(
    proposal: RequestProposal,
    engine: PolicyEngine,
    decision: PolicyDecision,
) -> dict[str, object]:
    request = decision.request
    return {
        "mode": "dry-run",
        "planner": DeterministicSafeRequestPlanner.name,
        "proposal_id": proposal_id(proposal),
        "policy_sha256": engine.policy_sha256,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "endpoint_id": proposal.endpoint_id,
        "test_case_id": proposal.test_case_id,
        "method": request.method if request else None,
        "path": request.path if request else None,
        "requested_header_names": sorted(proposal.requested_headers),
        "request_bytes": request.request_bytes if request else 0,
        "expected_status": request.expected_status if request else None,
    }


def _receipt_view(stage: str, receipt: ExecutionReceipt) -> dict[str, object]:
    return {
        "stage": stage,
        **receipt.model_dump(mode="json"),
    }


def _is_expected_success(receipt: ExecutionReceipt) -> bool:
    return receipt.outcome == "success" and receipt.expected_status_matched is True


def _execute_one(
    proposal: RequestProposal,
    *,
    engine: PolicyEngine,
    audit_path: Path,
    approval_path: Path,
    guarded_response_path: Path,
    event_path: Path,
    runtime_profile: str,
    approval_timeout: float,
) -> ExecutionReceipt:
    api_key = load_api_key(engine.policy.api_key.environment_variable)
    provider = InteractiveApprovalProvider(
        timeout_seconds=approval_timeout,
        input_fn=lambda: input(),
        output_fn=lambda value: print(value, file=sys.stderr),
    )
    with SafeApiClient(
        engine,
        api_key=api_key,
        audit_writer=AuditLogWriter(audit_path),
        approval_writer=ContractJsonlWriter(approval_path),
        guarded_response_writer=ContractJsonlWriter(guarded_response_path),
        event_writer=ContractJsonlWriter(event_path),
        approval_provider=provider,
        runtime_profile=runtime_profile,
    ) as client:
        return client.execute(proposal)


def _run_demo(args: argparse.Namespace, engine: PolicyEngine) -> int:
    findings = load_analysis_findings(args.analysis)
    finding = select_finding(findings, args.finding_id)
    planner = DeterministicSafeRequestPlanner()
    status_proposal = planner.status_proposal()
    finding_proposal = planner.propose(finding)
    forbidden_proposal = RequestProposal(
        endpoint_id="admin",
        test_case_id="empty",
        rationale="Negative control proving an unlisted capability is denied.",
        source_finding_ids=list(finding.source_finding_ids),
        requested_headers={},
    )

    if not args.execute:
        views = [
            _decision_view(proposal, engine, engine.decide(proposal))
            for proposal in (status_proposal, finding_proposal, forbidden_proposal)
        ]
        _print_json({"demo": "dry-run", "steps": views})
        return 0 if [view["allowed"] for view in views] == [True, True, False] else 4

    api_key = load_api_key(engine.policy.api_key.environment_variable)
    provider = InteractiveApprovalProvider(
        timeout_seconds=args.approval_timeout,
        input_fn=lambda: input(),
        output_fn=lambda value: print(value, file=sys.stderr),
    )
    with SafeApiClient(
        engine,
        api_key=api_key,
        audit_writer=AuditLogWriter(args.audit),
        approval_writer=ContractJsonlWriter(args.approval_log),
        guarded_response_writer=ContractJsonlWriter(args.guarded_response_log),
        event_writer=ContractJsonlWriter(args.event_log),
        approval_provider=provider,
        runtime_profile=args.runtime_profile,
    ) as client:
        status_receipt = client.execute(status_proposal)
        print(
            "Demo decision 1/2: type Reject to prove zero network calls.",
            file=sys.stderr,
        )
        rejected_receipt = client.execute(finding_proposal)
        print(
            "Demo decision 2/2: type Approve to execute one bounded request.",
            file=sys.stderr,
        )
        finding_receipt = client.execute(finding_proposal)
        forbidden_receipt = client.execute(forbidden_proposal)
    receipts = [
        _receipt_view("gateway-status", status_receipt),
        _receipt_view("reject-control", rejected_receipt),
        _receipt_view("approve-control", finding_receipt),
        _receipt_view("negative-control", forbidden_receipt),
    ]
    _print_json(
        {
            "demo": "execute",
            "artifacts": {
                "receipts": str(args.audit),
                "approvals": str(args.approval_log),
                "guarded_responses": str(args.guarded_response_log),
                "events": str(args.event_log),
            },
            "steps": receipts,
        }
    )
    passed = (
        _is_expected_success(status_receipt)
        and rejected_receipt.outcome == "policy_denied"
        and rejected_receipt.reason == "approval_rejected"
        and _is_expected_success(finding_receipt)
        and forbidden_receipt.outcome == "policy_denied"
    )
    return 0 if passed else 4


def main(arguments: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        if args.command == "propose":
            finding = select_finding(
                load_analysis_findings(args.analysis),
                args.finding_id,
            )
            proposal = DeterministicSafeRequestPlanner().propose(finding)
            output = write_proposal(proposal, args.output)
            _print_json(
                {
                    "planner": DeterministicSafeRequestPlanner.name,
                    "proposal_id": proposal_id(proposal),
                    "source_finding_ids": proposal.source_finding_ids,
                    "output": str(output),
                }
            )
            return 0

        engine = PolicyEngine.from_files(args.policy, args.test_cases)
        if args.command == "demo":
            return _run_demo(args, engine)

        proposal = _load_proposal(args.proposal)
        if not args.execute:
            decision = engine.decide(proposal)
            _print_json(_decision_view(proposal, engine, decision))
            return 0 if decision.allowed else 3

        receipt = _execute_one(
            proposal,
            engine=engine,
            audit_path=args.audit,
            approval_path=args.approval_log,
            guarded_response_path=args.guarded_response_log,
            event_path=args.event_log,
            runtime_profile=args.runtime_profile,
            approval_timeout=args.approval_timeout,
        )
        _print_json(_receipt_view("execute", receipt))
        if _is_expected_success(receipt):
            return 0
        return 3 if receipt.outcome == "policy_denied" else 4
    except (
        ClientConfigurationError,
        PlannerInputError,
        PolicyLoadError,
        ValidationError,
        ValueError,
    ) as error:
        safe_error = sanitize_text(str(error)).value
        print(f"error: {safe_error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
