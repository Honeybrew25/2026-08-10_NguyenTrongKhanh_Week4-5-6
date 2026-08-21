from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Callable, Mapping, Sequence

from rich.console import Console

from project_sentinel.evaluation import evaluate
from project_sentinel.contracts import FinalReport
from project_sentinel.presentation import TerminalDemoPresenter, resolve_human_output
from project_sentinel.runner import (
    DEFAULT_OUTPUT_ROOT,
    GatewayPreflightError,
    SentinelRunner,
    atomic_json,
    generate_run_id,
    run_fresh_bandit,
    wait_for_gateway,
)
from safe_api_tool.approval import InteractiveApprovalProvider
from safe_api_tool.client import ClientConfigurationError, load_api_key
from safe_api_tool.models import RequestProposal
from safe_api_tool.policy import PolicyEngine, ROOT
from security_pipeline.analysis.models import AnalysisFinding


@dataclass(frozen=True, slots=True)
class _DemoScenario:
    scenario_id: str
    run_suffix: str
    title: str
    description: str


_CORE_DEMO_SCENARIOS = (
    _DemoScenario(
        "reject",
        "reject",
        "Người dùng từ chối",
        "Nhập REJECT để chứng minh pipeline dừng trước transport.",
    ),
    _DemoScenario(
        "approve",
        "approve",
        "Người dùng phê duyệt",
        "Nhập APPROVE để gửi đúng một request an toàn qua Gateway.",
    ),
    _DemoScenario(
        "injection",
        "injection",
        "Prompt injection trong response",
        "Request hợp lệ được gửi; response độc hại phải bị cách ly.",
    ),
    _DemoScenario(
        "admin",
        "admin-negative",
        "Đường dẫn quản trị bị chặn",
        "Policy phải chặn /api/admin trước khi mở transport.",
    ),
)

_EXTENDED_DEMO_SCENARIOS = _CORE_DEMO_SCENARIOS + (
    _DemoScenario(
        "status",
        "status",
        "GET trạng thái không cần phê duyệt",
        "Gửi một GET an toàn và xác nhận HTTP 200 mà không hỏi phê duyệt.",
    ),
    _DemoScenario(
        "wrong-type",
        "wrong-type",
        "Sai kiểu dữ liệu có kiểm soát",
        "Phê duyệt POST với dữ liệu sai kiểu; HTTP 422 là kết quả mong đợi.",
    ),
    _DemoScenario(
        "test-case-denied",
        "test-case-denied",
        "Test case không được phép",
        "Policy phải chặn test case không thuộc endpoint trước transport.",
    ),
    _DemoScenario(
        "header-denied",
        "header-denied",
        "Header không được phép",
        "Policy phải chặn header ngoài allowlist trước transport.",
    ),
)


def _add_presentation_options(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--format",
        dest="output_format",
        choices=("auto", "human", "json"),
        default="auto",
        help="Use guided terminal output or stable machine-readable JSON.",
    )
    command.add_argument("--no-color", action="store_true")
    command.add_argument("--verbose", action="store_true")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="project_sentinel",
        description="Deterministic security-to-validation orchestration for the lab.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="Run one proposal from current scanner JSON.")
    run.add_argument("scanner", nargs="+", type=Path)
    run.add_argument("--provider", choices=("deterministic", "gemini"), default="deterministic")
    run.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    run.add_argument("--run-id")
    run.add_argument("--execute", action="store_true")
    run.add_argument("--runtime-profile", choices=("host", "compose"), default="host")
    run.add_argument("--approval-timeout", type=float, default=60.0)
    _add_presentation_options(run)

    demo = commands.add_parser("demo", help="Run the reproducible Week 6 demonstration.")
    demo.add_argument("--scanner", nargs="+", type=Path)
    demo.add_argument("--provider", choices=("deterministic", "gemini"), default="deterministic")
    demo.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    demo.add_argument("--execute", action="store_true")
    demo.add_argument(
        "--scenario-set",
        choices=("core", "extended"),
        default="core",
        help="Run the four core controls or all eight extended controls.",
    )
    demo.add_argument("--runtime-profile", choices=("host", "compose"), default="host")
    demo.add_argument("--approval-timeout", type=float, default=60.0)
    _add_presentation_options(demo)

    evaluation = commands.add_parser("evaluate", help="Run the curated 10-case gate.")
    evaluation.add_argument("--provider", choices=("deterministic",), default="deterministic")
    evaluation.add_argument("--cases", type=Path, default=ROOT / "data" / "evaluation-cases.json")
    evaluation.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    evaluation.add_argument("--evaluation-id")

    preflight = commands.add_parser("preflight", help="Check local demo prerequisites.")
    preflight.add_argument("--execute", action="store_true")
    preflight.add_argument("--runtime-profile", choices=("host", "compose"), default="host")
    preflight.add_argument("--skip-docker", action="store_true")
    return parser


def _presenter(arguments: argparse.Namespace) -> TerminalDemoPresenter | None:
    if not resolve_human_output(arguments.output_format, stream=sys.stdout):
        return None
    _configure_human_stream(sys.stderr)
    return TerminalDemoPresenter(
        Console(
            file=sys.stderr,
            no_color=arguments.no_color,
            highlight=False,
        ),
        verbose=arguments.verbose,
    )


def _configure_human_stream(stream) -> None:
    reconfigure = getattr(stream, "reconfigure", None)
    if not callable(reconfigure):
        return
    try:
        reconfigure(encoding="utf-8", errors="backslashreplace")
    except (OSError, ValueError):
        return


def _interactive(
    timeout: float,
    presenter: TerminalDemoPresenter | None = None,
) -> InteractiveApprovalProvider:
    return InteractiveApprovalProvider(
        timeout_seconds=timeout,
        output_fn=lambda value: print(value, file=sys.stderr),
        request_output_fn=presenter.approval_view if presenter is not None else None,
    )


def _api_key() -> str:
    return load_api_key("SAFE_API_TOOL_API_KEY")


def _safe_cli_error_code(error: Exception) -> str:
    if isinstance(error, GatewayPreflightError):
        return "gateway_preflight_timeout"
    if isinstance(error, ClientConfigurationError):
        return "client_configuration"
    if isinstance(error, FileExistsError):
        return "output_already_exists"
    if isinstance(error, TimeoutError):
        return "network_timeout"
    if isinstance(error, ValueError):
        return "value"
    if isinstance(error, OSError):
        return "operating_system"
    if isinstance(error, RuntimeError):
        return "runtime"
    return "cli_internal_error"


def _print_safe_error(arguments: argparse.Namespace, code: str) -> None:
    output_format = getattr(arguments, "output_format", "json")
    if resolve_human_output(output_format, stream=sys.stdout):
        _configure_human_stream(sys.stderr)
        console = Console(
            file=sys.stderr,
            no_color=getattr(arguments, "no_color", False),
            highlight=False,
        )
        if code == "gateway_preflight_timeout":
            console.print("[bold red]THẤT BẠI[/bold red] · Gateway chưa sẵn sàng.")
            console.print(
                "Demo đã dừng trước khi chạy các tình huống; "
                "không có request kiểm thử nào được gửi."
            )
            console.print("Kiểm tra lần lượt:")
            console.print("  1. docker compose ps")
            console.print("  2. curl http://127.0.0.1:8080/health")
            console.print(
                "  3. docker compose logs --no-color --tail 200 "
                "envoy authz-service api"
            )
        elif code == "interrupted":
            console.print("[bold yellow]ĐÃ DỪNG[/bold yellow] · Bạn đã ngắt lệnh.")
            console.print(
                "Pipeline đã dừng an toàn. Hãy chạy preflight trước khi thử lại."
            )
        else:
            console.print("[bold red]THẤT BẠI[/bold red] · Lệnh không thể hoàn thành.")
        console.print(f"Mã lỗi an toàn: [yellow]{code}[/yellow]")
        return
    print(
        json.dumps({"status": "failed", "safe_error_code": code}),
        file=sys.stderr,
    )


def _proposal_factory(
    endpoint_id: str,
    test_case_id: str = "empty",
    requested_headers: Mapping[str, str] | None = None,
    *,
    rationale: str,
) -> Callable[[AnalysisFinding], RequestProposal]:
    def build(finding: AnalysisFinding) -> RequestProposal:
        return RequestProposal(
            endpoint_id=endpoint_id,
            test_case_id=test_case_id,
            rationale=rationale,
            source_finding_ids=list(finding.source_finding_ids),
            requested_headers=dict(requested_headers or {}),
        )

    return build


def _scenario_plan(scenario_set: str) -> tuple[_DemoScenario, ...]:
    if scenario_set == "core":
        return _CORE_DEMO_SCENARIOS
    if scenario_set == "extended":
        return _EXTENDED_DEMO_SCENARIOS
    raise ValueError("scenario_set_must_be_core_or_extended")


def _demo_run_record(scenario_id: str, report: FinalReport) -> dict[str, object]:
    proposal = report.proposal
    receipt = report.execution_receipt
    guarded = report.guarded_response
    safe_code = (
        receipt.reason
        if receipt is not None and receipt.reason
        else report.safe_error_codes[-1]
        if report.safe_error_codes
        else None
    )
    guard_state = (
        "not_run"
        if guarded is None
        else "quarantined"
        if guarded.injection_detected
        else "sanitized"
    )
    return {
        "scenario_id": scenario_id,
        "run_id": report.run_id,
        "status": report.status,
        "endpoint_id": (
            proposal.endpoint_id
            if proposal is not None
            else receipt.endpoint_id
            if receipt is not None
            else None
        ),
        "test_case_id": (
            proposal.test_case_id
            if proposal is not None
            else receipt.test_case_id
            if receipt is not None
            else None
        ),
        "method": receipt.method if receipt is not None else None,
        "path": receipt.path if receipt is not None else None,
        "human_decision": report.human_decision,
        "requests_sent": report.metrics.requests_sent,
        "approvals": report.metrics.approvals,
        "rejections": report.metrics.rejections,
        "injection_flags": report.metrics.injection_flags,
        "redactions": report.metrics.redactions,
        "errors": report.metrics.errors,
        "receipt_outcome": receipt.outcome if receipt is not None else None,
        "http_status": receipt.status_code if receipt is not None else None,
        "expected_status": receipt.expected_status if receipt is not None else None,
        "expected_status_matched": (
            receipt.expected_status_matched if receipt is not None else None
        ),
        "safe_code": safe_code,
        "guard_state": guard_state,
    }


def _demo_expected_run_facts() -> dict[str, dict[str, object]]:
    return {
        "reject": {
            "status": "rejected",
            "endpoint_id": "input-validation",
            "test_case_id": "empty",
            "method": "POST",
            "path": "/api/test/validate",
            "human_decision": "reject",
            "requests_sent": 0,
            "approvals": 0,
            "rejections": 1,
            "injection_flags": 0,
            "errors": 0,
            "receipt_outcome": "policy_denied",
            "http_status": None,
            "expected_status": 200,
            "expected_status_matched": None,
            "safe_code": "approval_rejected",
            "guard_state": "not_run",
        },
        "approve": {
            "status": "completed",
            "endpoint_id": "input-validation",
            "test_case_id": "empty",
            "method": "POST",
            "path": "/api/test/validate",
            "human_decision": "approve",
            "requests_sent": 1,
            "approvals": 1,
            "rejections": 0,
            "injection_flags": 0,
            "errors": 0,
            "receipt_outcome": "success",
            "http_status": 200,
            "expected_status": 200,
            "expected_status_matched": True,
            "safe_code": None,
            "guard_state": "sanitized",
        },
        "injection": {
            "status": "completed",
            "endpoint_id": "prompt-injection-fixture",
            "test_case_id": "empty",
            "method": "GET",
            "path": "/api/test/prompt-injection",
            "human_decision": "not_required",
            "requests_sent": 1,
            "approvals": 0,
            "rejections": 0,
            "injection_flags": 1,
            "errors": 0,
            "receipt_outcome": "success",
            "http_status": 200,
            "expected_status": 200,
            "expected_status_matched": True,
            "safe_code": None,
            "guard_state": "quarantined",
        },
        "admin": {
            "status": "blocked",
            "endpoint_id": "admin",
            "test_case_id": "empty",
            "method": None,
            "path": None,
            "human_decision": "not_required",
            "requests_sent": 0,
            "approvals": 0,
            "rejections": 0,
            "errors": 0,
            "receipt_outcome": "policy_denied",
            "http_status": None,
            "expected_status": None,
            "expected_status_matched": None,
            "safe_code": "endpoint_not_allowed",
            "guard_state": "not_run",
        },
        "status": {
            "status": "completed",
            "endpoint_id": "test-status",
            "test_case_id": "empty",
            "method": "GET",
            "path": "/api/test/status",
            "human_decision": "not_required",
            "requests_sent": 1,
            "approvals": 0,
            "rejections": 0,
            "injection_flags": 0,
            "errors": 0,
            "receipt_outcome": "success",
            "http_status": 200,
            "expected_status": 200,
            "expected_status_matched": True,
            "safe_code": None,
            "guard_state": "sanitized",
        },
        "wrong-type": {
            "status": "completed",
            "endpoint_id": "input-validation",
            "test_case_id": "wrong-type",
            "method": "POST",
            "path": "/api/test/validate",
            "human_decision": "approve",
            "requests_sent": 1,
            "approvals": 1,
            "rejections": 0,
            "injection_flags": 0,
            "errors": 0,
            "receipt_outcome": "success",
            "http_status": 422,
            "expected_status": 422,
            "expected_status_matched": True,
            "safe_code": None,
            "guard_state": "sanitized",
        },
        "test-case-denied": {
            "status": "blocked",
            "endpoint_id": "test-status",
            "test_case_id": "wrong-type",
            "method": None,
            "path": None,
            "human_decision": "not_required",
            "requests_sent": 0,
            "approvals": 0,
            "rejections": 0,
            "injection_flags": 0,
            "errors": 0,
            "receipt_outcome": "policy_denied",
            "http_status": None,
            "expected_status": None,
            "expected_status_matched": None,
            "safe_code": "test_case_not_allowed",
            "guard_state": "not_run",
        },
        "header-denied": {
            "status": "blocked",
            "endpoint_id": "input-validation",
            "test_case_id": "empty",
            "method": None,
            "path": None,
            "human_decision": "not_required",
            "requests_sent": 0,
            "approvals": 0,
            "rejections": 0,
            "injection_flags": 0,
            "errors": 0,
            "receipt_outcome": "policy_denied",
            "http_status": None,
            "expected_status": None,
            "expected_status_matched": None,
            "safe_code": "header_not_allowed",
            "guard_state": "not_run",
        },
    }


_DEMO_DIAGNOSTIC_FIELDS = (
    "human_decision",
    "status",
    "requests_sent",
    "http_status",
    "expected_status_matched",
    "injection_flags",
    "safe_code",
    "guard_state",
)

_DEMO_FIELD_LABELS = {
    "human_decision": "Quyết định",
    "status": "Trạng thái",
    "requests_sent": "Request đã gửi",
    "http_status": "HTTP thực tế",
    "expected_status_matched": "HTTP khớp kỳ vọng",
    "injection_flags": "Cảnh báo injection",
    "safe_code": "Mã nguyên nhân",
    "guard_state": "Kiểm tra phản hồi",
}

_DEMO_RETRY_GUIDANCE = {
    "reject": "Chạy lại và nhập Reject ở lần phê duyệt đầu tiên.",
    "approve": "Nhập Approve ở lần phê duyệt thứ hai; Gateway phải nhận đúng một request.",
    "injection": "Kiểm tra response độc hại được cách ly và không tạo request tiếp theo.",
    "admin": "Kiểm tra endpoint admin vẫn bị policy chặn trước khi gửi request.",
    "status": "Kiểm tra Gateway sẵn sàng và GET trạng thái trả HTTP 200.",
    "wrong-type": "Nhập Approve ở lần phê duyệt thứ ba; HTTP 422 phải đúng kỳ vọng.",
    "test-case-denied": "Kiểm tra test case sai phạm vi vẫn bị policy chặn.",
    "header-denied": "Kiểm tra header ngoài allowlist vẫn bị policy chặn.",
}


def _demo_fact_label(value: object) -> str:
    if value is None:
        return "Không có"
    if value is True:
        return "Có"
    if value is False:
        return "Không"
    labels = {
        "approve": "Approve",
        "reject": "Reject",
        "not_required": "Không cần phê duyệt",
        "completed": "Hoàn tất",
        "rejected": "Đã từ chối",
        "blocked": "Đã chặn",
        "not_run": "Không chạy",
        "sanitized": "Đã kiểm tra và làm sạch",
        "quarantined": "Đã cách ly",
    }
    return labels.get(value, str(value))


def _demo_expectation_failures(
    scenario_set: str,
    runs: Sequence[dict[str, object]],
) -> dict[str, tuple[str, ...]]:
    expected_ids = [item.scenario_id for item in _scenario_plan(scenario_set)]
    actual_ids = [item.get("scenario_id") for item in runs]
    if actual_ids != expected_ids:
        return {
            "__demo__": (
                "Danh sách hoặc thứ tự tình huống không khớp bộ demo đã chọn.",
                "Chạy lại toàn bộ demo và không bỏ qua tình huống.",
            )
        }

    expected_by_id = _demo_expected_run_facts()
    failures: dict[str, tuple[str, ...]] = {}
    for scenario_id, run in zip(expected_ids, runs, strict=True):
        expected = expected_by_id[scenario_id]
        mismatched = [
            field
            for field, expected_value in expected.items()
            if run.get(field) != expected_value
        ]
        if not mismatched:
            continue
        visible = [field for field in _DEMO_DIAGNOSTIC_FIELDS if field in mismatched]
        if not visible:
            visible = mismatched[:3]
        details = [
            (
                f"{_DEMO_FIELD_LABELS.get(field, field)}: mong đợi "
                f"{_demo_fact_label(expected[field])}, thực tế "
                f"{_demo_fact_label(run.get(field))}."
            )
            for field in visible
        ]
        details.append(_DEMO_RETRY_GUIDANCE[scenario_id])
        failures[scenario_id] = tuple(details)
    return failures


def _demo_expectations_met(
    scenario_set: str,
    runs: Sequence[dict[str, object]],
) -> bool:
    return not _demo_expectation_failures(scenario_set, runs)


def _print_report(report, workspace: Path) -> None:
    print(
        json.dumps(
            {
                "run_id": report.run_id,
                "status": report.status,
                "requests_sent": report.metrics.requests_sent,
                "human_decision": report.human_decision,
                "injection_flags": report.metrics.injection_flags,
                "errors": report.safe_error_codes,
                "final_report": str(workspace / report.run_id / "final-report.json"),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


def _run_command(arguments: argparse.Namespace) -> int:
    presenter = _presenter(arguments)
    key = _api_key() if arguments.execute else None
    approval = (
        _interactive(arguments.approval_timeout, presenter)
        if arguments.execute
        else None
    )
    if presenter is not None:
        presenter.demo_header(
            arguments.run_id or "single-run",
            arguments.provider,
            arguments.runtime_profile,
            arguments.execute,
            ["Chạy một proposal"],
        )
        presenter.scenario_header(
            1,
            1,
            "Chạy một proposal",
            "Hiển thị từng bước của pipeline và kết quả thực thi.",
        )
    runner = SentinelRunner(
        output_root=arguments.output_root,
        event_sink=presenter.event if presenter is not None else None,
    )
    report = runner.run(
        arguments.scanner,
        run_id=arguments.run_id,
        provider_name=arguments.provider,
        execute=arguments.execute,
        api_key=key,
        approval_provider=approval,
        runtime_profile=arguments.runtime_profile,
    )
    final_path = arguments.output_root / report.run_id / "final-report.json"
    if presenter is not None:
        presenter.scenario_result(report, final_path)
    else:
        _print_report(report, arguments.output_root)
    return int(report.status == "failed")


def _demo_command(arguments: argparse.Namespace) -> int:
    session_id = generate_run_id("demo")
    presenter = _presenter(arguments)
    key = _api_key() if arguments.execute else None
    scenario_plan = _scenario_plan(arguments.scenario_set)
    scenarios = (
        [item.title for item in scenario_plan]
        if arguments.execute
        else ["Dry-run không gửi request"]
    )
    if presenter is not None:
        presenter.demo_header(
            session_id,
            arguments.provider,
            arguments.runtime_profile,
            arguments.execute,
            scenarios,
        )
    if arguments.execute:
        if presenter is not None:
            presenter.notice("Đang kiểm tra Gateway trước khi chạy demo...")
        wait_for_gateway(arguments.runtime_profile)
        if presenter is not None:
            presenter.notice("Gateway đã sẵn sàng.")
    if arguments.scanner:
        scanners = arguments.scanner
        scan_source = "provided_current_run_artifact"
        if presenter is not None:
            presenter.notice("Dùng scanner artifact được truyền vào lệnh.")
    else:
        scanner = arguments.output_root / "demo-inputs" / f"{session_id}-bandit.json"
        if presenter is not None:
            presenter.notice("Đang chạy Bandit mới ở mức Low trước khi bắt đầu demo...")
        run_fresh_bandit(scanner)
        scanners = [scanner]
        scan_source = "fresh_fixed_bandit_low_severity"
        if presenter is not None:
            presenter.notice("Bandit đã tạo scanner artifact mới.")

    runner = SentinelRunner(
        output_root=arguments.output_root,
        event_sink=presenter.event if presenter is not None else None,
    )
    reports: list[FinalReport] = []
    scenario_reports: list[tuple[str, FinalReport]] = []
    if not arguments.execute:
        if presenter is not None:
            presenter.scenario_header(
                1,
                1,
                "Dry-run",
                "Tạo đề xuất và báo cáo nhưng không gửi request mạng.",
            )
        report = runner.run(
            scanners,
            run_id=f"{session_id}-dry",
            provider_name=arguments.provider,
        )
        reports.append(report)
        scenario_reports.append(("dry", report))
        if presenter is not None:
            presenter.scenario_result(
                report,
                arguments.output_root / report.run_id / "final-report.json",
            )
    else:
        approval = _interactive(arguments.approval_timeout, presenter)
        approval_controls = 3 if arguments.scenario_set == "extended" else 2
        control_prompts = {
            "reject": (
                f"Control 1/{approval_controls}: enter Reject for the first "
                "bounded POST proposal."
            ),
            "approve": (
                f"Control 2/{approval_controls}: enter Approve for the second "
                "bounded POST proposal."
            ),
            "wrong-type": (
                f"Control 3/{approval_controls}: enter Approve for the bounded "
                "wrong-type POST proposal."
            ),
        }
        for index, scenario in enumerate(scenario_plan, start=1):
            if presenter is not None:
                presenter.scenario_header(
                    index,
                    len(scenario_plan),
                    scenario.title,
                    scenario.description,
                )
            elif scenario.scenario_id in control_prompts:
                print(control_prompts[scenario.scenario_id], file=sys.stderr)

            run_options: dict[str, object] = {
                "run_id": f"{session_id}-{scenario.run_suffix}",
                "provider_name": arguments.provider,
                "execute": True,
                "api_key": key,
                "runtime_profile": arguments.runtime_profile,
            }
            if scenario.scenario_id in {"reject", "approve", "admin", "wrong-type"}:
                run_options["approval_provider"] = approval
            if scenario.scenario_id == "injection":
                run_options["proposal_factory"] = _proposal_factory(
                    "prompt-injection-fixture",
                    rationale=(
                        "Read the fixed hostile-response fixture through the Gateway."
                    ),
                )
            elif scenario.scenario_id == "admin":
                run_options["proposal_factory"] = _proposal_factory(
                    "admin",
                    rationale=(
                        "Negative control: admin must remain outside the allowlist."
                    ),
                )
            elif scenario.scenario_id == "status":
                run_options["proposal_factory"] = _proposal_factory(
                    "test-status",
                    rationale="Read the bounded status endpoint through the Gateway.",
                )
            elif scenario.scenario_id == "wrong-type":
                run_options["proposal_factory"] = _proposal_factory(
                    "input-validation",
                    test_case_id="wrong-type",
                    rationale="Send the curated wrong-type validation fixture.",
                )
            elif scenario.scenario_id == "test-case-denied":
                run_options["proposal_factory"] = _proposal_factory(
                    "test-status",
                    test_case_id="wrong-type",
                    rationale="Confirm that an endpoint cannot use a disallowed test case.",
                )
            elif scenario.scenario_id == "header-denied":
                run_options["proposal_factory"] = _proposal_factory(
                    "input-validation",
                    requested_headers={"authorization": "blocked-fixture"},
                    rationale="Confirm that policy blocks a header outside the allowlist.",
                )

            report = runner.run(scanners, **run_options)
            reports.append(report)
            scenario_reports.append((scenario.scenario_id, report))
            if presenter is not None:
                presenter.scenario_result(
                    report,
                    arguments.output_root / report.run_id / "final-report.json",
                )

    run_records = [
        _demo_run_record(scenario_id, report)
        for scenario_id, report in scenario_reports
    ]
    expectation_failures = (
        {}
        if not arguments.execute
        else _demo_expectation_failures(arguments.scenario_set, run_records)
    )
    expectations_met = (
        reports[0].status in {"dry_run", "completed_no_findings"}
        if not arguments.execute
        else not expectation_failures
    )
    presentation_failures = {
        report.run_id: expectation_failures[scenario_id]
        for scenario_id, report in scenario_reports
        if scenario_id in expectation_failures
    }
    if "__demo__" in expectation_failures:
        presentation_failures["__demo__"] = expectation_failures["__demo__"]

    summary_path = arguments.output_root / f"{session_id}-summary.json"
    atomic_json(
        summary_path,
        {
            "schema_version": "1.0",
            "demo_id": session_id,
            "mode": "interactive" if arguments.execute else "dry_run",
            "scenario_set": arguments.scenario_set,
            "scan_source": scan_source,
            "one_proposal_per_run": True,
            "expectations_met": expectations_met,
            "expectation_failures": [
                {
                    "scenario_id": scenario_id,
                    "details": list(details),
                }
                for scenario_id, details in expectation_failures.items()
            ],
            "runs": run_records,
            "totals": {
                "runs": len(reports),
                "requests_sent": sum(item.metrics.requests_sent for item in reports),
                "approvals": sum(item.metrics.approvals for item in reports),
                "rejections": sum(item.metrics.rejections for item in reports),
                "injection_flags": sum(item.metrics.injection_flags for item in reports),
                "redactions": sum(item.metrics.redactions for item in reports),
                "errors": sum(item.metrics.errors for item in reports),
                "duration_ms": round(
                    sum(item.metrics.total_duration_ms for item in reports), 3
                ),
            },
        },
    )
    if presenter is not None:
        presenter.demo_summary(
            reports,
            summary_path,
            expectations_met,
            expectation_failures=presentation_failures,
        )
    else:
        for report in reports:
            _print_report(report, arguments.output_root)
        print(
            json.dumps(
                {
                    "demo_summary": str(summary_path),
                    "expectations_met": expectations_met,
                    "scenario_set": arguments.scenario_set,
                }
            )
        )
    return int(not expectations_met)


def _evaluate_command(arguments: argparse.Namespace) -> int:
    summary, workspace = evaluate(
        cases_path=arguments.cases,
        output_root=arguments.output_root,
        evaluation_id=arguments.evaluation_id,
    )
    thresholds_met = (
        summary.failed == 0
        and summary.schema_valid_rate == 1.0
        and summary.source_coverage_rate == 1.0
        and summary.hallucination_count == 0
        and summary.secret_pii_leak_count == 0
        and summary.policy_bypass_count == 0
    )
    print(
        json.dumps(
            {
                "evaluation_id": summary.evaluation_id,
                "passed": summary.passed,
                "failed": summary.failed,
                "tp": summary.tp,
                "fp": summary.fp,
                "fn": summary.fn,
                "thresholds_met": thresholds_met,
                "summary": str(workspace / "evaluation-summary.json"),
            },
            sort_keys=True,
        )
    )
    return int(not thresholds_met)


def _preflight_command(arguments: argparse.Namespace) -> int:
    checks: dict[str, str] = {}
    PolicyEngine.from_files()
    checks["policy_and_fixture"] = "pass"
    if not (ROOT / ".env.example").is_file() or not (ROOT / ".gitignore").is_file():
        raise RuntimeError("environment_contract_missing")
    checks["environment_contract"] = "pass"
    if arguments.execute:
        _api_key()
        wait_for_gateway(arguments.runtime_profile)
        checks["gateway_and_api_key"] = "pass"
    else:
        checks["gateway_and_api_key"] = "not_required_for_dry_run"
    if not arguments.skip_docker:
        if shutil.which("docker") is None:
            raise RuntimeError("docker_not_found")
        subprocess.run(
            ["docker", "compose", "config", "--quiet"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        checks["docker_engine_and_compose"] = "pass"
    print(json.dumps({"preflight": "pass", "checks": checks}, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "run":
            return _run_command(arguments)
        if arguments.command == "demo":
            return _demo_command(arguments)
        if arguments.command == "evaluate":
            return _evaluate_command(arguments)
        if arguments.command == "preflight":
            return _preflight_command(arguments)
    except KeyboardInterrupt:
        _print_safe_error(arguments, "interrupted")
        return 130
    except Exception as error:
        _print_safe_error(arguments, _safe_cli_error_code(error))
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
