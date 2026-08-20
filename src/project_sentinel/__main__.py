from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Callable, Sequence

from rich.console import Console

from project_sentinel.evaluation import evaluate
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
    *,
    rationale: str,
) -> Callable[[AnalysisFinding], RequestProposal]:
    def build(finding: AnalysisFinding) -> RequestProposal:
        return RequestProposal(
            endpoint_id=endpoint_id,
            test_case_id="empty",
            rationale=rationale,
            source_finding_ids=list(finding.source_finding_ids),
            requested_headers={},
        )

    return build


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
    scenarios = (
        [
            "Người dùng từ chối",
            "Người dùng phê duyệt",
            "Prompt injection trong response",
            "Đường dẫn quản trị bị chặn",
        ]
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
    reports = []
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
        if presenter is not None:
            presenter.scenario_result(
                report,
                arguments.output_root / report.run_id / "final-report.json",
            )
        expectations_met = reports[0].status in {"dry_run", "completed_no_findings"}
    else:
        approval = _interactive(arguments.approval_timeout, presenter)
        if presenter is not None:
            presenter.scenario_header(
                1,
                4,
                "Người dùng từ chối",
                "Nhập REJECT để chứng minh pipeline dừng trước transport.",
            )
        else:
            print(
                "Control 1/2: enter Reject for the first bounded POST proposal.",
                file=sys.stderr,
            )
        report = runner.run(
            scanners,
            run_id=f"{session_id}-reject",
            provider_name=arguments.provider,
            execute=True,
            api_key=key,
            approval_provider=approval,
            runtime_profile=arguments.runtime_profile,
        )
        reports.append(report)
        if presenter is not None:
            presenter.scenario_result(
                report,
                arguments.output_root / report.run_id / "final-report.json",
            )

        if presenter is not None:
            presenter.scenario_header(
                2,
                4,
                "Người dùng phê duyệt",
                "Nhập APPROVE để gửi đúng một request an toàn qua Gateway.",
            )
        else:
            print(
                "Control 2/2: enter Approve for the second bounded POST proposal.",
                file=sys.stderr,
            )
        report = runner.run(
            scanners,
            run_id=f"{session_id}-approve",
            provider_name=arguments.provider,
            execute=True,
            api_key=key,
            approval_provider=approval,
            runtime_profile=arguments.runtime_profile,
        )
        reports.append(report)
        if presenter is not None:
            presenter.scenario_result(
                report,
                arguments.output_root / report.run_id / "final-report.json",
            )

        if presenter is not None:
            presenter.scenario_header(
                3,
                4,
                "Prompt injection trong response",
                "Request hợp lệ được gửi; response độc hại phải bị cách ly.",
            )
        report = runner.run(
            scanners,
            run_id=f"{session_id}-injection",
            provider_name=arguments.provider,
            execute=True,
            api_key=key,
            runtime_profile=arguments.runtime_profile,
            proposal_factory=_proposal_factory(
                "prompt-injection-fixture",
                rationale="Read the fixed hostile-response fixture through the Gateway.",
            ),
        )
        reports.append(report)
        if presenter is not None:
            presenter.scenario_result(
                report,
                arguments.output_root / report.run_id / "final-report.json",
            )

        if presenter is not None:
            presenter.scenario_header(
                4,
                4,
                "Đường dẫn quản trị bị chặn",
                "Policy phải chặn /api/admin trước khi mở transport.",
            )
        report = runner.run(
            scanners,
            run_id=f"{session_id}-admin-negative",
            provider_name=arguments.provider,
            execute=True,
            api_key=key,
            approval_provider=approval,
            runtime_profile=arguments.runtime_profile,
            proposal_factory=_proposal_factory(
                "admin",
                rationale="Negative control: admin must remain outside the allowlist.",
            ),
        )
        reports.append(report)
        if presenter is not None:
            presenter.scenario_result(
                report,
                arguments.output_root / report.run_id / "final-report.json",
            )
        expectations_met = (
            reports[0].status == "rejected"
            and reports[0].metrics.requests_sent == 0
            and reports[1].status == "completed"
            and reports[1].metrics.requests_sent == 1
            and reports[2].metrics.injection_flags == 1
            and reports[3].status == "blocked"
            and reports[3].metrics.requests_sent == 0
        )

    summary_path = arguments.output_root / f"{session_id}-summary.json"
    atomic_json(
        summary_path,
        {
            "schema_version": "1.0",
            "demo_id": session_id,
            "mode": "interactive" if arguments.execute else "dry_run",
            "scan_source": scan_source,
            "one_proposal_per_run": True,
            "expectations_met": expectations_met,
            "runs": [
                {
                    "run_id": report.run_id,
                    "status": report.status,
                    "requests_sent": report.metrics.requests_sent,
                    "approvals": report.metrics.approvals,
                    "rejections": report.metrics.rejections,
                    "injection_flags": report.metrics.injection_flags,
                    "errors": report.metrics.errors,
                }
                for report in reports
            ],
            "totals": {
                "runs": len(reports),
                "requests_sent": sum(item.metrics.requests_sent for item in reports),
                "approvals": sum(item.metrics.approvals for item in reports),
                "rejections": sum(item.metrics.rejections for item in reports),
                "injection_flags": sum(item.metrics.injection_flags for item in reports),
                "duration_ms": round(
                    sum(item.metrics.total_duration_ms for item in reports), 3
                ),
            },
        },
    )
    if presenter is not None:
        presenter.demo_summary(reports, summary_path, expectations_met)
    else:
        for report in reports:
            _print_report(report, arguments.output_root)
        print(
            json.dumps(
                {
                    "demo_summary": str(summary_path),
                    "expectations_met": expectations_met,
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
