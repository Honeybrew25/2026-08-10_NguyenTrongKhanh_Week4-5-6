from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from project_sentinel.contracts import FinalReport, PipelineEvent
from safe_api_tool.approval import ApprovalRequestView
from sentinel_guardrails.redaction import sanitize_data, sanitize_text


_STAGE_LABELS = {
    "scanner_input": "Nhận kết quả quét",
    "normalize": "Chuẩn hóa cảnh báo",
    "analysis": "Phân tích",
    "proposal": "Tạo đề xuất",
    "approval": "Phê duyệt",
    "request": "Gửi qua Gateway",
    "response_guard": "Kiểm tra phản hồi",
    "final_report": "Tạo báo cáo",
    "evaluation": "Đánh giá",
    "cleanup": "Dọn hệ thống",
}

_STAGE_ORDER = (
    "scanner_input",
    "normalize",
    "analysis",
    "proposal",
    "approval",
    "request",
    "response_guard",
    "final_report",
)

_OUTCOME_LABELS = {
    "success": ("Hoàn thành", "green", "✓"),
    "approved": ("Đã phê duyệt", "green", "✓"),
    "rejected": ("Đã từ chối", "yellow", "!"),
    "blocked": ("Đã chặn", "yellow", "!"),
    "failed": ("Thất bại", "red", "✗"),
}

_STATUS_LABELS = {
    "dry_run": ("Mô phỏng hoàn tất", "cyan"),
    "completed": ("Hoàn tất", "green"),
    "completed_no_findings": ("Hoàn tất, không có cảnh báo", "green"),
    "rejected": ("Người dùng từ chối", "yellow"),
    "blocked": ("Policy đã chặn", "yellow"),
    "failed": ("Thất bại", "red"),
}

_DECISION_LABELS = {
    "approve": "Phê duyệt",
    "reject": "Từ chối",
    "not_required": "Không cần phê duyệt",
    "not_requested": "Chưa yêu cầu phê duyệt",
}

_COUNTER_LABELS = {
    "scanner_inputs": "file scan",
    "raw_findings": "cảnh báo gốc",
    "normalized_findings": "sau chuẩn hóa",
    "analysis_groups": "nhóm phân tích",
    "proposals": "đề xuất",
    "approvals": "phê duyệt",
    "rejections": "từ chối",
    "requests_attempted": "request được xử lý",
    "requests_sent": "request đã gửi",
    "injection_flags": "cờ injection",
    "redactions": "dữ liệu đã che",
    "errors": "lỗi",
}

_RECEIPT_OUTCOME_LABELS = {
    "success": "Thành công",
    "unexpected_status": "HTTP status ngoài dự kiến",
    "policy_denied": "Bị policy chặn",
    "rate_limited": "Bị giới hạn tần suất",
    "timeout": "Hết thời gian",
    "connection_error": "Không kết nối được",
    "response_truncated": "Response đã bị cắt theo giới hạn",
}

_SAFE_REASON_LABELS = {
    "approval_rejected": "Người dùng từ chối",
    "endpoint_not_allowed": "Endpoint nằm ngoài allowlist",
    "header_not_allowed": "Header nằm ngoài allowlist",
    "test_case_not_allowed": "Test case không được phép cho endpoint",
}

_INJECTION_REASON_LABELS = {
    "instruction_override": "cố ghi đè chỉ dẫn",
    "secret_exfiltration": "cố lấy thông tin nhạy cảm",
    "out_of_scope_tool_or_endpoint": "yêu cầu tool hoặc endpoint ngoài phạm vi",
}


def resolve_human_output(requested: str, *, stream) -> bool:
    """Resolve ``auto``/``human``/``json`` without assuming a real TTY."""

    mode = requested.strip().casefold()
    if mode == "human":
        return True
    if mode == "json":
        return False
    if mode != "auto":
        raise ValueError("output_format_must_be_auto_human_or_json")
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except (OSError, ValueError):
        return False


def _safe(value: object) -> str:
    return str(sanitize_text(str(value)).value)


def _text(value: object, style: str | None = None) -> Text:
    return Text(_safe(value), style=style)


def _copyable_path(path: Path) -> str:
    """Prefer a short path from the current directory without hiding characters."""

    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (OSError, ValueError):
        return str(path.resolve())


def _scenario_title(scenario: object) -> str:
    if isinstance(scenario, str):
        return _safe(scenario)
    if isinstance(scenario, Mapping):
        for key in ("title", "name", "label", "id"):
            if key in scenario:
                return _safe(scenario[key])
    title = getattr(scenario, "title", None) or getattr(scenario, "name", None)
    if title is not None:
        return _safe(title)
    if isinstance(scenario, Sequence) and not isinstance(scenario, (bytes, bytearray)):
        if scenario:
            return _safe(scenario[0])
    return _safe(scenario)


class TerminalDemoPresenter:
    """Line-oriented, sanitized Rich output for the guided Week 6 demo."""

    def __init__(self, console: Console, verbose: bool = False) -> None:
        self.console = console
        self.verbose = verbose
        self._seen_stages: set[str] = set()

    def _hash(self, value: str | None) -> str:
        if not value:
            return "—"
        safe_value = _safe(value)
        if self.verbose or len(safe_value) <= 16:
            return safe_value
        return f"{safe_value[:12]}…"

    def demo_header(
        self,
        demo_id,
        provider,
        runtime_profile,
        execute,
        scenarios,
    ) -> None:
        scenario_items = list(scenarios)
        mode = (
            Text("THỰC THI CÓ KIỂM SOÁT", style="bold yellow")
            if execute
            else Text("MÔ PHỎNG — KHÔNG GỬI REQUEST", style="bold cyan")
        )
        details = Table.grid(padding=(0, 1))
        details.add_column(style="bold")
        details.add_column()
        details.add_row("Mã demo", _text(demo_id))
        details.add_row("Chế độ", mode)
        details.add_row("Bộ phân tích", _text(provider))
        details.add_row("Môi trường", _text(runtime_profile))
        details.add_row(
            "API key",
            _text("Đã nạp · giá trị được ẩn" if execute else "Không dùng trong dry-run"),
        )
        details.add_row("Số tình huống", _text(len(scenario_items)))
        self.console.print(
            Panel(details, title="PROJECT SENTINEL · DEMO WEEK 6", border_style="blue")
        )
        for index, scenario in enumerate(scenario_items, start=1):
            self.console.print(
                Text.assemble(
                    (f"  {index}. ", "bold blue"),
                    (_scenario_title(scenario), "white"),
                )
            )

    def notice(self, text) -> None:
        self.console.print(
            Text.assemble(("Lưu ý: ", "bold yellow"), (_safe(text), "yellow"))
        )

    def scenario_header(self, index, total, title, description) -> None:
        self._seen_stages = set()
        heading = Text.assemble(
            (f"TÌNH HUỐNG {index}/{total}", "bold blue"),
            (" · ", "dim"),
            (_safe(title), "bold white"),
        )
        self.console.rule(heading, style="blue")
        self.console.print(_text(description, "white"))

    def event(self, event: PipelineEvent) -> None:
        if event.stage == "final_report":
            self._render_skipped_stages()
        outcome, color, marker = _OUTCOME_LABELS.get(
            event.outcome, (_safe(event.outcome), "white", "•")
        )
        stage_label = _STAGE_LABELS.get(event.stage, event.stage)
        if (
            event.stage == "approval"
            and event.outcome == "success"
            and event.counters.get("approvals", 0) == 0
            and event.counters.get("rejections", 0) == 0
        ):
            outcome, color, marker = "Không cần phê duyệt", "cyan", "—"
        if (
            event.stage == "request"
            and event.outcome == "blocked"
            and event.counters.get("requests_sent", 0) == 0
        ):
            stage_label = "Gateway / transport"
            outcome = "Chặn trước transport"
        line = Text()
        if event.stage in _STAGE_ORDER:
            step = _STAGE_ORDER.index(event.stage) + 1
            line.append(f"[{step}/8] ", style="dim")
        line.append(f"{marker} ", style=f"bold {color}")
        line.append(stage_label, style="bold")
        line.append(f" — {outcome}", style=color)
        if event.stage == "final_report":
            line.append(f" · tổng thời gian={event.duration_ms} ms", style="dim")
        elif event.stage == "request":
            line.append(f" · lượt thực thi={event.duration_ms} ms", style="dim")
        elif event.stage not in {"approval", "response_guard"}:
            line.append(f" · {event.duration_ms} ms", style="dim")
        if event.counters:
            counters = ", ".join(
                f"{_COUNTER_LABELS.get(key, _safe(key))}={value}"
                for key, value in sorted(event.counters.items())
            )
            line.append(f" · {counters}", style="cyan")
        if event.safe_error_code:
            line.append(f" · mã={_safe(event.safe_error_code)}", style="yellow")
        self.console.print(line)
        self._seen_stages.add(event.stage)

    def _render_skipped_stages(self) -> None:
        for index, stage in enumerate(_STAGE_ORDER[:-1], start=1):
            if stage in self._seen_stages:
                continue
            self.console.print(
                Text.assemble(
                    (f"[{index}/8] ", "dim"),
                    ("— ", "dim"),
                    (_STAGE_LABELS[stage], "dim"),
                    (" — Không chạy", "dim"),
                )
            )
            self._seen_stages.add(stage)

    def approval_view(
        self,
        view: ApprovalRequestView,
        timeout_seconds: float,
    ) -> None:
        payload: Any = sanitize_data(view.curated_payload).value
        payload_text = (
            "Không có"
            if payload is None
            else json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
        )
        source_ids = "\n".join(_safe(item) for item in view.source_finding_ids) or "—"
        header_names = ", ".join(
            _safe(item) for item in view.requested_header_names
        ) or "Không có"

        request = Table.grid(padding=(0, 1))
        request.add_column(style="bold", no_wrap=True)
        request.add_column(overflow="fold")
        request.add_row("Request", _text(f"{view.method} {view.path}", "bold cyan"))
        request.add_row("Rủi ro", _text(f"{view.method} · cần người dùng phê duyệt"))
        request.add_row("Giới hạn mạng", _text("Tối đa 1 request qua Gateway"))
        request.add_row(
            "Mục đích dễ hiểu",
            _text(
                "Dùng endpoint kiểm thử với payload cố định để thu thêm tín hiệu "
                "an toàn cho cảnh báo đã chọn."
            ),
        )
        request.add_row("Chi tiết từ Agent", _text(view.rationale))
        request.add_row("Payload đã làm sạch", _text(payload_text))
        request.add_row("Tên header", _text(header_names))
        request.add_row("Nguồn cảnh báo", _text(source_ids))
        request.add_row("Môi trường tin cậy", _text(view.trusted_origin_id))
        request.add_row("Proposal ID", _text(self._hash(view.proposal_id), "dim"))
        request.add_row("Policy SHA-256", _text(self._hash(view.policy_sha256), "dim"))
        request.add_row(
            "Request fingerprint",
            _text(self._hash(view.request_fingerprint), "dim"),
        )
        self.console.print(
            Panel(request, title="CẦN QUYẾT ĐỊNH CỦA NGƯỜI DÙNG", border_style="yellow")
        )
        self.console.print(
            Text.assemble(
                ("Gõ chính xác ", "white"),
                ("Approve", "bold green"),
                (" để gửi hoặc ", "white"),
                ("Reject", "bold yellow"),
                (" để dừng. ", "white"),
                (
                    f"Bỏ trống, nhập sai hoặc quá {timeout_seconds:g} giây đều được xem là Reject.",
                    "dim",
                ),
            )
        )
        self.console.print(Text("Quyết định > ", style="bold white"), end="")
        flush = getattr(self.console.file, "flush", None)
        if callable(flush):
            flush()

    def scenario_result(
        self,
        report: FinalReport,
        final_path: Path,
    ) -> None:
        status_label, status_color = _STATUS_LABELS.get(
            report.status, (_safe(report.status), "white")
        )
        metrics = report.metrics
        result = Table.grid(padding=(0, 1))
        result.add_column(style="bold", no_wrap=True)
        result.add_column(overflow="fold")
        result.add_row(
            "Kết quả",
            _text(
                f"{status_label} ({report.status.upper()})",
                f"bold {status_color}",
            ),
        )
        result.add_row("Quyết định", _text(_DECISION_LABELS[report.human_decision]))
        result.add_row("Request đã gửi", _text(metrics.requests_sent, "bold cyan"))
        result.add_row("Approve / Reject", _text(f"{metrics.approvals} / {metrics.rejections}"))
        result.add_row("Cảnh báo injection", _text(metrics.injection_flags))
        result.add_row("Dữ liệu đã che", _text(metrics.redactions))
        result.add_row("Lỗi", _text(metrics.errors, "red" if metrics.errors else "green"))

        receipt = report.execution_receipt
        if receipt is not None:
            request_target = (
                f"{receipt.method} {receipt.path}"
                if receipt.method and receipt.path
                else "Không tạo request hợp lệ"
            )
            result.add_row("Đích", _text(request_target))
            result.add_row("Trạng thái HTTP", _text(receipt.status_code or "—"))
            result.add_row(
                "Kết quả Gateway",
                _text(_RECEIPT_OUTCOME_LABELS.get(receipt.outcome, receipt.outcome)),
            )
            if receipt.reason:
                reason = _SAFE_REASON_LABELS.get(receipt.reason, receipt.reason)
                result.add_row(
                    "Lý do an toàn",
                    _text(f"{reason} ({receipt.reason})", "yellow"),
                )

        guarded = report.guarded_response
        if guarded is not None:
            guard_label = (
                "Đã phát hiện và cách ly"
                if guarded.injection_detected
                else "Đã kiểm tra, không phát hiện injection"
            )
            result.add_row(
                "Response guard",
                _text(guard_label, "yellow" if guarded.injection_detected else "green"),
            )
            if guarded.injection_reasons:
                result.add_row(
                    "Dấu hiệu",
                    _text(
                        ", ".join(
                            _INJECTION_REASON_LABELS.get(reason, reason)
                            for reason in guarded.injection_reasons
                        )
                    ),
                )

        if report.safe_error_codes:
            result.add_row("Mã lỗi an toàn", _text(", ".join(report.safe_error_codes)))
        result.add_row("Báo cáo", _text(final_path))
        self.console.print(
            Panel(result, title=f"KẾT QUẢ · {_safe(report.run_id)}", border_style=status_color)
        )

    def demo_summary(
        self,
        reports: Sequence[FinalReport],
        summary_path: Path,
        expectations_met: bool,
        *,
        expectation_failures: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        failures = expectation_failures or {}
        summary_display_path = _copyable_path(summary_path)
        dashboard_command = (
            'python scripts/build_dashboard_replay.py '
            f'"{summary_display_path}"'
        )
        table = Table(show_header=True, header_style="bold blue", box=None)
        table.add_column("#", justify="right")
        table.add_column("Tình huống")
        table.add_column("Trạng thái")
        table.add_column("Quyết định")
        table.add_column("Request", justify="right")
        table.add_column("Injection", justify="right")
        table.add_column("Lỗi", justify="right")
        table.add_column("Kỳ vọng")

        for index, report in enumerate(reports, start=1):
            status_label, status_color = _STATUS_LABELS.get(
                report.status, (_safe(report.status), "white")
            )
            table.add_row(
                str(index),
                _text(self._run_label(report.run_id)),
                _text(status_label, status_color),
                _text(_DECISION_LABELS[report.human_decision]),
                str(report.metrics.requests_sent),
                str(report.metrics.injection_flags),
                str(report.metrics.errors),
                _text(
                    "CHƯA ĐẠT" if report.run_id in failures else "ĐẠT",
                    "bold red" if report.run_id in failures else "green",
                ),
            )

        totals = Table.grid(padding=(0, 1))
        totals.add_column(style="bold")
        totals.add_column(overflow="fold")
        totals.add_row("Tổng số run", _text(len(reports)))
        totals.add_row(
            "Tổng request đã gửi",
            _text(sum(item.metrics.requests_sent for item in reports)),
        )
        totals.add_row(
            "Tổng phê duyệt / từ chối",
            _text(
                f"{sum(item.metrics.approvals for item in reports)} / "
                f"{sum(item.metrics.rejections for item in reports)}"
            ),
        )
        totals.add_row(
            "Tổng cảnh báo injection",
            _text(sum(item.metrics.injection_flags for item in reports)),
        )
        totals.add_row(
            "Tổng dữ liệu đã che",
            _text(sum(item.metrics.redactions for item in reports)),
        )
        totals.add_row(
            "Tổng lỗi",
            _text(sum(item.metrics.errors for item in reports)),
        )
        totals.add_row(
            "Kỳ vọng",
            _text(
                "Đạt" if expectations_met else "Chưa đạt",
                "bold green" if expectations_met else "bold red",
            ),
        )
        totals.add_row("Tóm tắt", _text(summary_display_path))

        self.console.print(Panel(table, title="TỔNG KẾT DEMO", border_style="blue"))
        self.console.print(totals)
        self.console.print(_text("Lệnh cập nhật dashboard:", "bold"))
        self.console.print(_text(dashboard_command, "cyan"), soft_wrap=True)

        if not expectations_met:
            details = Table.grid(padding=(0, 1))
            details.add_column(style="bold red", no_wrap=True)
            details.add_column(overflow="fold")
            for index, report in enumerate(reports, start=1):
                run_failures = failures.get(report.run_id)
                if not run_failures:
                    continue
                details.add_row(
                    f"{index}.",
                    _text(self._run_label(report.run_id), "bold red"),
                )
                for reason in run_failures:
                    details.add_row("", _text(f"• {reason}"))
            for reason in failures.get("__demo__", ()):
                details.add_row("Demo", _text(f"• {reason}"))
            if not failures:
                details.add_row(
                    "Demo",
                    _text("• Không có chi tiết; xem file tổng kết để kiểm tra."),
                )
            self.console.print(
                Panel(
                    details,
                    title="NGUYÊN NHÂN CHƯA ĐẠT",
                    border_style="red",
                )
            )

        failed_runs = sum(report.run_id in failures for report in reports)
        self.console.print(
            _text(
                (
                    f"DEMO PASS · {len(reports)}/{len(reports)} kỳ vọng đạt"
                    if expectations_met
                    else (
                        f"DEMO CHƯA ĐẠT · {failed_runs}/{len(reports)} "
                        "tình huống lệch kỳ vọng"
                        if failed_runs
                        else "DEMO CHƯA ĐẠT · xem phần nguyên nhân bên trên"
                    )
                ),
                "bold green" if expectations_met else "bold red",
            )
        )

    @staticmethod
    def _run_label(run_id: str) -> str:
        labels = {
            "-test-case-denied": "Test case không được phép",
            "-header-denied": "Header không được phép",
            "-admin-negative": "Đường dẫn admin bị chặn",
            "-wrong-type": "Sai kiểu dữ liệu có kiểm soát",
            "-status": "GET trạng thái không cần phê duyệt",
            "-injection": "Prompt injection bị cách ly",
            "-approve": "Người dùng phê duyệt",
            "-reject": "Người dùng từ chối",
            "-dry": "Mô phỏng không gửi request",
        }
        return next(
            (label for suffix, label in labels.items() if run_id.endswith(suffix)),
            run_id,
        )
