from __future__ import annotations

import json
from pathlib import Path
import re
from types import SimpleNamespace

import project_sentinel.__main__ as cli_module
from project_sentinel.runner import GatewayPreflightError


main = cli_module.main


SUMMARY_RUN_KEYS = {
    "scenario_id",
    "run_id",
    "status",
    "endpoint_id",
    "test_case_id",
    "method",
    "path",
    "human_decision",
    "requests_sent",
    "approvals",
    "rejections",
    "injection_flags",
    "redactions",
    "errors",
    "receipt_outcome",
    "http_status",
    "expected_status",
    "expected_status_matched",
    "safe_code",
    "guard_state",
}


def _empty_bandit(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "errors": [],
                "generated_at": "2026-08-20T00:00:00Z",
                "metrics": {},
                "results": [],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_demo_scenario_set_defaults_to_core_and_extended_order_is_stable() -> None:
    parser = cli_module._parser()

    core = parser.parse_args(["demo"])
    extended = parser.parse_args(["demo", "--scenario-set", "extended"])

    assert core.scenario_set == "core"
    assert [item.scenario_id for item in cli_module._scenario_plan(core.scenario_set)] == [
        "reject",
        "approve",
        "injection",
        "admin",
    ]
    assert [
        item.scenario_id for item in cli_module._scenario_plan(extended.scenario_set)
    ] == [
        "reject",
        "approve",
        "injection",
        "admin",
        "status",
        "wrong-type",
        "test-case-denied",
        "header-denied",
    ]


def test_proposal_factory_accepts_test_case_and_requested_headers() -> None:
    factory = cli_module._proposal_factory(
        "input-validation",
        "wrong-type",
        {"authorization": "blocked-fixture"},
        rationale="Controlled policy check.",
    )

    proposal = factory(SimpleNamespace(source_finding_ids=["finding-1"]))

    assert proposal.endpoint_id == "input-validation"
    assert proposal.test_case_id == "wrong-type"
    assert proposal.requested_headers == {"authorization": "blocked-fixture"}


def test_demo_summary_run_record_is_complete_and_omits_sensitive_details() -> None:
    report = SimpleNamespace(
        run_id="demo-contract-header-denied",
        status="blocked",
        proposal=SimpleNamespace(
            endpoint_id="input-validation",
            test_case_id="empty",
            rationale="rationale-must-not-print",
            requested_headers={"authorization": "header-value-must-not-print"},
        ),
        execution_receipt=SimpleNamespace(
            endpoint_id="input-validation",
            test_case_id="empty",
            method=None,
            path=None,
            outcome="policy_denied",
            status_code=None,
            expected_status=None,
            expected_status_matched=None,
            reason="header_not_allowed",
            response_excerpt="response-excerpt-must-not-print",
        ),
        guarded_response=None,
        human_decision="not_required",
        safe_error_codes=["fallback-must-not-win"],
        metrics=SimpleNamespace(
            requests_sent=0,
            approvals=0,
            rejections=0,
            injection_flags=0,
            redactions=0,
            errors=0,
        ),
    )

    record = cli_module._demo_run_record("header-denied", report)
    serialized = json.dumps(record)

    assert set(record) == SUMMARY_RUN_KEYS
    assert record["safe_code"] == "header_not_allowed"
    assert record["guard_state"] == "not_run"
    assert "header-value-must-not-print" not in serialized
    assert "response-excerpt-must-not-print" not in serialized
    assert "rationale-must-not-print" not in serialized


def test_demo_json_mode_keeps_machine_readable_output(
    tmp_path: Path,
    capsys,
) -> None:
    scanner = _empty_bandit(tmp_path / "bandit.json")
    output_root = tmp_path / "json-runs"

    exit_code = main(
        [
            "demo",
            "--scanner",
            str(scanner),
            "--output-root",
            str(output_root),
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    records = [json.loads(line) for line in captured.out.splitlines()]
    assert exit_code == 0
    assert captured.err == ""
    assert len(records) == 2
    assert records[0]["status"] == "completed_no_findings"
    assert records[0]["requests_sent"] == 0
    assert records[1]["expectations_met"] is True
    assert "PROJECT SENTINEL" not in captured.out


def test_demo_human_mode_shows_all_eight_steps_without_machine_json(
    tmp_path: Path,
    capsys,
) -> None:
    scanner = _empty_bandit(tmp_path / "bandit.json")

    exit_code = main(
        [
            "demo",
            "--scanner",
            str(scanner),
            "--output-root",
            str(tmp_path / "human-runs"),
            "--format",
            "human",
            "--no-color",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == ""
    assert "PROJECT SENTINEL · DEMO WEEK 6" in captured.err
    assert "TÌNH HUỐNG 1/1" in captured.err
    assert "[1/8]" in captured.err
    assert "[8/8]" in captured.err
    assert "Không chạy" in captured.err
    assert "Request đã gửi" in captured.err
    assert "Kỳ vọng" in captured.err
    assert not re.search(r"\x1b\[[0-9;]*m", captured.err)


def test_human_mode_reports_only_a_safe_error_code(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    scanner = _empty_bandit(tmp_path / "bandit.json")

    def fail_api_key() -> str:
        raise ValueError("sensitive diagnostic details must stay hidden")

    monkeypatch.setattr("project_sentinel.__main__._api_key", fail_api_key)
    exit_code = main(
        [
            "run",
            str(scanner),
            "--output-root",
            str(tmp_path / "failed-runs"),
            "--execute",
            "--format",
            "human",
            "--no-color",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "THẤT BẠI" in captured.err
    assert "value" in captured.err
    assert "sensitive diagnostic details" not in captured.err
    assert str(tmp_path) not in captured.err
    assert "Traceback" not in captured.err


def test_demo_gateway_failure_stops_before_bandit_and_runner(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    sensitive_detail = "socket target and credential must stay hidden"

    def gateway_unavailable(_: str) -> None:
        raise GatewayPreflightError(sensitive_detail)

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("demo work started before gateway readiness passed")

    monkeypatch.setattr(cli_module, "_api_key", lambda: "test-api-key")
    monkeypatch.setattr(cli_module, "wait_for_gateway", gateway_unavailable)
    monkeypatch.setattr(cli_module, "run_fresh_bandit", must_not_run)
    monkeypatch.setattr(cli_module, "SentinelRunner", must_not_run)

    exit_code = main(
        [
            "demo",
            "--execute",
            "--output-root",
            str(tmp_path / "runs"),
            "--format",
            "human",
            "--no-color",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "gateway_preflight_timeout" in captured.err
    assert sensitive_detail not in captured.err
    assert "Traceback" not in captured.err


def test_keyboard_interrupt_returns_130_without_traceback(capsys, monkeypatch) -> None:
    def interrupted(_arguments) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module, "_demo_command", interrupted)

    exit_code = main(["demo", "--format", "human", "--no-color"])

    captured = capsys.readouterr()
    assert exit_code == 130
    assert captured.out == ""
    assert "interrupted" in captured.err
    assert "Traceback" not in captured.err
