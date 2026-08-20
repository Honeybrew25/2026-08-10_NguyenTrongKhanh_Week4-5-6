from __future__ import annotations

import json
from pathlib import Path
import re

import project_sentinel.__main__ as cli_module
from project_sentinel.runner import GatewayPreflightError


main = cli_module.main


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
