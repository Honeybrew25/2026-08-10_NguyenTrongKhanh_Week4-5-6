from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from project_sentinel.dashboard_replay import ReplayValidationError, update_dashboard_replay


ROOT = Path(__file__).resolve().parents[1]


def _use_utf8_stdout() -> None:
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a sanitized eight-scenario dashboard replay from one "
            "extended demo summary."
        )
    )
    parser.add_argument("demo_summary", type=Path)
    parser.add_argument(
        "--dashboard-data",
        type=Path,
        default=ROOT / "src" / "app" / "static" / "dashboard-data.json",
    )
    parser.add_argument(
        "--snapshot-output",
        type=Path,
        default=(
            ROOT
            / "security-results"
            / "runs"
            / "week-6"
            / "golden"
            / "dashboard-replay.json"
        ),
    )
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=("human", "json"),
        default="human",
        help="Use human output for the terminal or json for automation.",
    )
    arguments = parser.parse_args(argv)
    try:
        snapshot = update_dashboard_replay(
            arguments.demo_summary,
            dashboard_path=arguments.dashboard_data,
            snapshot_path=arguments.snapshot_output,
        )
    except ReplayValidationError as error:
        print(f"dashboard_replay_error:{error}", file=sys.stderr)
        return 1
    except json.JSONDecodeError:
        print("dashboard_replay_error:invalid_json", file=sys.stderr)
        return 1
    except UnicodeError:
        print("dashboard_replay_error:invalid_encoding", file=sys.stderr)
        return 1
    except OSError:
        print("dashboard_replay_error:io_error", file=sys.stderr)
        return 1
    result = {
        "dashboard_replay": "updated",
        "demo_id": snapshot["demo_id"],
        "scenarios": len(snapshot["scenario_ids"]),
        "dashboard_data": str(arguments.dashboard_data),
        "snapshot": str(arguments.snapshot_output),
    }
    if arguments.output_format == "json":
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        _use_utf8_stdout()
        print("DASHBOARD ĐÃ CẬP NHẬT")
        print(f"Demo: {result['demo_id']}")
        print(f"Tình huống: {result['scenarios']}/8")
        print(f"Dữ liệu giao diện: {result['dashboard_data']}")
        print(f"Bản kiểm chứng: {result['snapshot']}")
        print()
        print("Để xem dữ liệu mới:")
        print("  docker compose up --build --detach --wait --wait-timeout 180")
        print("  Mở http://localhost:8080/ui/ rồi nhấn Ctrl+F5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
