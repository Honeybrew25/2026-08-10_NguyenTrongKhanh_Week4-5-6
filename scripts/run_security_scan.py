from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SCAN_TARGETS = ("app", "authz_service", "scripts", "security_pipeline")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the pinned Bandit SAST scan and write JSON."
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--severity-level",
        choices=("low", "medium", "high"),
        default="low",
        help="Minimum finding severity to report and use for Bandit's exit code.",
    )
    args = parser.parse_args()

    output_path = args.output
    if not output_path.is_absolute():
        output_path = ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        "-m",
        "bandit",
        "--recursive",
        *SCAN_TARGETS,
        "--format",
        "json",
        "--severity-level",
        args.severity_level,
        "--output",
        str(output_path),
    ]
    result = subprocess.run(command, cwd=ROOT, check=False)
    if output_path.is_file():
        print(f"Bandit JSON: {output_path}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
