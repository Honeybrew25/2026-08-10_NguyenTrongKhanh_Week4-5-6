from __future__ import annotations

import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose"]
DEMO_AUDIT = (
    ROOT
    / "security-results"
    / "runs"
    / "week-4"
    / "safe-api-demo-ci.jsonl"
)
SECRET_NAMES = (
    "KEYCLOAK_ADMIN_PASSWORD",
    "AGENT_READER_CLIENT_SECRET",
    "AGENT_ADMIN_CLIENT_SECRET",
    "INTEGRATION_EXPIRED_CLIENT_SECRET",
    "INTEGRATION_WRONG_AUDIENCE_CLIENT_SECRET",
    "SAFE_API_TOOL_API_KEY",
)


def run(
    arguments: list[str],
    *,
    environment: dict[str, str],
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=ROOT,
        env=environment,
        check=check,
        text=True,
    )


def wait_for_envoy() -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with urlopen("http://localhost:8080/health", timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, URLError):
            time.sleep(0.5)
    raise RuntimeError("Envoy did not become ready within 30 seconds")


def main() -> int:
    environment = os.environ.copy()
    environment["KEYCLOAK_ADMIN_USERNAME"] = "integration-admin"
    environment["RUN_INTEGRATION_TESTS"] = "1"
    for name in SECRET_NAMES:
        environment[name] = secrets.token_urlsafe(32)

    run([*COMPOSE, "down", "--remove-orphans"], environment=environment)
    try:
        run(
            [
                *COMPOSE,
                "up",
                "--build",
                "--detach",
                "--wait",
                "--wait-timeout",
                "180",
            ],
            environment=environment,
        )
        wait_for_envoy()
        result = run(
            [sys.executable, "-m", "pytest", "-q"],
            environment=environment,
            check=False,
        )
        if result.returncode:
            run(
                [*COMPOSE, "logs", "--no-color", "--tail", "200"],
                environment=environment,
                check=False,
            )
            return result.returncode

        DEMO_AUDIT.unlink(missing_ok=True)
        demo = run(
            [
                sys.executable,
                "-m",
                "safe_api_tool",
                "demo",
                "--execute",
                "--audit",
                str(DEMO_AUDIT),
            ],
            environment=environment,
            check=False,
        )
        if demo.returncode:
            run(
                [*COMPOSE, "logs", "--no-color", "--tail", "200"],
                environment=environment,
                check=False,
            )
        return demo.returncode
    finally:
        run(
            [*COMPOSE, "down", "--remove-orphans"],
            environment=environment,
            check=False,
        )


if __name__ == "__main__":
    raise SystemExit(main())
