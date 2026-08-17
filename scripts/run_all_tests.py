from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose"]
DEMO_DIRECTORY = ROOT / "security-results" / "runs" / "week-5"
DEMO_AUDIT = (
    ROOT
    / "security-results"
    / "runs"
    / "week-5"
    / "safe-api-demo-ci.jsonl"
)
DEMO_APPROVALS = DEMO_DIRECTORY / "approval-decisions-ci.jsonl"
DEMO_GUARDED_RESPONSES = DEMO_DIRECTORY / "guarded-responses-ci.jsonl"
DEMO_EVENTS = DEMO_DIRECTORY / "run-events-ci.jsonl"
WEEK6_DIRECTORY = ROOT / "security-results" / "runs" / "week-6"
DEMO_CONTRACTS = (
    (DEMO_AUDIT, ROOT / "schemas" / "safe-api-log.schema.json"),
    (DEMO_APPROVALS, ROOT / "schemas" / "safe-api-approval.schema.json"),
    (
        DEMO_GUARDED_RESPONSES,
        ROOT / "schemas" / "safe-api-guarded-response.schema.json",
    ),
    (DEMO_EVENTS, ROOT / "schemas" / "safe-api-run-event.schema.json"),
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
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=ROOT,
        env=environment,
        check=check,
        text=True,
        input=input_text,
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


def verify_demo_artifacts() -> None:
    """Fail CI before upload if generated contracts or data minimization fail."""
    documents: dict[Path, list[dict[str, object]]] = {}
    combined = ""
    for artifact, schema_path in DEMO_CONTRACTS:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        records = [
            json.loads(line)
            for line in artifact.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        for record in records:
            Draft202012Validator(schema).validate(record)
        documents[artifact] = records
        combined += artifact.read_text(encoding="utf-8")

    receipts = documents[DEMO_AUDIT]
    approvals = documents[DEMO_APPROVALS]
    receipt_results = [
        (item.get("outcome"), item.get("reason")) for item in receipts
    ]
    approval_results = [
        (item.get("decision"), item.get("used")) for item in approvals
    ]
    if receipt_results != [
        ("success", None),
        ("policy_denied", "approval_rejected"),
        ("success", None),
        ("policy_denied", "endpoint_not_allowed"),
    ]:
        raise RuntimeError("Safe API demo receipt sequence did not match contract")
    if approval_results != [("reject", True), ("approve", True)]:
        raise RuntimeError("Safe API demo approval sequence did not match contract")
    if len({item.get("run_id") for item in approvals}) != 2:
        raise RuntimeError("Reject and Approve must use separate run IDs")

    unsafe_patterns = {
        "email": re.compile(
            r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])",
            re.I,
        ),
        "phone": re.compile(r"(?<!\w)(?:\+?84|0)(?:[ .-]?\d){9,10}(?!\w)"),
        "bearer": re.compile(r"Bearer\s+\S+", re.I),
        "secret_assignment": re.compile(
            r"(?:api[_-]?key|password|access[_-]?token)\s*[:=]\s*"
            r"(?!\[REDACTED_)[^\s,}\]]+",
            re.I,
        ),
        "jwt": re.compile(
            r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
        ),
    }
    matches = [
        name for name, pattern in unsafe_patterns.items() if pattern.search(combined)
    ]
    if matches:
        raise RuntimeError(
            "Generated Safe API artifacts failed the secret/PII sentinel: "
            + ",".join(matches)
        )
    print("Safe API JSONL schemas, cross-contract checks and sentinel: PASS")


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

        for artifact in (
            DEMO_AUDIT,
            DEMO_APPROVALS,
            DEMO_GUARDED_RESPONSES,
            DEMO_EVENTS,
        ):
            artifact.unlink(missing_ok=True)
        demo = run(
            [
                sys.executable,
                "-m",
                "safe_api_tool",
                "demo",
                "--execute",
                "--audit",
                str(DEMO_AUDIT),
                "--approval-log",
                str(DEMO_APPROVALS),
                "--guarded-response-log",
                str(DEMO_GUARDED_RESPONSES),
                "--event-log",
                str(DEMO_EVENTS),
            ],
            environment=environment,
            check=False,
            input_text="Reject\nApprove\n",
        )
        if demo.returncode:
            run(
                [*COMPOSE, "logs", "--no-color", "--tail", "200"],
                environment=environment,
                check=False,
            )
        else:
            verify_demo_artifacts()
        if demo.returncode:
            return demo.returncode

        week6_demo = run(
            [
                sys.executable,
                "-m",
                "project_sentinel",
                "demo",
                "--scanner",
                str(ROOT / "security-results" / "bandit-baseline.json"),
                "--provider",
                "deterministic",
                "--execute",
                "--output-root",
                str(WEEK6_DIRECTORY),
            ],
            environment=environment,
            check=False,
            input_text="Reject\nApprove\n",
        )
        if week6_demo.returncode:
            run(
                [*COMPOSE, "logs", "--no-color", "--tail", "200"],
                environment=environment,
                check=False,
            )
        return week6_demo.returncode
    finally:
        run(
            [*COMPOSE, "down", "--remove-orphans"],
            environment=environment,
            check=False,
        )


if __name__ == "__main__":
    raise SystemExit(main())
