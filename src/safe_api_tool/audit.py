from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from threading import Lock
from typing import Literal

from pydantic import Field

from safe_api_tool.models import HttpMethod, StrictModel


ExecutionOutcome = Literal[
    "success",
    "unexpected_status",
    "policy_denied",
    "rate_limited",
    "timeout",
    "connection_error",
    "response_truncated",
]

_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_SECRET_NAME = r"(?:password|secret|(?:x-)?api[_-]?key|access[_-]?token)"
_JSON_SECRET_ASSIGNMENT = re.compile(
    rf"(?i)([\"']{_SECRET_NAME}[\"']\s*:\s*[\"'])([^\"']*)([\"'])"
)
_SECRET_ASSIGNMENT = re.compile(
    rf"(?i)\b({_SECRET_NAME})\b(\s*[:=]\s*)([^\s,;&}}]+)"
)


class ExecutionReceipt(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    timestamp: str = Field(min_length=1)
    proposal_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    request_id: str = Field(min_length=1, max_length=128)
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    endpoint_id: str = Field(min_length=1)
    test_case_id: str = Field(min_length=1)
    method: HttpMethod | None
    path: str | None
    requested_header_names: list[str]
    request_bytes: int = Field(ge=0)
    request_sha256: str | None
    expected_status: int | None = Field(default=None, ge=100, le=599)
    expected_status_matched: bool | None
    outcome: ExecutionOutcome
    status_code: int | None = Field(default=None, ge=100, le=599)
    duration_ms: float = Field(ge=0)
    response_bytes: int = Field(ge=0)
    response_sha256: str | None
    response_truncated: bool
    response_excerpt: str | None = Field(default=None, max_length=1024)
    reason: str | None = Field(default=None, max_length=200)


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def redact_text(value: str, *, secrets: tuple[str, ...] = ()) -> str:
    redacted = value
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    redacted = _BEARER_TOKEN.sub("Bearer [REDACTED]", redacted)
    redacted = _JSON_SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}[REDACTED]{match.group(3)}",
        redacted,
    )
    return _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        redacted,
    )


class AuditLogWriter:
    """Append validated receipts without ever accepting credential fields."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = Lock()

    def write(self, receipt: ExecutionReceipt) -> Path:
        line = json.dumps(
            receipt.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8", newline="\n") as output:
            output.write(f"{line}\n")
            output.flush()
            os.fsync(output.fileno())
        return self.path
