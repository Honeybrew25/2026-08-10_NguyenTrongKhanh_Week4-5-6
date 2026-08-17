from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from queue import Empty, Queue
from threading import Lock, Thread
from typing import Any, Callable, Literal, Protocol
import os
import uuid

from pydantic import Field, field_validator, model_validator

from safe_api_tool.models import MaterializedRequest, RequestProposal, StrictModel
from sentinel_guardrails.redaction import sanitize_data, sanitize_text


ExecutionState = Literal[
    "proposed",
    "validated",
    "pending_approval",
    "approved",
    "rejected",
    "ready_to_execute",
    "executed",
    "blocked",
    "failed",
]
TrustedOriginId = Literal["host", "compose"]
ApprovalChoiceValue = Literal["approve", "reject"]

TRUSTED_RUNTIME_ORIGINS: dict[TrustedOriginId, str] = {
    "host": "http://localhost:8080",
    "compose": "http://envoy:8080",
}

_TRANSITIONS: dict[ExecutionState, frozenset[ExecutionState]] = {
    "proposed": frozenset({"validated", "blocked", "failed"}),
    "validated": frozenset({"ready_to_execute", "pending_approval", "blocked", "failed"}),
    "pending_approval": frozenset({"approved", "rejected", "blocked", "failed"}),
    "approved": frozenset({"ready_to_execute", "blocked", "failed"}),
    "ready_to_execute": frozenset({"executed", "blocked", "failed"}),
    "rejected": frozenset(),
    "executed": frozenset(),
    "blocked": frozenset(),
    "failed": frozenset(),
}


class StateTransitionError(ValueError):
    pass


class ApprovalValidationError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ExecutionStateMachine:
    def __init__(self) -> None:
        self.state: ExecutionState = "proposed"
        self.history: list[ExecutionState] = [self.state]

    def transition(self, target: ExecutionState) -> None:
        if target not in _TRANSITIONS[self.state]:
            raise StateTransitionError(f"invalid_transition:{self.state}:{target}")
        self.state = target
        self.history.append(target)


class RiskDecision(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    requires_approval: bool
    reason: Literal["post_method", "curated_payload", "no_payload_get"]
    method: Literal["GET", "POST"]
    test_case_id: str = Field(min_length=1)


class ApprovalRequestView(StrictModel):
    run_id: str = Field(min_length=1, max_length=128)
    proposal_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    trusted_origin_id: TrustedOriginId
    request_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    method: Literal["GET", "POST"]
    path: str = Field(pattern=r"^/api/test/")
    curated_payload: dict[str, Any] | None
    requested_header_names: list[str]
    rationale: str = Field(min_length=1, max_length=500)
    source_finding_ids: list[str]


class ApprovalDecision(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    approval_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    run_id: str = Field(min_length=1, max_length=128)
    proposal_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    trusted_origin_id: TrustedOriginId
    request_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    decision: ApprovalChoiceValue
    timestamp: str = Field(min_length=1)
    expires_at: str = Field(min_length=1)
    used: bool
    approver_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=200)

    @field_validator("timestamp", "expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: str) -> str:
        parsed = _parse_timestamp(value)
        if parsed.utcoffset() != timedelta(0):
            raise ValueError("approval timestamps must use UTC")
        return value

    @model_validator(mode="after")
    def expiry_must_follow_issue_time(self) -> "ApprovalDecision":
        if _parse_timestamp(self.expires_at) <= _parse_timestamp(self.timestamp):
            raise ValueError("approval expiry must follow timestamp")
        return self


class GuardedResponse(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    response_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    run_id: str = Field(min_length=1, max_length=128)
    request_id: str = Field(min_length=1, max_length=128)
    trust_label: Literal["untrusted_http_response"] = "untrusted_http_response"
    status_code: int = Field(ge=100, le=599)
    response_bytes: int = Field(ge=0)
    response_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_truncated: bool
    sanitized_excerpt: str | None = Field(default=None, max_length=1024)
    injection_detected: bool
    injection_reasons: list[
        Literal[
            "instruction_override",
            "secret_exfiltration",
            "out_of_scope_tool_or_endpoint",
        ]
    ]
    redaction_summary: dict[str, int]

    @model_validator(mode="after")
    def injection_fields_must_agree(self) -> "GuardedResponse":
        if self.injection_detected != bool(self.injection_reasons):
            raise ValueError("injection flag must match reasons")
        if any(value < 0 for value in self.redaction_summary.values()):
            raise ValueError("redaction counts cannot be negative")
        return self


class RunEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    run_id: str = Field(min_length=1, max_length=128)
    timestamp: str = Field(min_length=1)
    stage: Literal[
        "validate",
        "risk_classification",
        "approval",
        "policy_recheck",
        "execute",
        "response_guard",
    ]
    outcome: Literal["success", "approved", "rejected", "blocked", "failed"]
    duration_ms: float = Field(ge=0)
    safe_error_code: str | None = Field(default=None, max_length=100)
    counters: dict[str, int]
    related_ids: list[str]

    @model_validator(mode="after")
    def counters_must_be_non_negative(self) -> "RunEvent":
        if any(value < 0 for value in self.counters.values()):
            raise ValueError("event counters cannot be negative")
        return self


@dataclass(frozen=True)
class ApprovalChoice:
    decision: ApprovalChoiceValue
    reason: str
    approver_id: str


class ApprovalProvider(Protocol):
    def request(self, view: ApprovalRequestView) -> ApprovalChoice: ...


class StaticApprovalProvider:
    """Explicit test-only provider; product CLI never constructs it."""

    def __init__(
        self,
        decision: ApprovalChoiceValue,
        *,
        reason: str = "test_decision",
        approver_id: str = "controlled-test-provider",
    ) -> None:
        self.choice = ApprovalChoice(decision, reason, approver_id)
        self.views: list[ApprovalRequestView] = []

    def request(self, view: ApprovalRequestView) -> ApprovalChoice:
        self.views.append(view)
        return self.choice


class InteractiveApprovalProvider:
    def __init__(
        self,
        *,
        timeout_seconds: float = 60.0,
        input_fn: Callable[[], str] = input,
        output_fn: Callable[[str], None] = print,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.input_fn = input_fn
        self.output_fn = output_fn

    def request(self, view: ApprovalRequestView) -> ApprovalChoice:
        self.output_fn(
            json.dumps(
                view.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
        )
        self.output_fn("Decision required: type Approve or Reject")
        responses: Queue[tuple[bool, str]] = Queue(maxsize=1)

        def read() -> None:
            try:
                responses.put((True, self.input_fn()), block=False)
            except (EOFError, OSError):
                responses.put((False, ""), block=False)

        Thread(target=read, daemon=True).start()
        try:
            ok, raw = responses.get(timeout=max(0.01, self.timeout_seconds))
        except Empty:
            return ApprovalChoice("reject", "approval_timeout", "interactive-user")
        normalized = raw.strip().casefold() if ok else ""
        if normalized == "approve":
            return ApprovalChoice("approve", "interactive_approve", "interactive-user")
        if normalized == "reject":
            return ApprovalChoice("reject", "interactive_reject", "interactive-user")
        reason = "approval_eof" if not ok else "approval_invalid_input"
        return ApprovalChoice("reject", reason, "interactive-user")


class ContractJsonlWriter:
    """Append sanitized strict contract models as durable JSONL."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = Lock()

    def write(self, record: StrictModel) -> Path:
        sanitized = sanitize_data(record.model_dump(mode="json"))
        validated = type(record).model_validate(sanitized.value)
        line = json.dumps(
            validated.model_dump(mode="json"),
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


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def utc_timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def classify_risk(request: MaterializedRequest) -> RiskDecision:
    if request.method == "POST":
        return RiskDecision(
            requires_approval=True,
            reason="post_method",
            method=request.method,
            test_case_id=request.test_case_id,
        )
    if request.payload is not None:
        return RiskDecision(
            requires_approval=True,
            reason="curated_payload",
            method=request.method,
            test_case_id=request.test_case_id,
        )
    return RiskDecision(
        requires_approval=False,
        reason="no_payload_get",
        method=request.method,
        test_case_id=request.test_case_id,
    )


def request_fingerprint(
    request: MaterializedRequest,
    *,
    policy_sha256: str,
    trusted_origin_id: TrustedOriginId,
) -> str:
    document = {
        "policy_sha256": policy_sha256,
        "trusted_origin_id": trusted_origin_id,
        "trusted_origin": TRUSTED_RUNTIME_ORIGINS[trusted_origin_id],
        **request.model_dump(mode="json"),
    }
    canonical = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def approval_view(
    proposal: RequestProposal,
    request: MaterializedRequest,
    *,
    run_id: str,
    proposal_id: str,
    policy_sha256: str,
    trusted_origin_id: TrustedOriginId,
) -> ApprovalRequestView:
    payload = sanitize_data(request.payload).value if request.payload is not None else None
    rationale = sanitize_text(proposal.rationale).value
    return ApprovalRequestView(
        run_id=run_id,
        proposal_id=proposal_id,
        policy_sha256=policy_sha256,
        trusted_origin_id=trusted_origin_id,
        request_fingerprint=request_fingerprint(
            request,
            policy_sha256=policy_sha256,
            trusted_origin_id=trusted_origin_id,
        ),
        method=request.method,
        path=request.path,
        curated_payload=payload,
        requested_header_names=sorted(request.headers),
        rationale=rationale,
        source_finding_ids=[
            str(sanitize_text(finding_id).value)
            for finding_id in proposal.source_finding_ids
        ],
    )


def issue_approval(
    view: ApprovalRequestView,
    choice: ApprovalChoice,
    *,
    now: datetime,
    ttl_seconds: int = 120,
    approval_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
) -> ApprovalDecision:
    safe_reason = sanitize_text(choice.reason).value[:200] or "approval_reason_unavailable"
    safe_approver = sanitize_text(choice.approver_id).value[:64] or "unknown-approver"
    return ApprovalDecision(
        approval_id=approval_id_factory(),
        run_id=view.run_id,
        proposal_id=view.proposal_id,
        policy_sha256=view.policy_sha256,
        trusted_origin_id=view.trusted_origin_id,
        request_fingerprint=view.request_fingerprint,
        decision=choice.decision,
        timestamp=utc_timestamp(now),
        expires_at=utc_timestamp(now + timedelta(seconds=ttl_seconds)),
        used=False,
        approver_id=safe_approver,
        reason=safe_reason,
    )


class ApprovalRegistry:
    def __init__(self) -> None:
        self._used_ids: set[str] = set()
        self._lock = Lock()

    def consume(
        self,
        decision: ApprovalDecision,
        view: ApprovalRequestView,
        *,
        now: datetime,
    ) -> ApprovalDecision:
        expected = {
            "run_id": view.run_id,
            "proposal_id": view.proposal_id,
            "policy_sha256": view.policy_sha256,
            "trusted_origin_id": view.trusted_origin_id,
            "request_fingerprint": view.request_fingerprint,
        }
        for field, value in expected.items():
            if getattr(decision, field) != value:
                raise ApprovalValidationError(f"approval_{field}_mismatch")
        if decision.decision != "approve":
            raise ApprovalValidationError("approval_rejected")
        if decision.used:
            raise ApprovalValidationError("approval_already_used")
        if _parse_timestamp(decision.expires_at) <= now.astimezone(timezone.utc):
            raise ApprovalValidationError("approval_expired")
        with self._lock:
            if decision.approval_id in self._used_ids:
                raise ApprovalValidationError("approval_already_used")
            self._used_ids.add(decision.approval_id)
        return decision.model_copy(update={"used": True})
