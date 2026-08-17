from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from threading import Lock
import time
from typing import Callable
import uuid

import httpx

from safe_api_tool.approval import (
    ApprovalChoice,
    ApprovalDecision,
    ApprovalProvider,
    ApprovalRegistry,
    ApprovalValidationError,
    ContractJsonlWriter,
    ExecutionStateMachine,
    GuardedResponse,
    RiskDecision,
    RunEvent,
    TRUSTED_RUNTIME_ORIGINS,
    TrustedOriginId,
    approval_view,
    classify_risk,
    issue_approval,
    utc_timestamp,
)
from safe_api_tool.audit import AuditLogWriter, ExecutionOutcome, ExecutionReceipt
from safe_api_tool.models import MaterializedRequest, RequestProposal
from safe_api_tool.policy import PolicyEngine, ROOT
from sentinel_guardrails.prompt_injection import detect_prompt_injection
from sentinel_guardrails.redaction import REDACTED_API_KEY, sanitize_text


QUARANTINED_RESPONSE = "[QUARANTINED_UNTRUSTED_HTTP_RESPONSE]"


class ClientConfigurationError(ValueError):
    pass


class ResponseGuardError(RuntimeError):
    def __init__(self, reason: str = "response_guard_failed") -> None:
        super().__init__(reason)
        self.reason = reason


def _canonical_payload(payload: dict[str, object] | None) -> bytes | None:
    if payload is None:
        return None
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: bytes | None) -> str | None:
    return None if value is None else hashlib.sha256(value).hexdigest()


def proposal_id(proposal: RequestProposal) -> str:
    canonical = json.dumps(
        proposal.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:16]


def _redact_truncated_secret_suffix(value: str, secret: str) -> str:
    maximum = min(len(value), max(0, len(secret) - 1))
    for length in range(maximum, 0, -1):
        if value.endswith(secret[:length]):
            return f"{value[:-length]}{REDACTED_API_KEY}"
    return value


def load_api_key(
    environment_variable: str,
    *,
    env_file: Path = ROOT / ".env",
) -> str:
    value = os.getenv(environment_variable)
    if not value and env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            name, candidate = stripped.split("=", 1)
            if name.strip() == environment_variable:
                value = candidate.strip().strip("\"'")
                break
    if (
        not value
        or value.startswith("replace-with-")
        or value.strip() != value
        or not value.isascii()
        or not value.isprintable()
        or not 32 <= len(value.encode("ascii")) <= 512
    ):
        raise ClientConfigurationError(
            f"{environment_variable} must contain a 32+ byte non-placeholder key"
        )
    return value


class LocalRateLimiter:
    def __init__(
        self,
        requests_per_minute: int,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = requests_per_minute
        self._clock = clock
        self._buckets: dict[tuple[str, str], tuple[int, int]] = defaultdict(
            lambda: (-1, 0)
        )
        self._lock = Lock()

    def allow(self, method: str, path: str) -> bool:
        window = int(max(0.0, self._clock()) // 60)
        key = (method, path)
        with self._lock:
            bucket_window, count = self._buckets[key]
            if bucket_window != window:
                count = 0
            if count >= self._limit:
                self._buckets[key] = (window, count)
                return False
            self._buckets[key] = (window, count + 1)
            return True


def guard_http_response(
    response_body: bytes,
    *,
    run_id: str,
    request_id: str,
    status_code: int,
    response_truncated: bool,
    api_key: str,
    response_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
) -> GuardedResponse:
    decoded = response_body.decode("utf-8", errors="replace")
    if response_truncated:
        decoded = _redact_truncated_secret_suffix(decoded, api_key)
    signal = detect_prompt_injection(decoded)
    redaction = sanitize_text(decoded, api_keys=(api_key,))
    excerpt = QUARANTINED_RESPONSE if signal.detected else str(redaction.value)[:1024]
    return GuardedResponse(
        response_id=response_id_factory(),
        run_id=run_id,
        request_id=request_id,
        status_code=status_code,
        response_bytes=len(response_body),
        response_sha256=hashlib.sha256(response_body).hexdigest(),
        response_truncated=response_truncated,
        sanitized_excerpt=excerpt,
        injection_detected=signal.detected,
        injection_reasons=list(signal.reasons),
        redaction_summary=redaction.counts,
    )


class SafeApiClient:
    def __init__(
        self,
        engine: PolicyEngine,
        *,
        api_key: str,
        audit_writer: AuditLogWriter | None = None,
        approval_writer: ContractJsonlWriter | None = None,
        guarded_response_writer: ContractJsonlWriter | None = None,
        event_writer: ContractJsonlWriter | None = None,
        approval_provider: ApprovalProvider | None = None,
        runtime_profile: TrustedOriginId = "host",
        transport: httpx.BaseTransport | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        request_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
        run_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
        event_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
        response_guard: Callable[..., GuardedResponse] = guard_http_response,
    ) -> None:
        if (
            not api_key.isascii()
            or not api_key.isprintable()
            or not 32 <= len(api_key.encode("ascii")) <= 512
            or api_key.strip() != api_key
            or api_key.startswith("replace-with-")
        ):
            raise ClientConfigurationError("api_key must contain 32 to 512 ASCII bytes")
        if runtime_profile not in TRUSTED_RUNTIME_ORIGINS:
            raise ClientConfigurationError("runtime_profile must be host or compose")
        if not callable(response_guard):
            raise ClientConfigurationError("response_guard must be callable")
        self.engine = engine
        self.gateway_origin = TRUSTED_RUNTIME_ORIGINS[runtime_profile]
        self.trusted_origin_id = runtime_profile
        self._api_key = api_key
        self._audit_writer = audit_writer
        self._approval_writer = approval_writer
        self._guarded_response_writer = guarded_response_writer
        self._event_writer = event_writer
        self._approval_provider = approval_provider
        self._clock = monotonic_clock
        self._wall_clock = wall_clock
        self._request_id_factory = request_id_factory
        self._run_id_factory = run_id_factory
        self._event_id_factory = event_id_factory
        self._response_guard = response_guard
        self._approval_registry = ApprovalRegistry()
        self._run_ids: set[str] = set()
        self._run_ids_lock = Lock()
        self._rate_limiter = LocalRateLimiter(
            engine.policy.limits.requests_per_minute,
            clock=monotonic_clock,
        )
        self.last_approval: ApprovalDecision | None = None
        self.last_guarded_response: GuardedResponse | None = None
        self.last_risk_decision: RiskDecision | None = None
        self.last_receipt: ExecutionReceipt | None = None
        self.last_events: list[RunEvent] = []
        timeout = engine.policy.limits.timeout_seconds
        self._http = httpx.Client(
            base_url=self.gateway_origin,
            timeout=httpx.Timeout(timeout, connect=timeout, read=timeout, write=timeout),
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    def __enter__(self) -> "SafeApiClient":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def dry_run(self, proposal: RequestProposal):
        return self.engine.decide(proposal)

    def _finish(self, receipt: ExecutionReceipt) -> ExecutionReceipt:
        self.last_receipt = receipt
        if self._audit_writer is not None:
            self._audit_writer.write(receipt)
        return receipt

    def _emit(
        self,
        run_id: str,
        stage: str,
        outcome: str,
        *,
        started: float,
        safe_error_code: str | None = None,
        counters: dict[str, int] | None = None,
        related_ids: list[str] | None = None,
    ) -> RunEvent:
        event = RunEvent(
            event_id=self._event_id_factory(),
            run_id=run_id,
            timestamp=utc_timestamp(self._wall_clock()),
            stage=stage,
            outcome=outcome,
            duration_ms=round(max(0.0, self._clock() - started) * 1000, 3),
            safe_error_code=safe_error_code,
            counters=counters or {},
            related_ids=related_ids or [],
        )
        self.last_events.append(event)
        if self._event_writer is not None:
            self._event_writer.write(event)
        return event

    def _write_approval(self, decision: ApprovalDecision) -> None:
        self.last_approval = decision
        if self._approval_writer is not None:
            self._approval_writer.write(decision)

    def _write_guarded_response(self, response: GuardedResponse) -> None:
        self.last_guarded_response = response
        if self._guarded_response_writer is not None:
            self._guarded_response_writer.write(response)

    def _receipt(
        self,
        *,
        proposal: RequestProposal,
        request_id: str,
        request: MaterializedRequest | None,
        started: float,
        outcome: ExecutionOutcome,
        status_code: int | None = None,
        response_body: bytes | None = None,
        response_truncated: bool = False,
        response_excerpt: str | None = None,
        reason: str | None = None,
    ) -> ExecutionReceipt:
        body = _canonical_payload(request.payload) if request is not None else None
        expected_status = request.expected_status if request is not None else None
        expected_match = (
            None
            if expected_status is None or status_code is None
            else status_code == expected_status
        )
        return ExecutionReceipt(
            timestamp=utc_timestamp(self._wall_clock()),
            proposal_id=proposal_id(proposal),
            request_id=request_id,
            policy_sha256=self.engine.policy_sha256,
            endpoint_id=str(sanitize_text(proposal.endpoint_id).value),
            test_case_id=str(sanitize_text(proposal.test_case_id).value),
            method=request.method if request is not None else None,
            path=request.path if request is not None else None,
            requested_header_names=sorted(proposal.requested_headers),
            request_bytes=len(body or b""),
            request_sha256=_digest(body),
            expected_status=expected_status,
            expected_status_matched=expected_match,
            outcome=outcome,
            status_code=status_code,
            duration_ms=round(max(0.0, self._clock() - started) * 1000, 3),
            response_bytes=len(response_body or b""),
            response_sha256=_digest(response_body),
            response_truncated=response_truncated,
            response_excerpt=response_excerpt,
            reason=reason,
        )

    def _blocked_receipt(
        self,
        proposal: RequestProposal,
        request: MaterializedRequest | None,
        *,
        request_id: str,
        started: float,
        reason: str,
    ) -> ExecutionReceipt:
        return self._finish(
            self._receipt(
                proposal=proposal,
                request_id=request_id,
                request=request,
                started=started,
                outcome="policy_denied",
                reason=reason,
            )
        )

    def execute(
        self,
        proposal: RequestProposal,
        *,
        run_id: str | None = None,
        approval: ApprovalDecision | None = None,
    ) -> ExecutionReceipt:
        started = self._clock()
        current_run_id = run_id or self._run_id_factory()
        if not 1 <= len(current_run_id) <= 128:
            raise ValueError("run_id must contain 1 to 128 characters")
        if sanitize_text(current_run_id).value != current_run_id:
            raise ValueError("run_id must not contain sensitive data")
        request_id = self._request_id_factory()
        self.last_approval = None
        self.last_guarded_response = None
        self.last_risk_decision = None
        self.last_receipt = None
        self.last_events = []
        state = ExecutionStateMachine()
        with self._run_ids_lock:
            if current_run_id in self._run_ids:
                state.transition("blocked")
                self._emit(
                    current_run_id,
                    "validate",
                    "blocked",
                    started=started,
                    safe_error_code="run_id_already_used",
                    counters={"network_calls": 0},
                )
                return self._blocked_receipt(
                    proposal,
                    None,
                    request_id=request_id,
                    started=started,
                    reason="run_id_already_used",
                )
            self._run_ids.add(current_run_id)

        decision = self.engine.decide(proposal)
        if not decision.allowed or decision.request is None:
            state.transition("blocked")
            self._emit(
                current_run_id,
                "validate",
                "blocked",
                started=started,
                safe_error_code=decision.reason,
                counters={"network_calls": 0},
            )
            return self._blocked_receipt(
                proposal, None, request_id=request_id, started=started, reason=decision.reason
            )

        request = decision.request
        state.transition("validated")
        self._emit(current_run_id, "validate", "success", started=started)
        risk = classify_risk(request)
        self.last_risk_decision = risk
        self._emit(
            current_run_id,
            "risk_classification",
            "success",
            started=started,
            counters={"requires_approval": int(risk.requires_approval)},
        )

        if risk.requires_approval:
            state.transition("pending_approval")
            initial_view = approval_view(
                proposal,
                request,
                run_id=current_run_id,
                proposal_id=proposal_id(proposal),
                policy_sha256=self.engine.policy_sha256,
                trusted_origin_id=self.trusted_origin_id,
            )
            if approval is None:
                if self._approval_provider is None:
                    choice = ApprovalChoice("reject", "approval_missing", "execution-boundary")
                else:
                    try:
                        choice = self._approval_provider.request(initial_view)
                    except Exception:
                        choice = ApprovalChoice(
                            "reject", "approval_provider_error", "execution-boundary"
                        )
                approval = issue_approval(initial_view, choice, now=self._wall_clock())

            if approval.decision == "reject":
                rejected = approval.model_copy(update={"used": True})
                self._write_approval(rejected)
                state.transition("rejected")
                self._emit(
                    current_run_id,
                    "approval",
                    "rejected",
                    started=started,
                    safe_error_code=rejected.reason,
                    counters={"network_calls": 0, "rejected": 1},
                    related_ids=[rejected.approval_id],
                )
                return self._blocked_receipt(
                    proposal,
                    request,
                    request_id=request_id,
                    started=started,
                    reason="approval_rejected",
                )

            recheck = self.engine.decide(proposal)
            if not recheck.allowed or recheck.request is None:
                state.transition("blocked")
                self._write_approval(approval)
                self._emit(
                    current_run_id,
                    "policy_recheck",
                    "blocked",
                    started=started,
                    safe_error_code=recheck.reason,
                    counters={"network_calls": 0},
                )
                return self._blocked_receipt(
                    proposal, None, request_id=request_id, started=started, reason=recheck.reason
                )
            request = recheck.request
            rechecked_view = approval_view(
                proposal,
                request,
                run_id=current_run_id,
                proposal_id=proposal_id(proposal),
                policy_sha256=self.engine.policy_sha256,
                trusted_origin_id=self.trusted_origin_id,
            )
            try:
                consumed = self._approval_registry.consume(
                    approval, rechecked_view, now=self._wall_clock()
                )
            except ApprovalValidationError as error:
                state.transition("blocked")
                self._write_approval(approval)
                self._emit(
                    current_run_id,
                    "approval",
                    "blocked",
                    started=started,
                    safe_error_code=error.reason,
                    counters={"network_calls": 0},
                    related_ids=[approval.approval_id],
                )
                return self._blocked_receipt(
                    proposal,
                    request,
                    request_id=request_id,
                    started=started,
                    reason=error.reason,
                )
            self._write_approval(consumed)
            state.transition("approved")
            self._emit(
                current_run_id,
                "approval",
                "approved",
                started=started,
                counters={"approved": 1},
                related_ids=[consumed.approval_id],
            )
            state.transition("ready_to_execute")
            self._emit(current_run_id, "policy_recheck", "success", started=started)
        else:
            state.transition("ready_to_execute")

        if not self._rate_limiter.allow(request.method, request.path):
            state.transition("blocked")
            self._emit(
                current_run_id,
                "execute",
                "blocked",
                started=started,
                safe_error_code="local_rate_limit_exceeded",
                counters={"network_calls": 0},
            )
            return self._finish(
                self._receipt(
                    proposal=proposal,
                    request_id=request_id,
                    request=request,
                    started=started,
                    outcome="rate_limited",
                    reason="local_rate_limit_exceeded",
                )
            )

        body = _canonical_payload(request.payload)
        if len(body or b"") > self.engine.policy.limits.max_request_bytes:
            state.transition("blocked")
            self._emit(
                current_run_id,
                "execute",
                "blocked",
                started=started,
                safe_error_code="request_body_too_large",
                counters={"network_calls": 0},
            )
            return self._blocked_receipt(
                proposal,
                request,
                request_id=request_id,
                started=started,
                reason="request_body_too_large",
            )

        headers = {
            **request.headers,
            self.engine.policy.api_key.header_name: self._api_key,
            "x-request-id": request_id,
            "accept": "application/json",
            "accept-encoding": "identity",
        }
        if body is not None:
            headers["content-type"] = "application/json"

        try:
            with self._http.stream(
                request.method, request.path, headers=headers, content=body
            ) as response:
                retained = bytearray()
                truncated = False
                maximum = self.engine.policy.limits.max_response_bytes
                for chunk in response.iter_raw():
                    remaining = maximum - len(retained)
                    if len(chunk) > remaining:
                        retained.extend(chunk[:remaining])
                        truncated = True
                        break
                    retained.extend(chunk)
                response_body = bytes(retained)
                if truncated:
                    outcome: ExecutionOutcome = "response_truncated"
                    reason = "response_size_limit_reached"
                elif response.status_code == 429:
                    outcome = "rate_limited"
                    reason = "gateway_rate_limit_exceeded"
                elif response.status_code != request.expected_status:
                    outcome = "unexpected_status"
                    reason = "unexpected_status"
                else:
                    outcome = "success"
                    reason = None
                self._emit(
                    current_run_id,
                    "execute",
                    "success",
                    started=started,
                    counters={"network_calls": 1},
                )
                try:
                    guarded = self._response_guard(
                        response_body,
                        run_id=current_run_id,
                        request_id=request_id,
                        status_code=response.status_code,
                        response_truncated=truncated,
                        api_key=self._api_key,
                    )
                except Exception as error:
                    state.transition("failed")
                    receipt = self._finish(
                        self._receipt(
                            proposal=proposal,
                            request_id=request_id,
                            request=request,
                            started=started,
                            outcome=outcome,
                            status_code=response.status_code,
                            response_body=response_body,
                            response_truncated=truncated,
                            response_excerpt=None,
                            reason=reason,
                        )
                    )
                    self._emit(
                        current_run_id,
                        "response_guard",
                        "failed",
                        started=started,
                        safe_error_code="response_guard_failed",
                        counters={"network_calls": 1},
                        related_ids=[receipt.request_id],
                    )
                    raise ResponseGuardError() from error
                self._write_guarded_response(guarded)
                state.transition("executed")
                self._emit(
                    current_run_id,
                    "response_guard",
                    "success",
                    started=started,
                    counters={
                        "injection_flags": int(guarded.injection_detected),
                        "redactions": sum(guarded.redaction_summary.values()),
                    },
                    related_ids=[guarded.response_id],
                )
                return self._finish(
                    self._receipt(
                        proposal=proposal,
                        request_id=request_id,
                        request=request,
                        started=started,
                        outcome=outcome,
                        status_code=response.status_code,
                        response_body=response_body,
                        response_truncated=truncated,
                        response_excerpt=guarded.sanitized_excerpt,
                        reason=reason,
                    )
                )
        except ResponseGuardError:
            raise
        except httpx.TimeoutException:
            state.transition("failed")
            self._emit(
                current_run_id,
                "execute",
                "failed",
                started=started,
                safe_error_code="gateway_timeout",
                counters={"network_calls": 1},
            )
            return self._finish(
                self._receipt(
                    proposal=proposal,
                    request_id=request_id,
                    request=request,
                    started=started,
                    outcome="timeout",
                    reason="gateway_timeout",
                )
            )
        except httpx.RequestError:
            state.transition("failed")
            self._emit(
                current_run_id,
                "execute",
                "failed",
                started=started,
                safe_error_code="gateway_connection_error",
                counters={"network_calls": 1},
            )
            return self._finish(
                self._receipt(
                    proposal=proposal,
                    request_id=request_id,
                    request=request,
                    started=started,
                    outcome="connection_error",
                    reason="gateway_connection_error",
                )
            )
