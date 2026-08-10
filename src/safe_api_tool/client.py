from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
from threading import Lock
import time
from typing import Callable
import uuid

import httpx

from safe_api_tool.audit import (
    AuditLogWriter,
    ExecutionOutcome,
    ExecutionReceipt,
    redact_text,
    utc_timestamp,
)
from safe_api_tool.models import MaterializedRequest, RequestProposal
from safe_api_tool.policy import PolicyEngine, ROOT


class ClientConfigurationError(ValueError):
    pass


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
    """Remove a credential prefix cut by the retained-response byte ceiling."""
    maximum = min(len(value), max(0, len(secret) - 1))
    for length in range(maximum, 0, -1):
        if value.endswith(secret[:length]):
            return f"{value[:-length]}[REDACTED]"
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


class SafeApiClient:
    def __init__(
        self,
        engine: PolicyEngine,
        *,
        api_key: str,
        audit_writer: AuditLogWriter | None = None,
        transport: httpx.BaseTransport | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
        request_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
    ) -> None:
        if (
            not api_key.isascii()
            or not api_key.isprintable()
            or not 32 <= len(api_key.encode("ascii")) <= 512
            or api_key.strip() != api_key
            or api_key.startswith("replace-with-")
        ):
            raise ClientConfigurationError("api_key must contain 32 to 512 ASCII bytes")
        self.engine = engine
        self._api_key = api_key
        self._audit_writer = audit_writer
        self._clock = monotonic_clock
        self._request_id_factory = request_id_factory
        self._rate_limiter = LocalRateLimiter(
            engine.policy.limits.requests_per_minute,
            clock=monotonic_clock,
        )
        timeout = engine.policy.limits.timeout_seconds
        self._http = httpx.Client(
            base_url=engine.policy.gateway_origin,
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
        if self._audit_writer is not None:
            self._audit_writer.write(receipt)
        return receipt

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
        reason: str | None = None,
    ) -> ExecutionReceipt:
        body = _canonical_payload(request.payload) if request is not None else None
        response_excerpt = None
        if response_body is not None:
            decoded = response_body.decode("utf-8", errors="replace")
            if response_truncated:
                decoded = _redact_truncated_secret_suffix(decoded, self._api_key)
            response_excerpt = redact_text(
                decoded,
                secrets=(self._api_key,),
            )[:1024]
        expected_status = request.expected_status if request is not None else None
        expected_match = (
            None
            if expected_status is None or status_code is None
            else status_code == expected_status
        )
        return ExecutionReceipt(
            timestamp=utc_timestamp(),
            proposal_id=proposal_id(proposal),
            request_id=request_id,
            policy_sha256=self.engine.policy_sha256,
            endpoint_id=proposal.endpoint_id,
            test_case_id=proposal.test_case_id,
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

    def execute(self, proposal: RequestProposal) -> ExecutionReceipt:
        started = self._clock()
        request_id = self._request_id_factory()
        decision = self.engine.decide(proposal)
        if not decision.allowed or decision.request is None:
            return self._finish(
                self._receipt(
                    proposal=proposal,
                    request_id=request_id,
                    request=None,
                    started=started,
                    outcome="policy_denied",
                    reason=decision.reason,
                )
            )

        request = decision.request
        if not self._rate_limiter.allow(request.method, request.path):
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
            return self._finish(
                self._receipt(
                    proposal=proposal,
                    request_id=request_id,
                    request=request,
                    started=started,
                    outcome="policy_denied",
                    reason="request_body_too_large",
                )
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
                request.method,
                request.path,
                headers=headers,
                content=body,
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
                        reason=reason,
                    )
                )
        except httpx.TimeoutException:
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
