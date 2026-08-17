from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Callable, Literal, Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen
import uuid

import httpx

from safe_api_tool.approval import (
    ApprovalProvider,
    ContractJsonlWriter,
    RiskDecision,
    TRUSTED_RUNTIME_ORIGINS,
    classify_risk,
)
from safe_api_tool.audit import AuditLogWriter, ExecutionReceipt
from safe_api_tool.client import ResponseGuardError, SafeApiClient, proposal_id
from safe_api_tool.models import RequestProposal
from safe_api_tool.planner import DeterministicSafeRequestPlanner
from safe_api_tool.policy import PolicyEngine, ROOT
from security_pipeline.analysis.agent import (
    SecurityAnalysisAgent,
    load_normalized_report,
    write_jsonl,
)
from security_pipeline.analysis.models import AnalysisFinding
from security_pipeline.analysis.providers import (
    DeterministicNarrativeProvider,
    GeminiNarrativeProvider,
    NarrativeProvider,
    ProviderError,
)
from security_pipeline.pipeline import normalize_files, write_normalized_report
from sentinel_guardrails.redaction import sanitize_data, sanitize_text

from project_sentinel.contracts import (
    FinalReport,
    PipelineEvent,
    RunManifest,
    RunMetrics,
    RunStatus,
    ScannerInputReference,
)


DEFAULT_OUTPUT_ROOT = ROOT / "security-results" / "runs" / "week-6"
DEFAULT_KNOWLEDGE_BASE = ROOT / "data" / "vulnerabilities.json"
RUN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
PipelineState = Literal[
    "created",
    "inputs_retained",
    "normalized",
    "analyzed",
    "proposed",
    "pending_approval",
    "executed",
    "reported",
    "failed",
]

_TRANSITIONS: dict[PipelineState, frozenset[PipelineState]] = {
    "created": frozenset({"inputs_retained", "failed"}),
    "inputs_retained": frozenset({"normalized", "failed"}),
    "normalized": frozenset({"analyzed", "failed"}),
    "analyzed": frozenset({"proposed", "reported", "failed"}),
    "proposed": frozenset({"pending_approval", "executed", "reported", "failed"}),
    "pending_approval": frozenset({"executed", "reported", "failed"}),
    "executed": frozenset({"reported", "failed"}),
    "reported": frozenset(),
    "failed": frozenset({"reported"}),
}


class PipelineTransitionError(ValueError):
    pass


class GatewayPreflightError(RuntimeError):
    pass


class PipelineStateMachine:
    def __init__(self) -> None:
        self.state: PipelineState = "created"
        self.history: list[PipelineState] = [self.state]

    def transition(self, target: PipelineState) -> None:
        if target not in _TRANSITIONS[self.state]:
            raise PipelineTransitionError(
                f"invalid_pipeline_transition:{self.state}:{target}"
            )
        self.state = target
        self.history.append(target)


def utc_timestamp(value: datetime | None = None) -> str:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: object) -> Path:
    sanitized = sanitize_data(value).value
    text = json.dumps(
        sanitized,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(f"{text}\n", encoding="utf-8")
    temporary.replace(path)
    return path


def atomic_contract(path: Path, value: object) -> Path:
    sanitized = sanitize_data(value.model_dump(mode="json")).value
    validated = type(value).model_validate(sanitized)
    return atomic_json(path, validated.model_dump(mode="json"))


def generate_run_id(prefix: str = "run") -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:8]}"


def wait_for_gateway(
    runtime_profile: Literal["host", "compose"],
    *,
    deadline_seconds: float = 30.0,
) -> None:
    origin = TRUSTED_RUNTIME_ORIGINS[runtime_profile]
    deadline = time.monotonic() + max(0.1, deadline_seconds)
    request = Request(f"{origin}/health", method="GET")
    while time.monotonic() < deadline:
        try:
            with urlopen(request, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, URLError):
            time.sleep(0.25)
    raise GatewayPreflightError("gateway_preflight_timeout")


def run_fresh_bandit(output_path: Path) -> int:
    """Run the fixed SAST command; no caller-controlled argv is accepted."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "bandit",
        "--recursive",
        "src",
        "scripts",
        "--format",
        "json",
        "--severity-level",
        "low",
        "--output",
        str(output_path.resolve()),
    ]
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode not in {0, 1} or not output_path.is_file():
        raise RuntimeError("bandit_data_scan_failed")
    json.loads(output_path.read_text(encoding="utf-8"))
    return completed.returncode


def _scanner_tool(path: Path) -> str:
    document = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(document, dict) and isinstance(document.get("results"), list):
        return "bandit"
    if isinstance(document, dict) and isinstance(document.get("site"), list):
        return "zap"
    return "supported-scanner"


def _provider(
    name: Literal["deterministic", "gemini"],
) -> NarrativeProvider:
    if name == "deterministic":
        return DeterministicNarrativeProvider()
    return GeminiNarrativeProvider(api_key=os.getenv("GEMINI_API_KEY"))


def _safe_error_code(error: Exception) -> str:
    if isinstance(error, GatewayPreflightError):
        return "gateway_preflight_timeout"
    if isinstance(error, ResponseGuardError):
        return "response_guard_failed"
    if isinstance(error, ProviderError):
        return "provider_error"
    if isinstance(error, (ValueError, FileNotFoundError, json.JSONDecodeError)):
        return "schema_or_input_error"
    return "pipeline_internal_error"


class SentinelRunner:
    def __init__(
        self,
        *,
        output_root: Path = DEFAULT_OUTPUT_ROOT,
        knowledge_base: Path = DEFAULT_KNOWLEDGE_BASE,
        engine: PolicyEngine | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        gateway_preflight: Callable[[Literal["host", "compose"]], None] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.output_root = output_root
        self.knowledge_base = knowledge_base
        self.engine = engine or PolicyEngine.from_files()
        self._clock = monotonic_clock
        self._wall_clock = wall_clock
        self._gateway_preflight = gateway_preflight or wait_for_gateway
        self._transport = transport

    def _workspace(self, run_id: str) -> Path:
        if RUN_ID.fullmatch(run_id) is None:
            raise ValueError("run_id must use lowercase letters, digits and hyphens")
        if sanitize_text(run_id).value != run_id:
            raise ValueError("run_id must not contain sensitive data")
        workspace = self.output_root / run_id
        workspace.mkdir(parents=True, exist_ok=False)
        (workspace / "scanner-inputs").mkdir()
        return workspace

    def _event(
        self,
        writer: ContractJsonlWriter,
        run_id: str,
        stage: str,
        outcome: str,
        *,
        duration_ms: float,
        counters: dict[str, int] | None = None,
        safe_error_code: str | None = None,
        related_ids: list[str] | None = None,
    ) -> PipelineEvent:
        event = PipelineEvent(
            event_id=str(uuid.uuid4()),
            run_id=run_id,
            timestamp=utc_timestamp(self._wall_clock()),
            stage=stage,
            outcome=outcome,
            duration_ms=round(max(0.0, duration_ms), 3),
            safe_error_code=safe_error_code,
            counters=counters or {},
            related_ids=related_ids or [],
        )
        writer.write(event)
        return event

    def _retain_inputs(
        self,
        scanner_paths: Sequence[Path],
        workspace: Path,
    ) -> list[ScannerInputReference]:
        if not scanner_paths:
            raise ValueError("at least one scanner input is required")
        references: list[ScannerInputReference] = []
        for index, source in enumerate(scanner_paths, start=1):
            if not source.is_file():
                raise FileNotFoundError("scanner input not found")
            tool = _scanner_tool(source)
            suffix = source.suffix.lower() if source.suffix else ".json"
            retained = workspace / "scanner-inputs" / f"{index:02d}-{tool}{suffix}"
            shutil.copyfile(source, retained)
            references.append(
                ScannerInputReference(
                    name=source.name,
                    tool=tool,
                    sha256=sha256_file(retained),
                    bytes=retained.stat().st_size,
                    retained_path=retained.relative_to(workspace).as_posix(),
                )
            )
        return references

    def _schema_hashes(self) -> dict[str, str]:
        names = (
            "normalized-findings.schema.json",
            "security-analysis-finding.schema.json",
            "safe-api-request.schema.json",
            "safe-api-approval.schema.json",
            "safe-api-log.schema.json",
            "safe-api-guarded-response.schema.json",
            "project-sentinel-event.schema.json",
            "project-sentinel-final-report.schema.json",
        )
        return {name: sha256_file(ROOT / "schemas" / name) for name in names}

    def run(
        self,
        scanner_paths: Sequence[Path],
        *,
        run_id: str | None = None,
        provider_name: Literal["deterministic", "gemini"] = "deterministic",
        execute: bool = False,
        api_key: str | None = None,
        approval_provider: ApprovalProvider | None = None,
        runtime_profile: Literal["host", "compose"] = "host",
        proposal_override: RequestProposal | None = None,
        proposal_factory: Callable[[AnalysisFinding], RequestProposal] | None = None,
    ) -> FinalReport:
        if proposal_override is not None and proposal_factory is not None:
            raise ValueError("choose proposal_override or proposal_factory, not both")
        current_run_id = run_id or generate_run_id()
        workspace = self._workspace(current_run_id)
        event_writer = ContractJsonlWriter(workspace / "pipeline-events.jsonl")
        started_clock = self._clock()
        started_at = utc_timestamp(self._wall_clock())
        state = PipelineStateMachine()
        durations: dict[str, float] = {}
        scanner_refs: list[ScannerInputReference] = []
        analysis: list[AnalysisFinding] = []
        selected: AnalysisFinding | None = None
        proposal: RequestProposal | None = None
        risk: RiskDecision | None = None
        receipt: ExecutionReceipt | None = None
        approval = None
        guarded = None
        status: RunStatus = "failed"
        error_codes: list[str] = []
        normalized_total = 0
        raw_total = 0
        final_path = workspace / "final-report.json"

        try:
            stage_started = self._clock()
            scanner_refs = self._retain_inputs(scanner_paths, workspace)
            duration = (self._clock() - stage_started) * 1000
            durations["scanner_input"] = duration
            state.transition("inputs_retained")
            self._event(
                event_writer,
                current_run_id,
                "scanner_input",
                "success",
                duration_ms=duration,
                counters={"scanner_inputs": len(scanner_refs)},
            )

            retained_paths = [
                workspace / reference.retained_path for reference in scanner_refs
            ]
            stage_started = self._clock()
            normalized = normalize_files(retained_paths)
            normalized_path = write_normalized_report(
                normalized, workspace / "normalized-findings.json"
            )
            normalized_total = int(normalized["summary"]["total"])
            raw_total = sum(
                int(source["records_read"]) for source in normalized["sources"]
            )
            duration = (self._clock() - stage_started) * 1000
            durations["normalize"] = duration
            state.transition("normalized")
            self._event(
                event_writer,
                current_run_id,
                "normalize",
                "success",
                duration_ms=duration,
                counters={
                    "raw_findings": raw_total,
                    "normalized_findings": normalized_total,
                },
            )

            stage_started = self._clock()
            report_input = load_normalized_report(normalized_path)
            if normalized_total == 0:
                analysis = []
            else:
                narrative_provider = _provider(provider_name)
                analysis = SecurityAnalysisAgent(
                    provider=narrative_provider,
                    knowledge_base=self.knowledge_base,
                ).analyze(report_input)
            analysis_path = write_jsonl(
                analysis, workspace / "security-analysis.jsonl"
            )
            duration = (self._clock() - stage_started) * 1000
            durations["analysis"] = duration
            state.transition("analyzed")
            self._event(
                event_writer,
                current_run_id,
                "analysis",
                "success",
                duration_ms=duration,
                counters={"analysis_groups": len(analysis)},
            )

            if not analysis:
                status = "completed_no_findings"
                state.transition("reported")
            else:
                stage_started = self._clock()
                selected = analysis[0]
                if proposal_override is not None:
                    proposal = proposal_override
                elif proposal_factory is not None:
                    proposal = proposal_factory(selected)
                else:
                    proposal = DeterministicSafeRequestPlanner().propose(selected)
                atomic_json(
                    workspace / "request-proposal.json",
                    proposal.model_dump(mode="json"),
                )
                decision = self.engine.decide(proposal)
                if decision.request is not None:
                    risk = classify_risk(decision.request)
                duration = (self._clock() - stage_started) * 1000
                durations["proposal"] = duration
                state.transition("proposed")
                self._event(
                    event_writer,
                    current_run_id,
                    "proposal",
                    "success" if decision.allowed else "blocked",
                    duration_ms=duration,
                    counters={"proposals": 1},
                    safe_error_code=None if decision.allowed else decision.reason,
                    related_ids=[proposal_id(proposal)],
                )

                if not execute:
                    status = "dry_run" if decision.allowed else "blocked"
                    state.transition("reported")
                else:
                    if risk is not None and risk.requires_approval:
                        state.transition("pending_approval")
                    if decision.allowed:
                        self._gateway_preflight(runtime_profile)
                    if api_key is None:
                        raise ValueError("safe_api_key_required")
                    safe_event_path = workspace / "safe-api-events.jsonl"
                    client = SafeApiClient(
                        self.engine,
                        api_key=api_key,
                        audit_writer=AuditLogWriter(workspace / "execution-receipts.jsonl"),
                        approval_writer=ContractJsonlWriter(
                            workspace / "approval-decisions.jsonl"
                        ),
                        guarded_response_writer=ContractJsonlWriter(
                            workspace / "guarded-responses.jsonl"
                        ),
                        event_writer=ContractJsonlWriter(safe_event_path),
                        approval_provider=approval_provider,
                        runtime_profile=runtime_profile,
                        transport=self._transport,
                    )
                    try:
                        stage_started = self._clock()
                        with client:
                            receipt = client.execute(proposal, run_id=current_run_id)
                        duration = (self._clock() - stage_started) * 1000
                        durations["request"] = duration
                        approval = client.last_approval
                        guarded = client.last_guarded_response
                    except ResponseGuardError:
                        receipt = client.last_receipt
                        approval = client.last_approval
                        guarded = client.last_guarded_response
                        duration = (self._clock() - stage_started) * 1000
                        durations["request"] = duration
                        raise
                    if (
                        receipt.status_code is not None
                        and state.state in {"proposed", "pending_approval"}
                    ):
                        state.transition("executed")
                    sent = int(receipt.status_code is not None)
                    self._event(
                        event_writer,
                        current_run_id,
                        "approval",
                        (
                            approval.decision + "d"
                            if approval is not None and approval.decision == "approve"
                            else "rejected"
                            if approval is not None
                            else "success"
                        ),
                        duration_ms=duration,
                        counters={
                            "approvals": int(
                                approval is not None and approval.decision == "approve"
                            ),
                            "rejections": int(
                                approval is not None and approval.decision == "reject"
                            ),
                        },
                        related_ids=[approval.approval_id] if approval else [],
                    )
                    self._event(
                        event_writer,
                        current_run_id,
                        "request",
                        "success" if sent else "blocked",
                        duration_ms=duration,
                        counters={"requests_attempted": 1, "requests_sent": sent},
                        safe_error_code=receipt.reason,
                        related_ids=[receipt.request_id],
                    )
                    if guarded is not None:
                        self._event(
                            event_writer,
                            current_run_id,
                            "response_guard",
                            "success",
                            duration_ms=duration,
                            counters={
                                "injection_flags": int(guarded.injection_detected),
                                "redactions": sum(guarded.redaction_summary.values()),
                            },
                            related_ids=[guarded.response_id],
                        )
                    if receipt.outcome == "policy_denied":
                        status = (
                            "rejected"
                            if receipt.reason == "approval_rejected"
                            else "blocked"
                        )
                    elif receipt.outcome in {"success", "response_truncated"}:
                        status = "completed"
                    else:
                        status = "failed"
                        error_codes.append(receipt.reason or receipt.outcome)
                    state.transition("reported")
        except Exception as error:
            code = _safe_error_code(error)
            error_codes.append(code)
            status = "failed"
            if state.state != "failed" and "failed" in _TRANSITIONS[state.state]:
                state.transition("failed")
        total_duration = (self._clock() - started_clock) * 1000
        metrics = RunMetrics(
            total_duration_ms=round(max(0.0, total_duration), 3),
            raw_findings=raw_total,
            normalized_findings=normalized_total,
            analysis_groups=len(analysis),
            requests_attempted=int(receipt is not None),
            requests_sent=int(receipt is not None and receipt.status_code is not None),
            approvals=int(approval is not None and approval.decision == "approve"),
            rejections=int(approval is not None and approval.decision == "reject"),
            injection_flags=int(guarded is not None and guarded.injection_detected),
            redactions=(
                sum(guarded.redaction_summary.values()) if guarded is not None else 0
            ),
            errors=len(error_codes),
            stage_duration_ms={
                key: round(max(0.0, value), 3) for key, value in sorted(durations.items())
            },
        )
        human_decision: Literal[
            "not_required", "not_requested", "approve", "reject"
        ]
        if approval is not None:
            human_decision = approval.decision
        elif risk is not None and risk.requires_approval:
            human_decision = "not_requested"
        else:
            human_decision = "not_required"
        interpretation = (
            "not_executed"
            if receipt is None
            else "request_blocked_before_transport"
            if receipt.status_code is None
            else "verification_signal_not_exploit_proof"
        )
        self._event(
            event_writer,
            current_run_id,
            "final_report",
            "success" if status != "failed" else "failed",
            duration_ms=total_duration,
            counters={"errors": len(error_codes)},
            safe_error_code=error_codes[-1] if error_codes else None,
            related_ids=[current_run_id],
        )
        artifact_hashes: dict[str, str] = {}
        for path in sorted(workspace.iterdir()):
            if path.is_file() and path != final_path:
                artifact_hashes[path.name] = sha256_file(path)
        final = FinalReport(
            run_id=current_run_id,
            status=status,
            started_at=started_at,
            completed_at=utc_timestamp(self._wall_clock()),
            provider=(
                analysis[0].analysis_method
                if analysis
                else "deterministic-v1"
                if provider_name == "deterministic"
                else "gemini:not-called"
            ),
            provider_config={
                "requested_provider": provider_name,
                "prompt_version": "security_analysis_system.md",
            },
            policy_sha256=self.engine.policy_sha256,
            schema_sha256=self._schema_hashes(),
            scanner_inputs=scanner_refs,
            metrics=metrics,
            analysis_group=selected,
            proposal_id=proposal_id(proposal) if proposal else None,
            proposal=proposal,
            risk_decision=risk,
            approval=approval,
            execution_receipt=receipt,
            guarded_response=guarded,
            source_finding_ids=(selected.source_finding_ids if selected else []),
            human_decision=human_decision,
            test_interpretation=interpretation,
            safe_error_codes=error_codes,
            artifact_sha256=artifact_hashes,
        )
        atomic_contract(final_path, final)
        if state.state == "failed":
            state.transition("reported")
        manifest_files = {
            path.relative_to(workspace).as_posix(): sha256_file(path)
            for path in sorted(workspace.rglob("*"))
            if path.is_file() and path.name != "manifest.json"
        }
        manifest = RunManifest(
            run_id=current_run_id,
            status=status,
            files=manifest_files,
        )
        atomic_contract(workspace / "manifest.json", manifest)
        return final
