from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from safe_api_tool.approval import ApprovalDecision, GuardedResponse, RiskDecision
from safe_api_tool.audit import ExecutionReceipt
from safe_api_tool.models import RequestProposal, StrictModel
from security_pipeline.analysis.models import AnalysisFinding


PipelineStage = Literal[
    "scan",
    "scanner_input",
    "normalize",
    "analysis",
    "proposal",
    "approval",
    "request",
    "response_guard",
    "final_report",
    "evaluation",
    "cleanup",
]
RunStatus = Literal[
    "dry_run",
    "completed",
    "completed_no_findings",
    "rejected",
    "blocked",
    "failed",
]


class ScannerInputReference(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    tool: str = Field(min_length=1, max_length=40)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    bytes: int = Field(ge=0)
    retained_path: str = Field(min_length=1)


class PipelineEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,127}$")
    timestamp: str = Field(min_length=1)
    stage: PipelineStage
    outcome: Literal["success", "approved", "rejected", "blocked", "failed"]
    duration_ms: float = Field(ge=0)
    safe_error_code: str | None = Field(default=None, max_length=100)
    counters: dict[str, int]
    related_ids: list[str]

    @model_validator(mode="after")
    def counters_are_non_negative(self) -> "PipelineEvent":
        if any(value < 0 for value in self.counters.values()):
            raise ValueError("event counters cannot be negative")
        return self


class RunMetrics(StrictModel):
    total_duration_ms: float = Field(ge=0)
    raw_findings: int = Field(ge=0)
    normalized_findings: int = Field(ge=0)
    analysis_groups: int = Field(ge=0)
    requests_attempted: int = Field(ge=0)
    requests_sent: int = Field(ge=0)
    approvals: int = Field(ge=0)
    rejections: int = Field(ge=0)
    injection_flags: int = Field(ge=0)
    redactions: int = Field(ge=0)
    errors: int = Field(ge=0)
    stage_duration_ms: dict[str, float]


class FinalReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,127}$")
    status: RunStatus
    started_at: str
    completed_at: str
    provider: str = Field(min_length=1)
    provider_config: dict[str, str]
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    schema_sha256: dict[str, str]
    scanner_inputs: list[ScannerInputReference]
    metrics: RunMetrics
    analysis_group: AnalysisFinding | None
    proposal_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{16}$")
    proposal: RequestProposal | None
    risk_decision: RiskDecision | None
    approval: ApprovalDecision | None
    execution_receipt: ExecutionReceipt | None
    guarded_response: GuardedResponse | None
    source_finding_ids: list[str]
    human_decision: Literal["not_required", "not_requested", "approve", "reject"]
    test_interpretation: Literal[
        "not_executed",
        "verification_signal_not_exploit_proof",
        "request_blocked_before_transport",
    ]
    trust_statement: Literal[
        "scanner_facts_code_owned_narrative_provider_owned_http_untrusted"
    ] = "scanner_facts_code_owned_narrative_provider_owned_http_untrusted"
    safe_error_codes: list[str]
    artifact_sha256: dict[str, str]

    @model_validator(mode="after")
    def links_are_consistent(self) -> "FinalReport":
        if self.proposal is None and self.proposal_id is not None:
            raise ValueError("proposal_id requires proposal")
        if self.analysis_group is not None:
            if sorted(self.source_finding_ids) != sorted(
                self.analysis_group.source_finding_ids
            ):
                raise ValueError("final report source provenance mismatch")
        if self.execution_receipt is not None and self.proposal_id is not None:
            if self.execution_receipt.proposal_id != self.proposal_id:
                raise ValueError("receipt does not match proposal")
        return self


class RunManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str
    status: RunStatus
    files: dict[str, str]


class EvaluationCaseResult(StrictModel):
    case_id: str
    category: Literal["analysis_group", "behavioral"]
    passed: bool
    expected: dict[str, Any]
    actual: dict[str, Any]
    tp: int = Field(ge=0)
    fp: int = Field(ge=0)
    fn: int = Field(ge=0)
    safe_error_code: str | None = None


class EvaluationSummary(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    evaluation_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,127}$")
    provider: Literal["deterministic"] = "deterministic"
    truth_unit: Literal["expected_tool_rule_group_per_analysis_case"]
    case_count: int = Field(ge=1)
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    tp: int = Field(ge=0)
    fp: int = Field(ge=0)
    fn: int = Field(ge=0)
    schema_valid_rate: float = Field(ge=0, le=1)
    source_coverage_rate: float = Field(ge=0, le=1)
    hallucination_count: int = Field(ge=0)
    secret_pii_leak_count: int = Field(ge=0)
    policy_bypass_count: int = Field(ge=0)
    results: list[EvaluationCaseResult]

    @model_validator(mode="after")
    def totals_match_results(self) -> "EvaluationSummary":
        if self.case_count != len(self.results):
            raise ValueError("evaluation case_count mismatch")
        if self.passed != sum(item.passed for item in self.results):
            raise ValueError("evaluation passed count mismatch")
        if self.failed != self.case_count - self.passed:
            raise ValueError("evaluation failed count mismatch")
        return self
