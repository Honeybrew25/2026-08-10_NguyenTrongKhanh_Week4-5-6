from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Severity = Literal[
    "critical",
    "high",
    "medium",
    "low",
    "informational",
    "unknown",
]
Confidence = Literal["high", "medium", "low", "unknown"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)


class NormalizedSource(StrictModel):
    path: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    records_read: int = Field(ge=0)
    duplicates_ignored: int = Field(ge=0)


class NormalizedSummary(StrictModel):
    total: int = Field(ge=0)
    by_tool: dict[str, int]
    by_severity: dict[str, int]


class NormalizedFindingInput(StrictModel):
    id: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    tool_version: str | None
    severity: Severity
    confidence: str | None
    file_or_url: str = Field(min_length=1)
    line: int | None = Field(default=None, ge=1)
    method: str | None
    title: str = Field(min_length=1)
    description: str
    rule_id: str = Field(min_length=1)
    cwe: str | None
    remediation: str | None
    references: list[str]
    evidence: str | None
    source_file: str = Field(min_length=1)
    metadata: dict[str, Any]


class NormalizedReportInput(StrictModel):
    schema_path: Literal["schemas/normalized-findings.schema.json"] = Field(
        alias="schema"
    )
    schema_version: Literal["1.0"]
    generated_at: str = Field(min_length=1)
    sources: list[NormalizedSource]
    summary: NormalizedSummary
    findings: list[NormalizedFindingInput]


class KnowledgeContext(StrictModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    indicators: list[str]
    remediation: list[str]


class ScannerContext(StrictModel):
    tool: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    description: str
    evidence: str | None
    remediation: str | None


class NarrativeRequest(StrictModel):
    group_id: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    severity: Severity
    source_confidence: Confidence
    occurrence_count: int = Field(ge=1)
    scanner_contexts: list[ScannerContext] = Field(min_length=1)
    knowledge_contexts: list[KnowledgeContext]


class NarrativeDraft(StrictModel):
    group_id: str = Field(min_length=1)
    explanation: str = Field(min_length=1, max_length=2400)
    verification_steps: list[str] = Field(min_length=1, max_length=5)
    remediation_steps: list[str] = Field(min_length=1, max_length=5)

    @field_validator("explanation")
    @classmethod
    def explanation_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("explanation must not be blank")
        return value.strip()

    @field_validator("verification_steps", "remediation_steps")
    @classmethod
    def steps_must_be_nonempty_and_unique(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values]
        if any(not value for value in cleaned):
            raise ValueError("steps must not be blank")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("steps must be unique")
        return cleaned


class NarrativeBatch(StrictModel):
    findings: list[NarrativeDraft]


class FindingLocation(StrictModel):
    file_or_url: str = Field(min_length=1)
    line: int | None = Field(default=None, ge=1)
    method: str | None


class ScannerEvidence(StrictModel):
    finding_id: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    source_file: str = Field(min_length=1)
    evidence: str | None


class AnalysisFinding(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    severity: Severity
    locations: list[FindingLocation] = Field(min_length=1)
    scanner_evidence: list[ScannerEvidence] = Field(min_length=1)
    explanation: str = Field(min_length=1)
    verification_steps: list[str] = Field(min_length=1)
    remediation_steps: list[str] = Field(min_length=1)
    confidence: Confidence
    occurrence_count: int = Field(ge=1)
    source_finding_ids: list[str] = Field(min_length=1)
    knowledge_ids: list[str]
    analysis_method: str = Field(min_length=1)

    @model_validator(mode="after")
    def provenance_must_be_consistent(self) -> "AnalysisFinding":
        if len(self.source_finding_ids) != len(set(self.source_finding_ids)):
            raise ValueError("source_finding_ids must be unique")
        if len(self.knowledge_ids) != len(set(self.knowledge_ids)):
            raise ValueError("knowledge_ids must be unique")
        if self.occurrence_count != len(self.source_finding_ids):
            raise ValueError("occurrence_count must match source_finding_ids")
        evidence_ids = [item.finding_id for item in self.scanner_evidence]
        if sorted(evidence_ids) != sorted(self.source_finding_ids):
            raise ValueError("scanner_evidence must cover every source finding")
        return self
