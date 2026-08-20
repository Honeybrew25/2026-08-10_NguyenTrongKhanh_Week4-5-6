from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Sequence
from urllib.parse import urlparse

from pydantic import ValidationError

from security_pipeline.analysis.models import (
    AnalysisFinding,
    Confidence,
    FindingLocation,
    KnowledgeContext,
    NarrativeBatch,
    NarrativeDraft,
    NarrativeRequest,
    NormalizedFindingInput,
    NormalizedReportInput,
    ScannerContext,
    ScannerEvidence,
    Severity,
)
from security_pipeline.analysis.providers import (
    NarrativeProvider,
    ProviderError,
    ProviderOutputError,
)
from security_pipeline.knowledge import load_knowledge_base
from sentinel_guardrails.redaction import sanitize_text


SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "unknown": 5,
}
CONFIDENCE_ORDER: dict[str, int] = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}
MAX_SCANNER_CONTEXTS_PER_GROUP = 3

_URL = re.compile(r"https?://[^\s)\]}>'\"]+", re.IGNORECASE)
_ENDPOINT = re.compile(r"(?<![\w])/(?:[A-Za-z0-9._~:@%+-]+/?)+")
_WINDOWS_PATH = re.compile(r"\b[A-Za-z]:\\[^\s]+")
_REPO_PATH = re.compile(
    r"\b(?:src|scripts|tests|config|data|schemas|security-results|evidence)/"
    r"[A-Za-z0-9_./-]+"
)
_SECURITY_IDENTIFIER = re.compile(
    r"\b(?:CVE-\d{4}-\d+|CWE-\d+|B\d{3})\b", re.IGNORECASE
)


class AnalysisInputError(ValueError):
    """Raised when normalized findings or knowledge data are invalid."""


@dataclass(frozen=True)
class FindingGroup:
    group_id: str
    tool: str
    rule_id: str
    name: str
    severity: Severity
    confidence: Confidence
    findings: tuple[NormalizedFindingInput, ...]
    knowledge_contexts: tuple[KnowledgeContext, ...]


@dataclass(frozen=True)
class AnalysisRunSummary:
    input_findings: int
    output_groups: int
    output_path: Path
    analysis_method: str


def load_normalized_report(path: str | Path) -> NormalizedReportInput:
    report_path = Path(path)
    try:
        raw_text = report_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    if not raw_text.strip():
        raise AnalysisInputError("Normalized report is empty")
    try:
        raw_document = json.loads(raw_text)
    except json.JSONDecodeError as error:
        raise AnalysisInputError("Normalized report is not valid JSON") from error
    try:
        report = NormalizedReportInput.model_validate(raw_document)
    except ValidationError as error:
        raise AnalysisInputError(
            "Normalized report does not match schema 1.0"
        ) from error

    _validate_report_summary(report)
    unique_by_id: dict[str, NormalizedFindingInput] = {}
    for finding in report.findings:
        existing = unique_by_id.get(finding.id)
        if existing is None:
            unique_by_id[finding.id] = finding
        elif existing != finding:
            raise AnalysisInputError(f"Conflicting duplicate finding id: {finding.id}")
    if len(unique_by_id) != len(report.findings):
        report = report.model_copy(update={"findings": list(unique_by_id.values())})
    return report


def _validate_report_summary(report: NormalizedReportInput) -> None:
    if report.summary.total != len(report.findings):
        raise AnalysisInputError("summary.total does not match findings")
    by_tool = dict(sorted(Counter(item.tool for item in report.findings).items()))
    by_severity = {
        severity: count
        for severity, count in sorted(
            Counter(item.severity for item in report.findings).items(),
            key=lambda item: SEVERITY_ORDER.get(item[0], 99),
        )
    }
    if report.summary.by_tool != by_tool:
        raise AnalysisInputError("summary.by_tool does not match findings")
    if report.summary.by_severity != by_severity:
        raise AnalysisInputError("summary.by_severity does not match findings")
    source_total = sum(
        source.records_read - source.duplicates_ignored for source in report.sources
    )
    if source_total != len(report.findings):
        raise AnalysisInputError("source record counts do not match findings")


def load_rule_index(
    knowledge_base: str | Path,
) -> dict[tuple[str, str], tuple[KnowledgeContext, ...]]:
    rule_index, _ = _load_knowledge_catalog(knowledge_base)
    return rule_index


def _load_knowledge_catalog(
    knowledge_base: str | Path,
) -> tuple[
    dict[tuple[str, str], tuple[KnowledgeContext, ...]],
    dict[str, tuple[str, ...]],
]:
    data = load_knowledge_base(knowledge_base)
    index: dict[tuple[str, str], list[KnowledgeContext]] = defaultdict(list)
    terms_by_document: dict[str, tuple[str, ...]] = {}
    for document in data["documents"]:
        rules_by_tool = document.get("related_scanner_rules")
        if not isinstance(rules_by_tool, dict):
            raise AnalysisInputError(
                f"Knowledge document {document['id']} has invalid scanner rules"
            )
        aliases = document.get("aliases")
        if not isinstance(aliases, list):
            raise AnalysisInputError(
                f"Knowledge document {document['id']} has invalid aliases"
            )
        context = KnowledgeContext(
            id=str(document["id"]),
            title=str(document["title"]),
            summary=str(document["summary"]),
            indicators=[str(value) for value in document["indicators"]],
            remediation=[str(value) for value in document["remediation"]],
        )
        terms_by_document[context.id] = tuple(
            sorted(
                {
                    term.strip()
                    for term in (context.title, *(str(alias) for alias in aliases))
                    if term.strip()
                },
                key=lambda term: (-len(term), term.casefold(), term),
            )
        )
        for tool, rules in rules_by_tool.items():
            if not isinstance(rules, list):
                raise AnalysisInputError(
                    f"Knowledge document {document['id']} has invalid rule list"
                )
            for rule in rules:
                key = (str(tool).casefold(), str(rule).casefold())
                if all(existing.id != context.id for existing in index[key]):
                    index[key].append(context)
    rule_index = {
        key: tuple(sorted(contexts, key=lambda context: context.id))
        for key, contexts in index.items()
    }
    return rule_index, terms_by_document


def group_findings(
    findings: Sequence[NormalizedFindingInput],
    rule_index: dict[tuple[str, str], tuple[KnowledgeContext, ...]],
) -> list[FindingGroup]:
    grouped: dict[tuple[str, str], list[NormalizedFindingInput]] = defaultdict(list)
    for finding in findings:
        grouped[(finding.tool.casefold(), finding.rule_id.casefold())].append(finding)

    result: list[FindingGroup] = []
    for key, members in grouped.items():
        members.sort(key=lambda item: item.id)
        tool = key[0]
        rule_id = min(
            {item.rule_id for item in members},
            key=lambda value: (value.casefold(), value),
        )
        title_counts = Counter(item.title for item in members)
        name = sorted(title_counts, key=lambda title: (-title_counts[title], title))[0]
        severity = min(
            (item.severity for item in members),
            key=lambda value: SEVERITY_ORDER[value],
        )
        confidence = min(
            (_normalize_confidence(item.confidence) for item in members),
            key=lambda value: CONFIDENCE_ORDER[value],
        )
        result.append(
            FindingGroup(
                group_id=f"{tool}:{rule_id}",
                tool=tool,
                rule_id=rule_id,
                name=name,
                severity=severity,
                confidence=confidence,
                findings=tuple(members),
                knowledge_contexts=rule_index.get(key, ()),
            )
        )
    return sorted(
        result,
        key=lambda group: (SEVERITY_ORDER[group.severity], group.group_id),
    )


def _normalize_confidence(value: str | None) -> Confidence:
    normalized = str(value or "").strip().casefold()
    if normalized in CONFIDENCE_ORDER:
        return normalized  # type: ignore[return-value]
    return "unknown"


def _redact_for_model(value: str | None, *, limit: int = 1200) -> str | None:
    if value is None:
        return None
    redacted = sanitize_text(value).value
    if len(redacted) > limit:
        return redacted[:limit] + "…[TRUNCATED]"
    return redacted


def _make_request(group: FindingGroup) -> NarrativeRequest:
    context_by_value: dict[
        tuple[str, str, str, str | None, str | None], ScannerContext
    ] = {}
    for finding in group.findings:
        description = _redact_for_model(finding.description) or ""
        evidence = _redact_for_model(finding.evidence)
        remediation = _redact_for_model(finding.remediation)
        key = (finding.tool, finding.rule_id, description, evidence, remediation)
        context_by_value[key] = ScannerContext(
            tool=finding.tool,
            rule_id=finding.rule_id,
            description=description,
            evidence=evidence,
            remediation=remediation,
        )
    contexts = [
        context_by_value[key]
        for key in sorted(
            context_by_value,
            key=lambda item: tuple(value or "" for value in item),
        )
    ][:MAX_SCANNER_CONTEXTS_PER_GROUP]
    knowledge_contexts = [
        KnowledgeContext(
            id=context.id,
            title=_redact_for_model(context.title) or "",
            summary=_redact_for_model(context.summary) or "",
            indicators=[_redact_for_model(value) or "" for value in context.indicators],
            remediation=[
                _redact_for_model(value) or "" for value in context.remediation
            ],
        )
        for context in group.knowledge_contexts
    ]
    return NarrativeRequest(
        group_id=group.group_id,
        tool=group.tool,
        rule_id=group.rule_id,
        name=_redact_for_model(group.name) or group.rule_id,
        severity=group.severity,
        source_confidence=group.confidence,
        occurrence_count=len(group.findings),
        scanner_contexts=contexts,
        knowledge_contexts=knowledge_contexts,
    )


class SecurityAnalysisAgent:
    def __init__(
        self,
        *,
        provider: NarrativeProvider,
        knowledge_base: str | Path,
    ) -> None:
        self.provider = provider
        self.rule_index, self.knowledge_terms = _load_knowledge_catalog(knowledge_base)

    def analyze(self, report: NormalizedReportInput) -> list[AnalysisFinding]:
        groups = group_findings(report.findings, self.rule_index)
        if not groups:
            return []
        requests = [_make_request(group) for group in groups]
        try:
            batch = self.provider.generate(requests)
            return self._validate_and_build(batch, groups, report)
        except ProviderOutputError as primary_error:
            fallback = getattr(self.provider, "generate_fallback", None)
            if not callable(fallback):
                raise
            try:
                batch = fallback(requests)
                return self._validate_and_build(batch, groups, report)
            except ProviderError as fallback_error:
                raise ProviderError(
                    f"Primary provider output was invalid ({primary_error}); "
                    "the single fallback attempt failed "
                    f"({fallback_error})"
                ) from fallback_error

    def _validate_and_build(
        self,
        batch: NarrativeBatch,
        groups: Sequence[FindingGroup],
        report: NormalizedReportInput,
    ) -> list[AnalysisFinding]:
        draft_by_id: dict[str, NarrativeDraft] = {}
        for draft in batch.findings:
            if draft.group_id in draft_by_id:
                raise ProviderOutputError(
                    f"Duplicate provider group: {draft.group_id}"
                )
            draft_by_id[draft.group_id] = draft
        expected_ids = {group.group_id for group in groups}
        if set(draft_by_id) != expected_ids:
            raise ProviderOutputError(
                "Provider group ids do not match requested groups"
            )

        records: list[AnalysisFinding] = []
        for group in groups:
            draft = draft_by_id[group.group_id]
            _validate_narrative_grounding(
                draft,
                group,
                knowledge_terms=self.knowledge_terms,
            )
            records.append(_build_record(group, draft, self.provider.name))
        _validate_source_coverage(records, report.findings)
        return records


def _validate_narrative_grounding(
    draft: NarrativeDraft,
    group: FindingGroup,
    *,
    knowledge_terms: dict[str, tuple[str, ...]],
) -> None:
    text = "\n".join(
        [draft.explanation, *draft.verification_steps, *draft.remediation_steps]
    )
    if _URL.search(text) or _WINDOWS_PATH.search(text):
        raise ProviderOutputError(
            f"Provider invented or repeated a URL/path for {group.group_id}"
        )

    allowed_endpoints = {
        urlparse(finding.file_or_url).path
        for finding in group.findings
        if urlparse(finding.file_or_url).scheme in {"http", "https"}
    }
    for endpoint in _ENDPOINT.findall(text):
        endpoint = endpoint.rstrip(".,;:")
        if endpoint not in allowed_endpoints:
            raise ProviderOutputError(f"Provider invented endpoint {endpoint}")

    allowed_repo_paths = {finding.file_or_url for finding in group.findings}
    for repo_path in _REPO_PATH.findall(text):
        if repo_path.rstrip(".,;:") not in allowed_repo_paths:
            raise ProviderOutputError(f"Provider invented source path {repo_path}")

    allowed_identifiers = {
        value.casefold()
        for finding in group.findings
        for value in (finding.rule_id, finding.cwe)
        if value
    }
    for identifier in _SECURITY_IDENTIFIER.findall(text):
        if identifier.casefold() not in allowed_identifiers:
            raise ProviderOutputError(
                f"Provider invented security identifier {identifier}"
            )

    allowed_knowledge_ids = {context.id for context in group.knowledge_contexts}
    for document_id in sorted(knowledge_terms):
        if document_id in allowed_knowledge_ids:
            continue
        for term in knowledge_terms[document_id]:
            if re.search(
                rf"(?<!\w){re.escape(term)}(?!\w)",
                text,
                flags=re.IGNORECASE,
            ):
                raise ProviderOutputError(
                    f"Provider invented vulnerability type {term} for {group.group_id}"
                )


def _build_record(
    group: FindingGroup,
    draft: NarrativeDraft,
    analysis_method: str,
) -> AnalysisFinding:
    locations_by_key: dict[tuple[str, int | None, str | None], FindingLocation] = {}
    for finding in group.findings:
        key = (finding.file_or_url, finding.line, finding.method)
        locations_by_key[key] = FindingLocation(
            file_or_url=_redact_for_model(finding.file_or_url) or "[LOCATION_REDACTED]",
            line=finding.line,
            method=_redact_for_model(finding.method),
        )
    location_keys = sorted(
        locations_by_key,
        key=lambda value: (
            value[0],
            value[1] is None,
            value[1] or 0,
            value[2] or "",
        ),
    )
    evidence = [
        ScannerEvidence(
            finding_id=finding.id,
            tool=_redact_for_model(finding.tool) or "unknown",
            rule_id=_redact_for_model(finding.rule_id) or "unknown",
            source_file=_redact_for_model(finding.source_file) or "[SOURCE_REDACTED]",
            evidence=_redact_for_model(finding.evidence),
        )
        for finding in sorted(group.findings, key=lambda item: item.id)
    ]
    source_ids = sorted(finding.id for finding in group.findings)
    return AnalysisFinding(
        id=group.group_id,
        name=_redact_for_model(group.name) or group.rule_id,
        severity=group.severity,
        locations=[locations_by_key[key] for key in location_keys],
        scanner_evidence=evidence,
        explanation=_redact_for_model(draft.explanation) or "Narrative unavailable.",
        verification_steps=[
            _redact_for_model(value) or "Verification step unavailable."
            for value in draft.verification_steps
        ],
        remediation_steps=[
            _redact_for_model(value) or "Remediation step unavailable."
            for value in draft.remediation_steps
        ],
        confidence=group.confidence,
        occurrence_count=len(source_ids),
        source_finding_ids=source_ids,
        knowledge_ids=sorted(context.id for context in group.knowledge_contexts),
        analysis_method=analysis_method,
    )


def _validate_source_coverage(
    records: Sequence[AnalysisFinding],
    findings: Sequence[NormalizedFindingInput],
) -> None:
    output_ids = [
        finding_id for record in records for finding_id in record.source_finding_ids
    ]
    input_ids = sorted({finding.id for finding in findings})
    if sorted(output_ids) != input_ids or len(output_ids) != len(set(output_ids)):
        raise ProviderError("Analysis output lost or duplicated source finding ids")


def write_jsonl(
    records: Sequence[AnalysisFinding],
    output_path: str | Path,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(
        json.dumps(
            record.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        for record in records
    )
    if text:
        text += "\n"
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)
    return path


def run_analysis(
    *,
    input_path: str | Path,
    knowledge_base: str | Path,
    output_path: str | Path,
    provider: NarrativeProvider,
) -> AnalysisRunSummary:
    report = load_normalized_report(input_path)
    agent = SecurityAnalysisAgent(
        provider=provider,
        knowledge_base=knowledge_base,
    )
    records = agent.analyze(report)
    output = write_jsonl(records, output_path)
    return AnalysisRunSummary(
        input_findings=len(report.findings),
        output_groups=len(records),
        output_path=output,
        analysis_method=provider.name,
    )
