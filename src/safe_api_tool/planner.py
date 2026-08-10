from __future__ import annotations

import json
from pathlib import Path
import re

from pydantic import ValidationError

from safe_api_tool.models import RequestProposal
from security_pipeline.analysis.models import AnalysisFinding


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ANALYSIS_PATH = ROOT / "security-results" / "security-analysis.jsonl"
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|secret|api[_-]?key|access[_-]?token)\b"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_URL = re.compile(r"https?://[^\s)\]}>'\"]+", re.IGNORECASE)


class PlannerInputError(ValueError):
    pass


def load_analysis_findings(
    path: Path = DEFAULT_ANALYSIS_PATH,
) -> list[AnalysisFinding]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as error:
        raise PlannerInputError(f"analysis file not found: {path}") from error
    except (OSError, UnicodeError) as error:
        raise PlannerInputError(f"analysis file is unreadable: {path}") from error

    findings: list[AnalysisFinding] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            findings.append(AnalysisFinding.model_validate_json(line))
        except ValidationError as error:
            raise PlannerInputError(
                f"invalid analysis record at line {line_number}"
            ) from error
    if not findings:
        raise PlannerInputError("analysis file contains no findings")
    ids = [finding.id for finding in findings]
    if len(ids) != len(set(ids)):
        raise PlannerInputError("analysis file contains duplicate finding IDs")
    return findings


def _safe_inline_text(value: str, *, limit: int) -> str:
    redacted = _BEARER_TOKEN.sub("Bearer [REDACTED]", value)
    redacted = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        redacted,
    )
    redacted = _URL.sub("[URL]", redacted)
    collapsed = re.sub(r"[\x00-\x1f\x7f]+", " ", redacted)
    collapsed = re.sub(r"\s+", " ", collapsed).strip()
    return collapsed[:limit].rstrip()


class DeterministicSafeRequestPlanner:
    """Choose a curated capability without allowing narrative text to become HTTP."""

    name = "deterministic-safe-request-planner-v1"

    def propose(self, finding: AnalysisFinding) -> RequestProposal:
        context = " ".join(
            [
                finding.name,
                finding.explanation,
                *finding.verification_steps,
            ]
        ).lower()
        if any(
            marker in context
            for marker in ("type", "schema", "validation", "unexpected input")
        ):
            test_case_id = "wrong-type"
        elif any(
            marker in context
            for marker in ("injection", "escape", "encoding", "xss", "special")
        ):
            test_case_id = "special-characters"
        elif any(
            marker in context
            for marker in ("length", "size", "resource", "denial of service")
        ):
            test_case_id = "long-string"
        else:
            test_case_id = "empty"

        safe_name = _safe_inline_text(finding.name, limit=180) or "security finding"
        return RequestProposal(
            endpoint_id="input-validation",
            test_case_id=test_case_id,
            rationale=(
                f"Bounded {test_case_id} validation proposed for finding {safe_name}. "
                "The executor will materialize only the curated payload."
            )[:500],
            source_finding_ids=list(finding.source_finding_ids),
            requested_headers={"x-test-purpose": "week-4-safe-validation"},
        )

    def status_proposal(self) -> RequestProposal:
        return RequestProposal(
            endpoint_id="test-status",
            test_case_id="empty",
            rationale="Confirm the stateless test surface is ready through the Gateway.",
            source_finding_ids=[],
            requested_headers={},
        )


def select_finding(
    findings: list[AnalysisFinding],
    finding_id: str | None,
) -> AnalysisFinding:
    if finding_id is None:
        return findings[0]
    for finding in findings:
        if finding.id == finding_id:
            return finding
    raise PlannerInputError(f"finding ID not found: {finding_id}")


def write_proposal(proposal: RequestProposal, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.tmp")
    text = json.dumps(
        proposal.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )
    try:
        temporary_path.write_text(f"{text}\n", encoding="utf-8")
        temporary_path.replace(output_path)
    except OSError as error:
        temporary_path.unlink(missing_ok=True)
        raise PlannerInputError(f"could not write proposal: {output_path}") from error
    return output_path
