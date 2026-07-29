from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from security_pipeline.models import SCHEMA_VERSION, NormalizedFinding
from security_pipeline.normalizers import (
    DEFAULT_NORMALIZERS,
    ReportNormalizer,
    select_normalizer,
)


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "unknown": 5,
}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON in {path}: {error}") from error
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return data


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def normalize_files(
    input_paths: Sequence[str | Path],
    *,
    normalizers: Sequence[ReportNormalizer] = DEFAULT_NORMALIZERS,
) -> dict[str, Any]:
    """Normalize and aggregate one or more supported scanner JSON reports."""
    if not input_paths:
        raise ValueError("At least one scanner report is required")

    findings_by_id: dict[str, NormalizedFinding] = {}
    sources: list[dict[str, Any]] = []

    for raw_path in input_paths:
        path = Path(raw_path)
        if not path.is_file():
            raise FileNotFoundError(f"Scanner report not found: {path}")
        source_file = _display_path(path)
        report = _load_json(path)
        normalizer = select_normalizer(report, normalizers)
        normalized = normalizer.normalize(report, source_file=source_file)
        duplicate_count = 0
        for finding in normalized:
            if finding.id in findings_by_id:
                duplicate_count += 1
                continue
            findings_by_id[finding.id] = finding
        sources.append(
            {
                "path": source_file,
                "tool": normalizer.tool,
                "records_read": len(normalized),
                "duplicates_ignored": duplicate_count,
            }
        )

    findings = sorted(
        findings_by_id.values(),
        key=lambda finding: (
            SEVERITY_ORDER[finding.severity],
            finding.tool,
            finding.file_or_url,
            finding.line or 0,
            finding.rule_id,
        ),
    )
    by_tool = Counter(finding.tool for finding in findings)
    by_severity = Counter(finding.severity for finding in findings)

    return {
        "schema": "schemas/normalized-findings.schema.json",
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": sources,
        "summary": {
            "total": len(findings),
            "by_tool": dict(sorted(by_tool.items())),
            "by_severity": {
                severity: by_severity[severity]
                for severity in SEVERITY_ORDER
                if by_severity[severity]
            },
        },
        "findings": [finding.to_dict() for finding in findings],
    }


def write_normalized_report(document: dict[str, Any], output_path: str | Path) -> Path:
    """Write normalized data as UTF-8 JSON using an atomic replace."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(f"{path.suffix}.tmp")
    temporary_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(path)
    return path
