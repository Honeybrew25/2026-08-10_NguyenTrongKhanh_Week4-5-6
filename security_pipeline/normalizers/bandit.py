from __future__ import annotations

from typing import Any

from security_pipeline.models import (
    NormalizedFinding,
    make_finding_id,
    normalize_severity,
)
from security_pipeline.normalizers.base import ReportNormalizer


def _path(value: object) -> str:
    return str(value or "unknown").replace("\\", "/")


def _unique_strings(*values: object) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        if isinstance(value, str) and value and value not in result:
            result.append(value)
    return tuple(result)


class BanditNormalizer(ReportNormalizer):
    tool = "bandit"

    def supports(self, report: dict[str, Any]) -> bool:
        return (
            isinstance(report.get("results"), list)
            and isinstance(report.get("metrics"), dict)
            and "errors" in report
        )

    def normalize(
        self,
        report: dict[str, Any],
        *,
        source_file: str,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for result in report.get("results", []):
            if not isinstance(result, dict):
                continue

            rule_id = str(result.get("test_id") or "unknown")
            filename = _path(result.get("filename"))
            line_value = result.get("line_number")
            line = line_value if isinstance(line_value, int) else None
            issue_text = str(result.get("issue_text") or "Bandit finding")
            cwe_data = result.get("issue_cwe")
            cwe_id = cwe_data.get("id") if isinstance(cwe_data, dict) else None
            cwe = f"CWE-{cwe_id}" if cwe_id else None
            cwe_link = cwe_data.get("link") if isinstance(cwe_data, dict) else None

            findings.append(
                NormalizedFinding(
                    id=make_finding_id(
                        self.tool,
                        rule_id,
                        filename,
                        line,
                        issue_text,
                    ),
                    tool=self.tool,
                    tool_version=None,
                    severity=normalize_severity(result.get("issue_severity")),
                    confidence=str(result.get("issue_confidence") or "").lower()
                    or None,
                    file_or_url=filename,
                    line=line,
                    method=None,
                    title=f"{rule_id}: {issue_text}",
                    description=issue_text,
                    rule_id=rule_id,
                    cwe=cwe,
                    remediation=(
                        "Review the flagged code in context and follow the Bandit "
                        "rule guidance."
                    ),
                    references=_unique_strings(result.get("more_info"), cwe_link),
                    evidence=str(result.get("code") or "").strip() or None,
                    source_file=source_file,
                    metadata={
                        "test_name": result.get("test_name"),
                        "line_range": result.get("line_range", []),
                        "column": result.get("col_offset"),
                        "end_column": result.get("end_col_offset"),
                    },
                )
            )
        return findings
