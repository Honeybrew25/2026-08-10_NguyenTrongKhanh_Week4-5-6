import json
from pathlib import Path

import pytest

from security_pipeline.knowledge import load_knowledge_base, search_knowledge
from security_pipeline.pipeline import normalize_files, write_normalized_report


ROOT = Path(__file__).resolve().parents[1]
BANDIT_REPORT = ROOT / "security-results" / "bandit-baseline.json"
ZAP_REPORT = ROOT / "security-results" / "zap-baseline-local.json"
KNOWLEDGE_BASE = ROOT / "data" / "vulnerabilities.json"
COMMON_FINDING_FIELDS = {
    "id",
    "tool",
    "tool_version",
    "severity",
    "confidence",
    "file_or_url",
    "line",
    "method",
    "title",
    "description",
    "rule_id",
    "cwe",
    "remediation",
    "references",
    "evidence",
    "source_file",
    "metadata",
}


def test_week1_reports_are_normalized_to_one_schema() -> None:
    document = normalize_files([BANDIT_REPORT, ZAP_REPORT])

    assert document["schema"] == "schemas/normalized-findings.schema.json"
    assert document["schema_version"] == "1.0"
    assert document["summary"] == {
        "total": 27,
        "by_tool": {"bandit": 21, "zap": 6},
        "by_severity": {
            "medium": 2,
            "low": 21,
            "informational": 4,
        },
    }
    assert all(set(finding) == COMMON_FINDING_FIELDS for finding in document["findings"])
    assert len({finding["id"] for finding in document["findings"]}) == 27
    assert all("\\" not in finding["file_or_url"] for finding in document["findings"])


def test_normalized_ids_are_stable() -> None:
    first = normalize_files([BANDIT_REPORT, ZAP_REPORT])
    second = normalize_files([BANDIT_REPORT, ZAP_REPORT])

    assert [finding["id"] for finding in first["findings"]] == [
        finding["id"] for finding in second["findings"]
    ]


def test_zap_html_is_converted_to_plain_text() -> None:
    document = normalize_files([ZAP_REPORT])
    finding = next(
        item for item in document["findings"] if item["rule_id"] == "10021"
    )

    assert "<p>" not in finding["description"]
    assert "<p>" not in finding["remediation"]
    assert finding["method"] == "GET"
    assert finding["file_or_url"] == "http://envoy:8080/health"


def test_normalized_report_is_valid_json(tmp_path: Path) -> None:
    output = tmp_path / "normalized.json"
    document = normalize_files([BANDIT_REPORT])

    write_normalized_report(document, output)

    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["total"] == 21
    assert not output.with_suffix(".json.tmp").exists()


@pytest.mark.parametrize(
    ("query", "expected_title"),
    [
        ("SQL Injection", "SQL Injection"),
        ("XSS", "Cross-Site Scripting (XSS)"),
        ("tiem nhiem SQL", "SQL Injection"),
    ],
)
def test_knowledge_search_returns_expected_document(
    query: str,
    expected_title: str,
) -> None:
    results = search_knowledge(query, knowledge_base=KNOWLEDGE_BASE)

    assert results
    assert results[0].document["title"] == expected_title


def test_knowledge_base_contains_between_10_and_20_examples() -> None:
    data = load_knowledge_base(KNOWLEDGE_BASE)

    assert 10 <= len(data["documents"]) <= 20
    assert all(document["references"] for document in data["documents"])


def test_unknown_scanner_format_is_rejected(tmp_path: Path) -> None:
    report = tmp_path / "unknown.json"
    report.write_text('{"findings": []}', encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported scanner JSON format"):
        normalize_files([report])
