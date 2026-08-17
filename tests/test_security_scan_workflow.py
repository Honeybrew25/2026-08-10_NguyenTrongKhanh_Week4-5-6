from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security-scan.yml"


def _job_block(workflow: str, job_name: str) -> str:
    match = re.search(
        rf"^  {re.escape(job_name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
        workflow,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"Missing workflow job: {job_name}"
    return match.group(0)


def test_bandit_data_scan_is_separate_from_high_release_gate() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    unit_job = _job_block(workflow, "unit-and-sast")

    assert "--output security-results/bandit-ci-full.json" in unit_job
    assert "--severity-level low" in unit_job
    assert "--output security-results/bandit-ci-high.json" in unit_job
    assert "--severity-level high" in unit_job
    assert "steps.bandit_high.outcome == 'failure'" in unit_job
    assert "bandit-ci-SHA256SUMS.txt" in unit_job
    assert "security-results/normalized-findings.json" not in unit_job


def test_fresh_analysis_consumes_same_run_bandit_and_zap_artifacts() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    analysis_job = _job_block(workflow, "fresh-analysis")

    assert "- unit-and-sast" in analysis_job
    assert "- dast" in analysis_job
    assert "name: bandit-json" in analysis_job
    assert "name: zap-baseline-report" in analysis_job
    assert (
        "security-results/ci-inputs/bandit/bandit-ci-full.json" in analysis_job
    )
    assert "security-results/ci-inputs/zap/zap-baseline-ci.json" in analysis_job
    assert "security-results/runs/ci/normalized-findings.json" in analysis_job
    assert "--provider deterministic" in analysis_job
    assert "security-results/runs/ci/security-analysis.jsonl" in analysis_job
    assert "name: fresh-security-analysis" in analysis_job
    assert "SHA256SUMS.txt" in analysis_job


def test_dast_scope_is_explicitly_passive_and_unauthenticated() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    dast_job = _job_block(workflow, "dast")

    assert "OWASP ZAP passive baseline (unauthenticated)" in dast_job
    assert "Run ZAP passive baseline from public health seed" in dast_job
    assert '-t "http://envoy:8080/health"' in dast_job
    assert "-I" in dast_job
    assert "Authorization: Bearer" not in dast_job


def test_image_publish_waits_for_fresh_analysis() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    publish_job = _job_block(workflow, "publish-images")

    assert "- fresh-analysis" in publish_job
    assert "- week6-e2e" in publish_job


def test_week6_e2e_uses_fresh_artifacts_and_uploads_release_contracts() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    job = _job_block(workflow, "week6-e2e")

    assert "- unit-and-sast" in job
    assert "- dast" in job
    assert "- fresh-analysis" in job
    assert "name: bandit-json" in job
    assert "name: zap-baseline-report" in job
    assert "python -m project_sentinel run" in job
    assert "--provider deterministic" in job
    assert "python -m project_sentinel evaluate" in job
    assert "verify_week6_artifacts.py" in job
    assert "final-report.json" in job
    assert "evaluation-summary.json" in job
    assert "verification-ci.json" in job
    assert "retention-days: 14" in job
    assert "GEMINI_API_KEY" not in job
