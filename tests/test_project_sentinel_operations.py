from __future__ import annotations

import json
import re

import yaml

from authz_service.policy import load_safe_api_policy
from safe_api_tool.approval import TRUSTED_RUNTIME_ORIGINS
from safe_api_tool.policy import PolicyEngine, ROOT


def test_compose_runner_uses_isolated_trusted_gateway_and_narrow_mounts() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["sentinel-runner"]
    assert service["profiles"] == ["sentinel"]
    assert service["build"]["dockerfile"] == "src/project_sentinel/Dockerfile"
    assert "--runtime-profile" in service["command"]
    assert service["command"][service["command"].index("--runtime-profile") + 1] == "compose"
    assert service["stdin_open"] is True
    assert service["tty"] is True
    assert "network_mode" not in service
    assert TRUSTED_RUNTIME_ORIGINS["compose"] == "http://envoy:8080"
    assert TRUSTED_RUNTIME_ORIGINS["host"] == "http://localhost:8080"
    volumes = service["volumes"]
    assert all(not value.startswith("./.env:") for value in volumes)
    assert "./config/safe-api-tool:/app/config/safe-api-tool:ro" in volumes
    assert "./data:/app/data:ro" in volumes
    assert "./schemas:/app/schemas:ro" in volumes
    assert "./security-results/runs/week-6:/app/security-results/runs/week-6" in volumes
    assert "ports" not in compose["services"]["api"]


def test_policy_limits_do_not_drift_across_client_authz_and_envoy() -> None:
    engine = PolicyEngine.from_files()
    authz = load_safe_api_policy(ROOT / "config" / "safe-api-tool" / "policy.json")
    envoy_text = (ROOT / "config" / "envoy" / "envoy.yaml").read_text(
        encoding="utf-8"
    )
    envoy_request_limits = {
        int(value)
        for value in re.findall(r"max_request_bytes:\s*(\d+)", envoy_text)
    }
    assert envoy_request_limits == {engine.policy.limits.max_request_bytes}
    assert authz.requests_per_minute == engine.policy.limits.requests_per_minute


def test_runner_image_has_minimal_runtime_contract_and_no_secret_copy() -> None:
    dockerfile = (ROOT / "src" / "project_sentinel" / "Dockerfile").read_text(
        encoding="utf-8"
    )
    requirements = (
        ROOT / "src" / "project_sentinel" / "requirements.txt"
    ).read_text(encoding="utf-8")
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "requirements-dev.txt" not in dockerfile
    assert "COPY .env" not in dockerfile
    assert "USER sentinel" in dockerfile
    assert "pytest" not in requirements
    assert "fastapi" not in requirements
    assert "bandit==" in requirements
    assert "jsonschema==" in requirements
    assert "rich==14.3.3" in requirements
    assert '"rich==14.3.3"' in project


def test_generated_week6_outputs_are_ignored_but_golden_can_be_tracked() -> None:
    patterns = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "/security-results/runs/week-6/*" in patterns
    assert "!/security-results/runs/week-6/golden/" in patterns
    assert "!/security-results/runs/week-6/golden/**" in patterns


def test_week6_golden_fallback_is_sanitized_and_honest() -> None:
    path = ROOT / "security-results" / "runs" / "week-6" / "golden" / "release-summary.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    text = path.read_text(encoding="utf-8")
    assert document["snapshot"] == "week-6-deterministic-fallback"
    assert document["evaluation"]["passed"] == 10
    assert document["live_controls"] == {
        "reject_requests_sent": 0,
        "approve_requests_sent": 1,
        "prompt_injection_flags": 1,
        "admin_requests_sent": 0,
        "raw_http_response_retained": False,
    }
    assert document["working_tree_claim"] == (
        "verified_dirty_worktree_not_final_release_commit"
    )
    assert document["evaluation"]["tp"] == 6
    assert document["tests"] == {
        "non_integration_passed": 216,
        "non_integration_deselected": 28,
        "full_stack_passed": 244,
    }
    assert "@" not in text
    assert "Bearer " not in text
