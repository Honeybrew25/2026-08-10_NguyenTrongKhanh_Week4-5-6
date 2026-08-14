from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from safe_api_tool.policy import PolicyEngine


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "app" / "static"
DATA_PATH = STATIC / "dashboard-data.json"


def load_dashboard_data() -> dict[str, Any]:
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def test_dashboard_capabilities_are_grounded_in_policy_and_catalog() -> None:
    data = load_dashboard_data()
    engine = PolicyEngine.from_files()

    assert data["project"]["policySha256"] == engine.policy_sha256
    dashboard_endpoints = {item["id"]: item for item in data["endpoints"]}
    assert set(dashboard_endpoints) == {item.id for item in engine.policy.endpoints}
    for endpoint in engine.policy.endpoints:
        displayed = dashboard_endpoints[endpoint.id]
        assert displayed["method"] == endpoint.method
        assert displayed["path"] == endpoint.path
        assert displayed["allowedTestCases"] == endpoint.allowed_test_case_ids

    dashboard_cases = {item["id"]: item for item in data["testCases"]}
    assert set(dashboard_cases) == {item.id for item in engine.catalog.test_cases}
    for test_case in engine.catalog.test_cases:
        displayed = dashboard_cases[test_case.id]
        assert displayed["expectedStatus"] == test_case.expected_status
        if displayed["kind"] == "repeated-string":
            displayed_value = displayed["character"] * displayed["length"]
        else:
            displayed_value = displayed["value"]
        assert displayed_value == test_case.payload["value"]

    radar = data["runtimeRadar"]
    assert {item["layer"] for item in radar.values()} == {"outer", "middle", "inner"}
    assert radar["gateway"]["origin"] == data["project"]["gatewayOrigin"]
    assert radar["gateway"]["healthPath"] == "/health"
    assert radar["policy"]["version"] == data["project"]["policyVersion"]
    assert radar["policy"]["sha256"] == data["project"]["policySha256"]
    assert radar["policy"]["capabilityCount"] == len(data["endpoints"])
    assert radar["policy"]["testCaseCount"] == len(data["testCases"])
    for item in radar.values():
        assert item["title"]
        assert item["description"]


def test_dashboard_evidence_is_derived_from_durable_receipts() -> None:
    data = load_dashboard_data()
    receipt_path = (
        ROOT / "security-results" / "runs" / "week-4" / "safe-api-demo.jsonl"
    )
    receipts = [
        json.loads(line)
        for line in receipt_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    events = {item["requestId"]: item for item in data["evidence"]}

    assert set(events) == {receipt["request_id"] for receipt in receipts}
    for receipt in receipts:
        event = events[receipt["request_id"]]
        expected_state = "ALLOW" if receipt["outcome"] == "success" else "DENY"
        expected_summary = (
            f'{receipt["method"]} {receipt["path"]}'
            if receipt["method"] is not None
            else receipt["reason"]
        )
        assert event["state"] == expected_state
        assert event["summary"] == expected_summary
    radar = data["runtimeRadar"]
    assert radar["evidence"]["successCount"] == sum(
        item["state"] == "ALLOW" for item in data["evidence"]
    )
    assert radar["evidence"]["deniedCount"] == sum(
        item["state"] == "DENY" for item in data["evidence"]
    )
    assert (ROOT / radar["evidence"]["source"]).is_file()


def test_dashboard_is_self_contained_and_manual_deploy_is_gated() -> None:
    data = load_dashboard_data()
    index = (STATIC / "index.html").read_text(encoding="utf-8")
    styles = (STATIC / "styles.css").read_text(encoding="utf-8")
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    workflow = (
        ROOT / ".github" / "workflows" / "deploy-ui-pages.yml"
    ).read_text(encoding="utf-8")

    assert 'href="./styles.css?v=runtime-radar-2"' in index
    assert 'src="./app.js?v=runtime-radar-2"' in index
    assert "Content-Security-Policy" in index
    assert 'role="tabpanel"' in index
    assert 'aria-controls="proposal-output"' in index
    assert 'id="runtime-radar" role="group"' in index
    assert 'id="runtime-radar-summary" aria-live="polite"' in index
    assert 'id="runtime-layer-detail" aria-live="polite"' in index
    for layer in ("gateway", "policy", "evidence"):
        assert f'id="radar-{layer}-layer"' in index
        assert f'id="{layer}-runtime-state"' in index
        assert f'data-runtime-layer="{layer}"' in index
    assert not re.search(r'(?:src|href)="https?://', index)
    for metric in data["metrics"]:
        assert f"<strong>{metric['value']}</strong>" in index
    assert "http://" not in styles and "https://" not in styles
    for unsafe_api in (
        "innerHTML",
        "outerHTML",
        "eval(",
        "localStorage",
        "sessionStorage",
        "document.cookie",
    ):
        assert unsafe_api not in script
    assert 'new URL("/health", window.location.origin)' in script
    assert "containsOnlyPrintableAscii" in script
    assert 'crypto.subtle.digest("SHA-256"' in script
    assert "handleTabKeydown" in script
    assert "initializeRuntimeRadar" in script
    assert "selectRuntimeLayer" in script
    assert 'document.querySelectorAll(".radar-hotspot")' in script
    assert 'dashboard-data.json?v=runtime-radar-2' in script
    assert 'setRuntimeLayer("gateway", "live"' in script
    assert 'setRuntimeLayer("gateway", "static"' in script
    assert '"CONTROLLED DENY"' in script
    assert '"DRY-RUN ALLOW"' in script
    assert "SAFE_API_TOOL_API_KEY" not in (
        index + styles + script + json.dumps(data)
    )

    assert "  workflow_dispatch:" in workflow
    assert "\n  push:" not in workflow
    assert "\n  pull_request:" not in workflow
    assert "if: github.ref == 'refs/heads/main'" in workflow
    assert "path: src/app/static" in workflow
    assert "find src/app/static -type l" in workflow
    assert "expected_files=" in workflow
