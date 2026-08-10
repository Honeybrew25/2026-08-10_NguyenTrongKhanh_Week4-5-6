import json
from pathlib import Path

import pytest

from authz_service.policy import PolicyConfigurationError, load_safe_api_policy


ROOT = Path(__file__).resolve().parents[1]


def test_realm_defines_placeholder_backed_machine_clients() -> None:
    realm = json.loads(
        (ROOT / "config/keycloak/staging-realm.json").read_text()
    )
    clients = {client["clientId"]: client for client in realm["clients"]}

    assert realm["defaultSignatureAlgorithm"] == "RS256"
    assert realm["accessTokenLifespan"] == 300

    reader = clients["agent-reader"]
    admin = clients["agent-admin"]

    assert reader["serviceAccountsEnabled"] is True
    assert reader["standardFlowEnabled"] is False
    assert reader["secret"] == "${AGENT_READER_CLIENT_SECRET}"
    assert reader["defaultClientScopes"] == [
        "users:read",
        "staging-api-audience",
    ]

    assert admin["serviceAccountsEnabled"] is True
    assert admin["standardFlowEnabled"] is False
    assert admin["secret"] == "${AGENT_ADMIN_CLIENT_SECRET}"
    assert admin["defaultClientScopes"] == [
        "users:read",
        "admin:read",
        "staging-api-audience",
    ]

    expired_fixture = clients["integration-expired-token"]
    assert expired_fixture["secret"] == "${INTEGRATION_EXPIRED_CLIENT_SECRET}"
    assert expired_fixture["attributes"]["access.token.lifespan"] == "2"

    audience_fixture = clients["integration-wrong-audience"]
    assert audience_fixture["secret"] == (
        "${INTEGRATION_WRONG_AUDIENCE_CLIENT_SECRET}"
    )
    assert audience_fixture["defaultClientScopes"] == [
        "users:read",
        "wrong-api-audience",
    ]


def test_envoy_external_authorization_is_fail_closed() -> None:
    config = (ROOT / "config/envoy/envoy.yaml").read_text()

    assert "envoy.filters.http.ext_authz" in config
    assert "failure_mode_allow: false" in config
    assert "status_on_error: { code: ServiceUnavailable }" in config
    assert "validate_mutations: true" in config


def test_envoy_routes_dashboard_before_the_fallback() -> None:
    config = (ROOT / "config/envoy/envoy.yaml").read_text()

    fallback = config.index('match: { prefix: "/" }')
    for route in (
        'match: { path: "/" }',
        'match: { path: "/ui" }',
        'match: { prefix: "/ui/" }',
    ):
        assert config.index(route) < fallback


def test_api_image_copy_includes_dashboard_assets() -> None:
    dockerfile = (ROOT / "src/app/Dockerfile").read_text()

    assert "COPY --chown=api:api src/app ./app" in dockerfile


def test_envoy_caps_only_the_exact_safe_post_before_authorization() -> None:
    config = (ROOT / "config/envoy/envoy.yaml").read_text()
    policy = json.loads((ROOT / "config/safe-api-tool/policy.json").read_text())
    request_limit = policy["limits"]["max_request_bytes"]

    exact_route = 'path: "/api/test/validate"'
    broad_route = 'match: { prefix: "/api/" }'
    buffer_filter = "- name: envoy.filters.http.buffer"
    authz_filter = "- name: envoy.filters.http.ext_authz"

    assert config.index(exact_route) < config.index(broad_route)
    assert 'name: ":method"' in config
    assert 'string_match: { exact: "POST" }' in config
    assert config.count(
        "type.googleapis.com/envoy.extensions.filters.http.buffer.v3.BufferPerRoute"
    ) == 1
    assert config.count(f"max_request_bytes: {request_limit}") == 2
    assert config.index(buffer_filter) < config.index(authz_filter)
    filter_config = config[config.index(buffer_filter) : config.index(authz_filter)]
    assert "disabled: true" in filter_config


def test_envoy_sends_api_key_only_to_external_authorization() -> None:
    config = (ROOT / "config/envoy/envoy.yaml").read_text()

    allowed_request_headers = config.split("allowed_headers:", maxsplit=1)[1]
    assert "- exact: x-api-key" in allowed_request_headers

    allowed_upstream_headers = config.split(
        "allowed_upstream_headers:", maxsplit=1
    )[1].split("allowed_client_headers:", maxsplit=1)[0]
    assert "x-api-key" not in allowed_upstream_headers


def test_compose_injects_secret_and_mounts_policy_read_only() -> None:
    compose = (ROOT / "docker-compose.yml").read_text()
    example_environment = (ROOT / ".env.example").read_text()

    assert "SAFE_API_TOOL_API_KEY: ${SAFE_API_TOOL_API_KEY:?" in compose
    assert "SAFE_API_POLICY_PATH: /app/config/safe-api-tool/policy.json" in compose
    assert (
        "./config/safe-api-tool/policy.json:"
        "/app/config/safe-api-tool/policy.json:ro"
    ) in compose
    assert "SAFE_API_TOOL_API_KEY=replace-with-" in example_environment


def test_authz_loads_exact_routes_and_rate_limit_from_shared_policy() -> None:
    policy = load_safe_api_policy(ROOT / "config/safe-api-tool/policy.json")

    assert policy.routes == frozenset(
        {
            ("GET", "/api/test/status"),
            ("POST", "/api/test/validate"),
        }
    )
    assert policy.requests_per_minute == 12
    assert policy.api_key.header_name == "x-api-key"
    assert policy.api_key.principal_id == "safe-api-tool"


def test_authz_rejects_policy_with_unrecognized_security_field(
    tmp_path: Path,
) -> None:
    document = json.loads(
        (ROOT / "config/safe-api-tool/policy.json").read_text()
    )
    document["api_key"]["unsafe_override"] = True
    malformed_policy = tmp_path / "policy.json"
    malformed_policy.write_text(json.dumps(document))

    with pytest.raises(PolicyConfigurationError, match="policy_schema_invalid"):
        load_safe_api_policy(malformed_policy)
