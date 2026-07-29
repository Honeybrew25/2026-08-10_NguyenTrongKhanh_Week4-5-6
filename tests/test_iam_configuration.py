import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_realm_defines_placeholder_backed_machine_clients() -> None:
    realm = json.loads((ROOT / "keycloak/staging-realm.json").read_text())
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
    config = (ROOT / "envoy/envoy.yaml").read_text()

    assert "envoy.filters.http.ext_authz" in config
    assert "failure_mode_allow: false" in config
    assert "status_on_error: { code: ServiceUnavailable }" in config
