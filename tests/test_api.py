from fastapi.testclient import TestClient

from app.main import (
    MAX_TEST_INPUT_CHARACTERS,
    MAX_TEST_PREVIEW_CHARACTERS,
    app,
)


client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_protected_resource_metadata() -> None:
    response = client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    assert response.json() == {
        "resource": "http://localhost:8080",
        "authorization_servers": ["http://localhost:8081/realms/staging"],
        "scopes_supported": ["users:read", "admin:read"],
        "bearer_methods_supported": ["header"],
    }


def test_list_users() -> None:
    response = client.get("/api/users")

    assert response.status_code == 200
    assert response.json() == [
        {"id": 1, "name": "Ada", "role": "student"},
        {"id": 2, "name": "Grace", "role": "instructor"},
    ]


def test_test_status_describes_stateless_limits() -> None:
    response = client.get("/api/test/status")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "stateless": True,
        "max_input_characters": MAX_TEST_INPUT_CHARACTERS,
        "max_preview_characters": MAX_TEST_PREVIEW_CHARACTERS,
    }


def test_test_surface_fails_closed_if_gateway_key_reaches_backend() -> None:
    secret = "this-value-must-not-be-reflected"

    response = client.get(
        "/api/test/status",
        headers={"x-api-key": secret},
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "gateway credential reached the application boundary"
    }
    assert secret not in response.text


def test_validate_regular_string_is_deterministic() -> None:
    payload = {"value": "sentinel-check"}

    first = client.post("/api/test/validate", json=payload)
    second = client.post("/api/test/validate", json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json() == {
        "accepted": True,
        "received_length": len(payload["value"]),
        "preview": payload["value"],
        "truncated": False,
    }


def test_validate_empty_profile() -> None:
    response = client.post("/api/test/validate", json={"value": ""})

    assert response.status_code == 200
    assert response.json() == {
        "accepted": True,
        "received_length": 0,
        "preview": "",
        "truncated": False,
    }


def test_validate_long_string_profile_has_bounded_output() -> None:
    value = "x" * (MAX_TEST_PREVIEW_CHARACTERS * 4)

    response = client.post("/api/test/validate", json={"value": value})

    assert response.status_code == 200
    assert response.json() == {
        "accepted": True,
        "received_length": len(value),
        "preview": value[:MAX_TEST_PREVIEW_CHARACTERS],
        "truncated": True,
    }


def test_validate_special_characters_profile() -> None:
    value = "<tag>&\"'\\/\n\t[]{}!?@#$%^*()"

    response = client.post("/api/test/validate", json={"value": value})

    assert response.status_code == 200
    assert response.json() == {
        "accepted": True,
        "received_length": len(value),
        "preview": value,
        "truncated": False,
    }


def test_validate_wrong_type_profile_returns_controlled_422() -> None:
    response = client.post("/api/test/validate", json={"value": 42})

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert len(detail) == 1
    assert detail[0]["loc"] == ["body", "value"]
    assert detail[0]["type"] == "string_type"


def test_validate_rejects_fields_outside_the_strict_contract() -> None:
    response = client.post(
        "/api/test/validate",
        json={"value": "safe", "unexpected": "not-allowed"},
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert len(detail) == 1
    assert detail[0]["loc"] == ["body", "unexpected"]
    assert detail[0]["type"] == "extra_forbidden"


def test_admin_is_an_explicit_unauthenticated_demo() -> None:
    response = client.get("/api/admin")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Administrative demonstration endpoint",
        "authentication_enabled": False,
    }
