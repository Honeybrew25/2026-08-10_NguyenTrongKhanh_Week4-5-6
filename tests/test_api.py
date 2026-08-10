from fastapi.testclient import TestClient

from app.main import (
    MAX_TEST_INPUT_CHARACTERS,
    MAX_TEST_PREVIEW_CHARACTERS,
    app,
)


client = TestClient(app)


def test_root_redirects_get_and_head_to_dashboard() -> None:
    for method in (client.get, client.head):
        response = method("/", follow_redirects=False)

        assert response.status_code == 307
        assert response.headers["location"] == "/ui/"


def test_dashboard_static_index_supports_get_and_head() -> None:
    response = client.get("/ui/")
    head = client.head("/ui/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.content
    assert head.status_code == 200
    assert head.content == b""
    for secured_response in (response, head):
        assert "default-src 'self'" in secured_response.headers[
            "content-security-policy"
        ]
        assert secured_response.headers["cross-origin-opener-policy"] == "same-origin"
        assert secured_response.headers["referrer-policy"] == "no-referrer"
        assert secured_response.headers["x-content-type-options"] == "nosniff"
        assert secured_response.headers["x-frame-options"] == "DENY"

    for path, media_type in (
        ("/ui/styles.css", "text/css"),
        ("/ui/app.js", "application/javascript"),
        ("/ui/dashboard-data.json", "application/json"),
    ):
        asset = client.get(path)
        assert asset.status_code == 200
        assert media_type in asset.headers["content-type"]
        assert asset.content


def test_dashboard_rejects_mutating_methods_at_application_boundary() -> None:
    for path in ("/", "/ui/", "/ui/index.html"):
        response = client.post(path, content=b"not-allowed")

        assert response.status_code == 405


def test_dashboard_fails_closed_if_gateway_key_reaches_backend() -> None:
    secret = "ui-key-must-not-be-reflected"

    response = client.get("/ui/", headers={"x-api-key": secret})

    assert response.status_code == 500
    assert response.json() == {
        "detail": "gateway credential reached the application boundary"
    }
    assert secret not in response.text


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
