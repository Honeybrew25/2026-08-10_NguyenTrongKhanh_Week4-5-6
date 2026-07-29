from fastapi.testclient import TestClient

from app.main import app


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


def test_admin_is_an_explicit_unauthenticated_demo() -> None:
    response = client.get("/api/admin")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Administrative demonstration endpoint",
        "authentication_enabled": False,
    }
