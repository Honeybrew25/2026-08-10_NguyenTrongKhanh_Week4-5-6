from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import pytest

from authz_service.config import Settings
from authz_service.security import AuthenticationError, TokenValidator


ISSUER = "http://localhost:8081/realms/staging"
AUDIENCE = "staging-api"


class StaticJwksClient:
    def __init__(self, public_key: object) -> None:
        self.public_key = public_key

    def get_signing_key_from_jwt(self, token: str) -> SimpleNamespace:
        return SimpleNamespace(key=self.public_key)


@pytest.fixture
def keys() -> tuple[object, object]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def make_validator(public_key: object) -> TokenValidator:
    settings = Settings(
        issuer=ISSUER,
        jwks_url="http://unused.test/jwks",
        audience=AUDIENCE,
        resource_url="http://localhost:8080",
        allowed_agents=frozenset({"agent-reader", "agent-admin"}),
    )
    validator = TokenValidator(settings)
    validator._jwks_client = StaticJwksClient(public_key)  # type: ignore[assignment]
    return validator


def make_token(private_key: object, **overrides: object) -> str:
    now = datetime.now(timezone.utc)
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + timedelta(minutes=5),
        "iat": now,
        "azp": "agent-reader",
        "scope": "users:read",
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test"})


def assert_reason(validator: TokenValidator, token: str, reason: str) -> None:
    with pytest.raises(AuthenticationError) as caught:
        validator.validate_authorization_header(f"Bearer {token}")
    assert caught.value.reason == reason


def test_valid_signature_and_claims_are_accepted(keys: tuple[object, object]) -> None:
    private_key, public_key = keys
    principal = make_validator(public_key).validate_authorization_header(
        f"Bearer {make_token(private_key)}"
    )

    assert principal.agent_id == "agent-reader"
    assert principal.scopes == frozenset({"users:read"})


def test_expired_token_is_rejected(keys: tuple[object, object]) -> None:
    private_key, public_key = keys
    token = make_token(
        private_key,
        exp=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    assert_reason(make_validator(public_key), token, "expired_token")


def test_wrong_audience_is_rejected(keys: tuple[object, object]) -> None:
    private_key, public_key = keys
    token = make_token(private_key, aud="different-api")

    assert_reason(make_validator(public_key), token, "wrong_audience")


def test_wrong_issuer_is_rejected(keys: tuple[object, object]) -> None:
    private_key, public_key = keys
    token = make_token(private_key, iss="http://untrusted.example/realm")

    assert_reason(make_validator(public_key), token, "wrong_issuer")


def test_invalid_signature_is_rejected(keys: tuple[object, object]) -> None:
    private_key, _ = keys
    other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = make_token(private_key)

    assert_reason(
        make_validator(other_private_key.public_key()),
        token,
        "invalid_token",
    )
