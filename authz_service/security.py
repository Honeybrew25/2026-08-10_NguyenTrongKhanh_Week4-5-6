from dataclasses import dataclass

import jwt
from jwt import PyJWKClient
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenError,
    PyJWKClientConnectionError,
    PyJWKClientError,
)

from authz_service.config import Settings


@dataclass(frozen=True)
class AgentPrincipal:
    agent_id: str
    scopes: frozenset[str]


class AuthenticationError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AuthorizationUnavailable(Exception):
    pass


class TokenValidator:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._jwks_client = PyJWKClient(
            settings.jwks_url,
            cache_jwk_set=True,
            lifespan=300,
            timeout=2,
        )

    def validate_authorization_header(self, header: str | None) -> AgentPrincipal:
        if not header:
            raise AuthenticationError("missing_token")

        scheme, separator, token = header.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token:
            raise AuthenticationError("malformed_authorization")

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._settings.audience,
                issuer=self._settings.issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except ExpiredSignatureError as error:
            raise AuthenticationError("expired_token") from error
        except InvalidAudienceError as error:
            raise AuthenticationError("wrong_audience") from error
        except InvalidIssuerError as error:
            raise AuthenticationError("wrong_issuer") from error
        except PyJWKClientConnectionError as error:
            raise AuthorizationUnavailable("jwks_unavailable") from error
        except (InvalidTokenError, PyJWKClientError) as error:
            raise AuthenticationError("invalid_token") from error

        agent_id = claims.get("azp") or claims.get("client_id")
        scope_claim = claims.get("scope")
        if agent_id not in self._settings.allowed_agents or not isinstance(
            scope_claim, str
        ):
            raise AuthenticationError("invalid_agent_claims")

        return AgentPrincipal(
            agent_id=agent_id,
            scopes=frozenset(scope_claim.split()),
        )
