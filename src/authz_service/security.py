from dataclasses import dataclass
import hashlib
import hmac
import math
from threading import Lock
import time
from typing import Callable

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


class ApiKeyAuthenticationError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ApiKeyConfigurationError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ApiKeyValidator:
    """Validate a high-entropy key without retaining its plaintext value."""

    MINIMUM_KEY_BYTES = 32
    MAXIMUM_KEY_BYTES = 512

    def __init__(self, expected_key: str | None, *, principal: str) -> None:
        if expected_key is None:
            raise ApiKeyConfigurationError("api_key_not_configured")
        try:
            encoded_key = expected_key.encode("ascii")
        except UnicodeEncodeError as error:
            raise ApiKeyConfigurationError("api_key_malformed") from error
        if (
            not self.MINIMUM_KEY_BYTES <= len(encoded_key) <= self.MAXIMUM_KEY_BYTES
            or not expected_key.isprintable()
            or expected_key.strip() != expected_key
            or expected_key.startswith("replace-with-")
        ):
            raise ApiKeyConfigurationError("api_key_malformed")

        self._expected_digest = hashlib.sha256(encoded_key).digest()
        self.key_id = hashlib.sha256(encoded_key).hexdigest()[:16]
        self.principal = principal

    def validate(self, candidate: str | None) -> AgentPrincipal:
        if candidate is None:
            raise ApiKeyAuthenticationError("missing_api_key")
        try:
            encoded_candidate = candidate.encode("ascii")
        except UnicodeEncodeError as error:
            raise ApiKeyAuthenticationError("malformed_api_key") from error
        if (
            not 1 <= len(encoded_candidate) <= self.MAXIMUM_KEY_BYTES
            or not candidate.isprintable()
            or candidate.strip() != candidate
        ):
            raise ApiKeyAuthenticationError("malformed_api_key")

        candidate_digest = hashlib.sha256(encoded_candidate).digest()
        if not hmac.compare_digest(candidate_digest, self._expected_digest):
            raise ApiKeyAuthenticationError("invalid_api_key")
        return AgentPrincipal(agent_id=self.principal, scopes=frozenset())


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int


@dataclass
class _RateLimitBucket:
    window: int
    count: int


class FixedWindowRateLimiter:
    """Thread-safe, process-local limiter keyed by tool identity and exact route."""

    def __init__(
        self,
        requests_per_minute: int,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if requests_per_minute < 1:
            raise ValueError("requests_per_minute must be positive")
        self._limit = requests_per_minute
        self._clock = clock
        self._buckets: dict[tuple[str, str, str], _RateLimitBucket] = {}
        self._lock = Lock()

    def check(self, *, key_id: str, method: str, path: str) -> RateLimitDecision:
        now = max(0.0, self._clock())
        window = int(now // 60)
        bucket_key = (key_id, method.upper(), path)
        with self._lock:
            bucket = self._buckets.get(bucket_key)
            if bucket is None or bucket.window != window:
                bucket = _RateLimitBucket(window=window, count=0)
                self._buckets[bucket_key] = bucket

            retry_after = max(1, math.ceil(((window + 1) * 60) - now))
            if bucket.count >= self._limit:
                return RateLimitDecision(
                    allowed=False,
                    limit=self._limit,
                    remaining=0,
                    retry_after_seconds=retry_after,
                )

            bucket.count += 1
            return RateLimitDecision(
                allowed=True,
                limit=self._limit,
                remaining=self._limit - bucket.count,
                retry_after_seconds=retry_after,
            )

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


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
