from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    issuer: str
    jwks_url: str
    audience: str
    resource_url: str
    allowed_agents: frozenset[str]

    @classmethod
    def from_environment(cls) -> "Settings":
        return cls(
            issuer=os.getenv(
                "KEYCLOAK_ISSUER",
                "http://localhost:8081/realms/staging",
            ),
            jwks_url=os.getenv(
                "KEYCLOAK_JWKS_URL",
                "http://keycloak:8080/realms/staging/protocol/openid-connect/certs",
            ),
            audience=os.getenv("JWT_AUDIENCE", "staging-api"),
            resource_url=os.getenv("PROTECTED_RESOURCE_URL", "http://localhost:8080"),
            allowed_agents=frozenset({"agent-reader", "agent-admin"}),
        )
