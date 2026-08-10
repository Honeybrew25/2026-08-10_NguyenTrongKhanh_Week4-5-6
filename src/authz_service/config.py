from dataclasses import dataclass, field
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    issuer: str
    jwks_url: str
    audience: str
    resource_url: str
    allowed_agents: frozenset[str]
    safe_api_policy_path: Path = field(
        default_factory=lambda: Path("config/safe-api-tool/policy.json")
    )
    safe_api_tool_api_key: str | None = None

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
            safe_api_policy_path=Path(
                os.getenv(
                    "SAFE_API_POLICY_PATH",
                    "config/safe-api-tool/policy.json",
                )
            ),
            safe_api_tool_api_key=os.getenv("SAFE_API_TOOL_API_KEY"),
        )
