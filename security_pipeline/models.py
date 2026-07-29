from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Any


SCHEMA_VERSION = "1.0"
VALID_SEVERITIES = {
    "informational",
    "low",
    "medium",
    "high",
    "critical",
    "unknown",
}


def normalize_severity(value: object) -> str:
    """Map scanner-specific severity text to the shared vocabulary."""
    raw = str(value or "").strip().lower()
    first_word = raw.split(maxsplit=1)[0].strip("()") if raw else ""
    aliases = {
        "info": "informational",
        "information": "informational",
        "informational": "informational",
        "warning": "medium",
        "warn": "medium",
    }
    normalized = aliases.get(first_word, first_word)
    return normalized if normalized in VALID_SEVERITIES else "unknown"


def make_finding_id(*parts: object) -> str:
    """Create a stable identifier from scanner-owned finding attributes."""
    canonical = "\x1f".join(str(part or "").strip() for part in parts)
    digest = sha256(canonical.encode("utf-8")).hexdigest()[:16]
    tool = str(parts[0] if parts else "finding").strip().lower() or "finding"
    return f"{tool}-{digest}"


@dataclass(frozen=True)
class NormalizedFinding:
    id: str
    tool: str
    severity: str
    file_or_url: str
    title: str
    description: str
    rule_id: str
    source_file: str
    tool_version: str | None = None
    confidence: str | None = None
    cwe: str | None = None
    line: int | None = None
    method: str | None = None
    remediation: str | None = None
    references: tuple[str, ...] = ()
    evidence: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Unsupported severity: {self.severity}")
        for name in ("id", "tool", "file_or_url", "title", "rule_id", "source_file"):
            if not getattr(self, name):
                raise ValueError(f"{name} must not be empty")

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["references"] = list(self.references)
        return result
