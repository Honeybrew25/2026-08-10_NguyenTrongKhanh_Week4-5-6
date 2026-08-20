from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import re
from typing import Any, Mapping, Sequence


REDACTED_EMAIL = "[REDACTED_EMAIL]"
REDACTED_PHONE = "[REDACTED_PHONE]"
REDACTED_TOKEN = "[REDACTED_TOKEN]"
REDACTED_API_KEY = "[REDACTED_API_KEY]"
REDACTED_PASSWORD = "[REDACTED_PASSWORD]"
REDACTED_PII = "[REDACTED_PII]"

MARKERS = frozenset(
    {
        REDACTED_EMAIL,
        REDACTED_PHONE,
        REDACTED_TOKEN,
        REDACTED_API_KEY,
        REDACTED_PASSWORD,
        REDACTED_PII,
    }
)

_EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I)
_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.I,
)
_PHONE = re.compile(
    r"(?<!\w)(?:\+?84|0)(?:[ .-]?\d){9,10}(?!\w)",
    re.I,
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_PII_FIXTURE = re.compile(
    r"(?i)\b(?:PID|NATIONAL[-_ ]?ID|CCCD)\s*[:=-]?\s*[A-Z0-9]{6,}\b"
)

_JSON_ASSIGNMENT = re.compile(
    r'''(?ix)
    (?P<prefix>["']?
      (?P<key>
        password|passwd|secret|api[_-]?key|x-api-key|
        access[_-]?token|refresh[_-]?token|token|
        ssn|national[_-]?id|customer[_-]?id|person[_-]?id
      )
      ["']?\s*:\s*["']
    )
    (?P<value>[^"']*)
    (?P<suffix>["'])
    '''
)
_PLAIN_ASSIGNMENT = re.compile(
    r'''(?ix)
    \b(?P<key>
      password|passwd|secret|api[_-]?key|x-api-key|
      access[_-]?token|refresh[_-]?token|token|
      ssn|national[_-]?id|customer[_-]?id|person[_-]?id
    )\b
    (?P<separator>\s*[:=]\s*)
    (?P<value>[^\s,;&}\]]+)
    '''
)

_API_KEY_NAMES = frozenset({"api_key", "apikey", "x_api_key", "xapikey"})
_PASSWORD_NAMES = frozenset({"password", "passwd", "secret"})
_TOKEN_NAMES = frozenset(
    {"authorization", "access_token", "accesstoken", "refresh_token", "refreshtoken", "token"}
)
_PII_NAMES = frozenset(
    {"ssn", "national_id", "nationalid", "customer_id", "customerid", "person_id", "personid"}
)


@dataclass(frozen=True)
class RedactionResult:
    value: Any
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def _marker_for_key(key: str) -> str | None:
    normalized = _normalized_key(key)
    compact = normalized.replace("_", "")
    if normalized in _API_KEY_NAMES or compact in _API_KEY_NAMES:
        return REDACTED_API_KEY
    if normalized in _PASSWORD_NAMES or compact in _PASSWORD_NAMES:
        return REDACTED_PASSWORD
    if normalized in _TOKEN_NAMES or compact in _TOKEN_NAMES:
        return REDACTED_TOKEN
    if normalized in _PII_NAMES or compact in _PII_NAMES:
        return REDACTED_PII
    return None


def _replace_pattern(
    value: str,
    pattern: re.Pattern[str],
    marker: str,
    counts: Counter[str],
) -> str:
    def replacement(_: re.Match[str]) -> str:
        counts[marker] += 1
        return marker

    return pattern.sub(replacement, value)


def sanitize_text(
    value: str,
    *,
    api_keys: Sequence[str] = (),
    secrets: Sequence[str] = (),
) -> RedactionResult:
    """Return a redacted copy and marker counts without retaining source values."""
    # UUIDs are machine identifiers. A final group that begins with ``84`` or
    # ``0`` can otherwise look like a Vietnamese phone number by chance.
    if _UUID.fullmatch(value):
        return RedactionResult(value=value, counts={})

    redacted = value
    counts: Counter[str] = Counter()

    for secret, marker in (
        *((secret, REDACTED_API_KEY) for secret in api_keys),
        *((secret, REDACTED_TOKEN) for secret in secrets),
    ):
        if secret and secret not in MARKERS:
            occurrences = redacted.count(secret)
            if occurrences:
                redacted = redacted.replace(secret, marker)
                counts[marker] += occurrences

    redacted = _replace_pattern(redacted, _BEARER, REDACTED_TOKEN, counts)
    redacted = _replace_pattern(redacted, _JWT, REDACTED_TOKEN, counts)

    def assignment_replacement(match: re.Match[str]) -> str:
        existing = match.group("value")
        if existing in MARKERS or existing.startswith("[REDACTED_"):
            return match.group(0)
        marker = _marker_for_key(match.group("key")) or REDACTED_PII
        counts[marker] += 1
        if "prefix" in match.groupdict():
            return f'{match.group("prefix")}{marker}{match.group("suffix")}'
        return f'{match.group("key")}{match.group("separator")}{marker}'

    redacted = _JSON_ASSIGNMENT.sub(assignment_replacement, redacted)
    redacted = _PLAIN_ASSIGNMENT.sub(assignment_replacement, redacted)
    redacted = _replace_pattern(redacted, _EMAIL, REDACTED_EMAIL, counts)
    redacted = _replace_pattern(redacted, _PHONE, REDACTED_PHONE, counts)
    redacted = _replace_pattern(redacted, _PII_FIXTURE, REDACTED_PII, counts)
    return RedactionResult(value=redacted, counts=dict(sorted(counts.items())))


def sanitize_data(
    value: Any,
    *,
    api_keys: Sequence[str] = (),
    secrets: Sequence[str] = (),
) -> RedactionResult:
    """Recursively sanitize mappings/sequences into a new structure."""
    counts: Counter[str] = Counter()

    def visit(item: Any, key: str | None = None) -> Any:
        if key is not None:
            marker = _marker_for_key(key)
            if marker is not None and item is not None:
                if item == marker:
                    return item
                counts[marker] += 1
                return marker
        if isinstance(item, str):
            result = sanitize_text(item, api_keys=api_keys, secrets=secrets)
            counts.update(result.counts)
            return result.value
        if isinstance(item, Mapping):
            return {str(name): visit(child, str(name)) for name, child in item.items()}
        if isinstance(item, tuple):
            return tuple(visit(child) for child in item)
        if isinstance(item, list):
            return [visit(child) for child in item]
        return item

    sanitized = visit(value)
    return RedactionResult(value=sanitized, counts=dict(sorted(counts.items())))
