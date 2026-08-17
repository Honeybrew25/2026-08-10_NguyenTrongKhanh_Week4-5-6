from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal


InjectionReason = Literal[
    "instruction_override",
    "secret_exfiltration",
    "out_of_scope_tool_or_endpoint",
]

_PATTERNS: tuple[tuple[InjectionReason, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(?:ignore|disregard|override|forget)\b.{0,60}\b(?:previous|prior|system|developer)\b.{0,30}\b(?:instruction|prompt|rule)s?\b"
        ),
    ),
    (
        "secret_exfiltration",
        re.compile(
            r"(?i)\b(?:reveal|show|print|return|expose|leak)\b.{0,60}\b(?:system prompt|api[_ -]?key|password|secret|token|credential)s?\b"
        ),
    ),
    (
        "out_of_scope_tool_or_endpoint",
        re.compile(
            r"(?i)(?:\b(?:call|invoke|execute|run|open|fetch|curl|powershell|cmd|shell)\b.{0,100}(?:/api/admin|https?://|\btool\b|\bcommand\b)|/api/admin)"
        ),
    ),
)


@dataclass(frozen=True)
class InjectionSignal:
    detected: bool
    reasons: tuple[InjectionReason, ...]


def detect_prompt_injection(value: str) -> InjectionSignal:
    reasons = tuple(reason for reason, pattern in _PATTERNS if pattern.search(value))
    return InjectionSignal(detected=bool(reasons), reasons=reasons)
