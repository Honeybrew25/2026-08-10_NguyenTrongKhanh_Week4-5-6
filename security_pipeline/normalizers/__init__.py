from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from security_pipeline.normalizers.bandit import BanditNormalizer
from security_pipeline.normalizers.base import ReportNormalizer
from security_pipeline.normalizers.zap import ZapNormalizer


DEFAULT_NORMALIZERS: tuple[ReportNormalizer, ...] = (
    BanditNormalizer(),
    ZapNormalizer(),
)


def select_normalizer(
    report: dict[str, Any],
    normalizers: Sequence[ReportNormalizer] = DEFAULT_NORMALIZERS,
) -> ReportNormalizer:
    matches = [normalizer for normalizer in normalizers if normalizer.supports(report)]
    if not matches:
        raise ValueError("Unsupported scanner JSON format")
    if len(matches) > 1:
        tools = ", ".join(normalizer.tool for normalizer in matches)
        raise ValueError(f"Ambiguous scanner JSON format; matched: {tools}")
    return matches[0]


__all__ = [
    "DEFAULT_NORMALIZERS",
    "ReportNormalizer",
    "select_normalizer",
]
