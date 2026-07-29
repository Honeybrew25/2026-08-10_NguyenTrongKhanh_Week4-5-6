from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from security_pipeline.models import NormalizedFinding


class ReportNormalizer(ABC):
    """Adapter interface for one scanner JSON format."""

    tool: str

    @abstractmethod
    def supports(self, report: dict[str, Any]) -> bool:
        """Return whether this adapter recognizes the report structure."""

    @abstractmethod
    def normalize(
        self,
        report: dict[str, Any],
        *,
        source_file: str,
    ) -> list[NormalizedFinding]:
        """Convert a scanner report into common finding records."""
