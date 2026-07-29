from __future__ import annotations

from html.parser import HTMLParser
import re
from typing import Any

from security_pipeline.models import (
    NormalizedFinding,
    make_finding_id,
    normalize_severity,
)
from security_pipeline.normalizers.base import ReportNormalizer


CONFIDENCE = {
    "0": "false_positive",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "confirmed",
}
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _plain_text(value: object) -> str:
    parser = _TextExtractor()
    parser.feed(str(value or ""))
    return " ".join(" ".join(parser.parts).split())


def _references(value: object, alert_ref: str) -> tuple[str, ...]:
    raw = str(value or "")
    references = [
        match.rstrip(".,);")
        for match in URL_PATTERN.findall(raw)
    ]
    zap_reference = f"https://www.zaproxy.org/docs/alerts/{alert_ref}/"
    if zap_reference not in references:
        references.append(zap_reference)
    return tuple(dict.fromkeys(references))


class ZapNormalizer(ReportNormalizer):
    tool = "zap"

    def supports(self, report: dict[str, Any]) -> bool:
        return (
            isinstance(report.get("site"), list)
            and "zap" in str(report.get("@programName", "")).lower()
        )

    def normalize(
        self,
        report: dict[str, Any],
        *,
        source_file: str,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        tool_version = str(report.get("@version") or "") or None

        for site in report.get("site", []):
            if not isinstance(site, dict):
                continue
            site_url = str(site.get("@name") or "unknown")
            alerts = site.get("alerts", [])
            if not isinstance(alerts, list):
                continue

            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                plugin_id = str(alert.get("pluginid") or "unknown")
                alert_ref = str(alert.get("alertRef") or plugin_id)
                title = str(
                    alert.get("name")
                    or alert.get("alert")
                    or f"ZAP alert {alert_ref}"
                )
                instances = alert.get("instances") or [{}]
                if not isinstance(instances, list):
                    instances = [{}]

                for instance in instances:
                    if not isinstance(instance, dict):
                        instance = {}
                    uri = str(instance.get("uri") or site_url)
                    method = str(instance.get("method") or "") or None
                    parameter = str(instance.get("param") or "")
                    evidence = str(instance.get("evidence") or parameter) or None
                    cwe_id = str(alert.get("cweid") or "")

                    findings.append(
                        NormalizedFinding(
                            id=make_finding_id(
                                self.tool,
                                alert_ref,
                                uri,
                                method,
                                parameter,
                            ),
                            tool=self.tool,
                            tool_version=tool_version,
                            severity=normalize_severity(alert.get("riskdesc")),
                            confidence=CONFIDENCE.get(
                                str(alert.get("confidence") or "")
                            ),
                            file_or_url=uri,
                            line=None,
                            method=method,
                            title=title,
                            description=_plain_text(alert.get("desc")),
                            rule_id=alert_ref,
                            cwe=f"CWE-{cwe_id}" if cwe_id and cwe_id != "-1" else None,
                            remediation=_plain_text(alert.get("solution")) or None,
                            references=_references(alert.get("reference"), alert_ref),
                            evidence=evidence,
                            source_file=source_file,
                            metadata={
                                "plugin_id": plugin_id,
                                "parameter": parameter or None,
                                "attack": instance.get("attack") or None,
                                "wasc_id": alert.get("wascid"),
                                "systemic": bool(alert.get("systemic", False)),
                            },
                        )
                    )
        return findings
