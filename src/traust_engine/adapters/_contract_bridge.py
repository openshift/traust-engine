"""Shared contract-model helpers for adapter scan() functions."""

from __future__ import annotations

import datetime
from typing import Any

from traust_contracts.enums import Severity
from traust_contracts.models import (
    AdapterMetadata,
    AdapterResult,
    AdapterSummary,
    EvidenceBlock,
    Finding,
    Location,
)


def utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
}


def map_severity(hint: str, default: str = "low") -> Severity:
    return _SEVERITY_MAP.get((hint or default).lower(), Severity.LOW)


def format_lines(start: int | None, end: int | None) -> str:
    if not start:
        return ""
    if end and end != start:
        return f"{start}-{end}"
    return str(start)


def build_adapter_result(
    target: str,
    tool: str,
    findings_data: list[dict[str, Any]],
    *,
    scanned_at: str | None = None,
    scanner_version: str = "",
    focus_areas: list[str] | None = None,
) -> AdapterResult:
    """Build AdapterResult from raw finding dicts produced by adapter parsers."""
    scanned_at = scanned_at or utc_now()
    by_severity: dict[str, int] = {}
    for item in findings_data:
        sev = item.get("severity", "low")
        key = sev.value if hasattr(sev, "value") else str(sev)
        by_severity[key] = by_severity.get(key, 0) + 1

    findings: list[Finding] = []
    for item in findings_data:
        locations = [
            loc if isinstance(loc, Location) else Location(**loc)
            for loc in item.get("locations", [])
        ]
        evidence = [
            ev if isinstance(ev, EvidenceBlock) else EvidenceBlock(**ev)
            for ev in item.get("evidence", [])
        ]
        sev = item.get("severity", Severity.LOW)
        if isinstance(sev, str):
            sev = map_severity(sev)
        findings.append(
            Finding(
                id=item["id"],
                title=item["title"],
                severity=sev,
                cwes=item.get(
                    "cwes",
                    [],
                ),
                locations=locations,
                description=item.get("description", ""),
                remediation=item.get("remediation", ""),
                evidence=evidence,
                category=item.get("category", ""),
                origin=item.get("origin", tool),
                fingerprint=item.get("fingerprint", ""),
                source_findings=item.get("source_findings", []),
            )
        )

    return AdapterResult(
        target=target,
        scanned_at=scanned_at,
        focus_areas=focus_areas or [],
        metadata=AdapterMetadata(tool=tool, scanner_version=scanner_version),
        findings=findings,
        summary=AdapterSummary(total=len(findings), by_severity=by_severity),
    )


# Backwards-compatible alias used by existing adapters
build_scan_result = build_adapter_result
