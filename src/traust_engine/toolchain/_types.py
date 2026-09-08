"""Shared dataclasses for toolchain state."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DBInfo:
    """Vuln-DB state for one tool."""

    exists: bool
    built: str | None = None
    schema_version: str | None = None
    path: str | None = None


@dataclass
class ToolCheck:
    """Result of checking one tool's readiness."""

    name: str
    installed: bool
    version: str | None = None
    version_ok: bool = False
    db: DBInfo | None = None
    # A tool can report a version that is not one. `go install` from a local
    # clone stamps v0.0.0, so govulncheck reads as "ancient" and every floor
    # fails -- pointing the operator at an upgrade that will not help. Carry
    # the distinction instead of losing it in a boolean.
    unstamped: bool = False
