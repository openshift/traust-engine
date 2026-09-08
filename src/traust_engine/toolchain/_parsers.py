"""Per-tool DB status parsers.

Each parser probes the tool's native cache location and returns a DBInfo
describing the current state of its vulnerability database.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from traust_engine.toolchain._types import DBInfo

# Native DB cache locations (platform-dependent defaults)
_GRYPE_DB_DIR = Path(
    os.environ.get(
        "GRYPE_DB_CACHE_DIR",
        Path.home() / ".cache" / "grype" / "db",
    )
)
_OSV_CACHE_DIR = Path(
    os.environ.get(
        "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY",
        Path.home() / ".cache" / "osv-scanner",
    )
)


def _parse_grype_db_status() -> DBInfo:
    """Parse ``grype db status`` output for build date and schema."""
    try:
        proc = subprocess.run(
            ["grype", "db", "status"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        text = proc.stdout + proc.stderr
    except (subprocess.SubprocessError, OSError):
        return DBInfo(exists=False)

    built = None
    schema = None
    location = None
    for line in text.splitlines():
        if m := re.match(r"^\s*Built:\s*(.+)", line):
            built = m.group(1).strip()
        elif m := re.match(r"^\s*Schema:\s*(\S+)", line):
            schema = m.group(1).strip()
        elif m := re.match(r"^\s*Location:\s*(.+)", line):
            location = m.group(1).strip()

    db_dir = Path(location) if location else _GRYPE_DB_DIR
    exists = any(db_dir.glob("*/vulnerability.db")) if db_dir.is_dir() else False

    return DBInfo(
        exists=exists or built is not None, built=built, schema_version=schema, path=str(db_dir)
    )


def _parse_osv_db_status() -> DBInfo:
    """Check osv-scanner offline DB cache."""
    if not _OSV_CACHE_DIR.is_dir():
        return DBInfo(exists=False, path=str(_OSV_CACHE_DIR))

    entries = [p for p in _OSV_CACHE_DIR.iterdir() if p.is_dir() or p.suffix == ".zip"]
    if not entries:
        return DBInfo(exists=False, path=str(_OSV_CACHE_DIR))

    latest_mtime = max(e.stat().st_mtime for e in entries)
    from datetime import UTC, datetime

    built = datetime.fromtimestamp(latest_mtime, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return DBInfo(exists=True, built=built, path=str(_OSV_CACHE_DIR))


def _parse_govulncheck_db_status() -> DBInfo:
    """govulncheck DB info is extracted from scan output, not a status command.

    This parser returns a stub; the real DB metadata comes from parsing
    the govulncheck -json config record during scan (see govulncheck adapter).
    """
    return DBInfo(exists=True)


_PARSERS: dict[str, callable] = {
    "grype": _parse_grype_db_status,
    "osv-scanner": _parse_osv_db_status,
    "govulncheck": _parse_govulncheck_db_status,
}

# Tools that have no vuln DB
_NO_DB_TOOLS = {"opengrep", "gitleaks", "syft", "skopeo", "cosign", "yara", "joern", "pip-audit"}


def db_status(tool_name: str) -> DBInfo | None:
    """Return DB status for *tool_name*, or None if the tool has no DB."""
    if tool_name in _NO_DB_TOOLS:
        return None
    parser = _PARSERS.get(tool_name)
    if parser is None:
        return None
    return parser()
