"""Populate tool vulnerability DBs.

Usage (standalone):
    python3 -m traust_engine.toolchain._fetch_dbs --tools grype osv-scanner

For profile-based usage, use the CLI layer which owns the manifest:
    python3 -m traust.cli.toolchain fetch-dbs --profile secure-code-audit
"""

from __future__ import annotations

import os
import subprocess

from traust_engine.toolchain._parsers import _OSV_CACHE_DIR, db_status

_POPULATE_CMDS: dict[str, list[list[str]]] = {
    "grype": [["grype", "db", "update"]],
    "osv-scanner": [
        [
            "osv-scanner",
            "scan",
            "source",
            "--offline-vulnerabilities",
            "--download-offline-databases",
            "-r",
            ".",
        ],
    ],
}

POPULATABLE_TOOLS: frozenset[str] = frozenset(_POPULATE_CMDS)


def populate(tool_name: str) -> tuple[bool, str]:
    """Run the DB populate command for *tool_name*.

    Returns (success, message).
    """
    cmds = _POPULATE_CMDS.get(tool_name)
    if cmds is None:
        return True, f"{tool_name}: no DB to populate"

    for cmd in cmds:
        try:
            env = None
            if tool_name == "osv-scanner":
                env = {**os.environ, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(_OSV_CACHE_DIR)}
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
            if proc.returncode != 0 and tool_name != "osv-scanner":
                err = proc.stderr.strip()[:500]
                return False, (
                    f"{tool_name}: {' '.join(cmd)} failed (exit {proc.returncode}): {err}"
                )
        except FileNotFoundError:
            return False, f"{tool_name}: {cmd[0]} not found on PATH"
        except subprocess.TimeoutExpired:
            return False, f"{tool_name}: {' '.join(cmd)} timed out"

    info = db_status(tool_name)
    if tool_name == "osv-scanner" and (info is None or not info.exists):
        return False, f"{tool_name}: DB download failed — cache not found"
    built = info.built if info else "unknown"
    return True, f"{tool_name}: DB populated (built {built})"
