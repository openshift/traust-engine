"""Per-tool DB freeze env vars and CLI flags.

When freeze is active, external tools must not auto-update their
vulnerability databases during a scan. Each tool has a different
mechanism; this module centralises the knowledge.
"""

from __future__ import annotations

_FREEZE_ENV: dict[str, dict[str, str]] = {
    "grype": {
        "GRYPE_DB_AUTO_UPDATE": "false",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    },
    "syft": {
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
    },
    "govulncheck": {},
}

_FREEZE_FLAGS: dict[str, list[str]] = {
    "osv-scanner": ["--offline"],
}


def freeze_env(tool_name: str, *, db_dir: str | None = None) -> dict[str, str]:
    """Return env vars that disable auto-update for *tool_name*.

    For govulncheck, *db_dir* sets ``GOVULNDB`` to a local file mirror.
    """
    env = dict(_FREEZE_ENV.get(tool_name, {}))
    if tool_name == "govulncheck" and db_dir:
        env["GOVULNDB"] = f"file://{db_dir}"
    return env


def freeze_flags(tool_name: str) -> list[str]:
    """Return extra CLI flags that disable auto-update for *tool_name*."""
    return list(_FREEZE_FLAGS.get(tool_name, []))
