"""Pre-flight validation — fail-closed tool checks before skill execution."""

from __future__ import annotations

from traust_engine.toolchain._check import check_tool
from traust_engine.toolchain._types import ToolCheck


def preflight(required_tools: list[str], pins: dict[str, dict] | None = None) -> list[ToolCheck]:
    """Validate that all *required_tools* are ready.

    *pins* maps tool name to its spec from external-tools.yaml (at minimum
    ``{"expected": "1.2.3"}``; may also include ``version_cmd`` and
    ``version_regex``).

    Returns a list of ToolCheck results. Every entry with
    ``installed=False`` or ``version_ok=False`` or a DB that doesn't
    exist is a failure — the caller should refuse to run the skill.
    """
    pins = pins or {}
    results: list[ToolCheck] = []
    for name in required_tools:
        spec = pins.get(name, {})
        tc = check_tool(
            name,
            expected=spec.get("expected"),
            version_cmd=spec.get("version_cmd"),
            version_regex=spec.get("version_regex"),
        )
        results.append(tc)
    return results


def preflight_failures(results: list[ToolCheck]) -> list[str]:
    """Return human-readable failure messages from preflight results."""
    msgs: list[str] = []
    for tc in results:
        if not tc.installed:
            msgs.append(f"{tc.name}: not found on PATH")
        elif getattr(tc, "unstamped", False):
            msgs.append(
                f"{tc.name}: reports version {tc.version}, which means the "
                f"binary carries no version stamp -- it was not installed from "
                f"the module proxy. Reinstall with a version query "
                f"(e.g. `go install <module>@latest`); upgrading will not help"
            )
        elif not tc.version_ok:
            msgs.append(f"{tc.name}: version {tc.version} does not meet pin")
        elif tc.db is not None and not tc.db.exists:
            msgs.append(f"{tc.name}: vulnerability DB not found at {tc.db.path}")
    return msgs
