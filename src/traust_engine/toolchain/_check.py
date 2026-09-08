"""Tool presence and version checks."""

from __future__ import annotations

import re
import shutil
import subprocess

from traust_engine.toolchain._parsers import db_status
from traust_engine.toolchain._types import ToolCheck


def tool_version(
    binary: str, version_cmd: list[str] | None = None, version_regex: str | None = None
) -> str | None:
    """Run a tool's version command and extract the semver."""
    cmd = version_cmd or [binary, "--version"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        text = proc.stdout + proc.stderr
    except (subprocess.SubprocessError, OSError):
        return None
    if not text.strip():
        return None
    if version_regex:
        m = re.search(version_regex, text)
        return ".".join(m.groups()) if m else None
    m = re.search(r"(\d+\.\d+\.\d+)", text)
    return m.group(1) if m else None


UNSTAMPED_VERSION = "0.0.0"


def _version_ge(installed: str, expected: str) -> bool:
    """True if installed >= expected using numeric tuple comparison."""

    def _parts(v: str) -> tuple[int, ...]:
        return tuple(int(x) for x in v.split("."))

    try:
        return _parts(installed) >= _parts(expected)
    except (ValueError, TypeError):
        return False


def check_tool(
    name: str,
    *,
    expected: str | None = None,
    version_cmd: list[str] | None = None,
    version_regex: str | None = None,
) -> ToolCheck:
    """Check whether *name* is installed, at the right version, with DB present."""
    path = shutil.which(name)
    if not path:
        return ToolCheck(name=name, installed=False)

    ver = tool_version(name, version_cmd=version_cmd, version_regex=version_regex)
    # 0.0.0 is not a version, it is an absent stamp: the Go toolchain only
    # records a version when it installs from the module proxy with a version
    # query. Treating it as "too old" sends the operator to upgrade, which
    # cannot fix it -- the install method has to change.
    unstamped = ver == UNSTAMPED_VERSION
    if ver and expected:
        ver_ok = _version_ge(ver, expected)
    elif expected and not ver:
        ver_ok = False
    else:
        ver_ok = True

    db = db_status(name)

    return ToolCheck(
        name=name, installed=True, version=ver, version_ok=ver_ok, db=db, unstamped=unstamped
    )
