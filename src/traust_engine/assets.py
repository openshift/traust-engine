"""Engine-owned assets: the engine's own version and its bundled scanner data.

NOT configuration and NOT injected: these are intrinsic to the engine package —
its version (from package metadata) and the opengrep rule pack + gitleaks config
that ship *inside* the wheel, versioned with the code. An operator never
configures them; they do not vary per estate.

Located via ``importlib`` (metadata + resources), never ``Path(__file__)``
arithmetic or a repo-layout assumption — the latter breaks the moment the
package is installed as a wheel (the original HARNESS_ROOT bug).
"""

from __future__ import annotations

import importlib.resources
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path


def _package_root() -> Path:
    """Filesystem root of the installed ``traust_engine`` package data."""
    return Path(importlib.resources.files("traust_engine"))


def harness_version() -> str:
    """Engine version, from package metadata."""
    try:
        return _pkg_version("traust-engine")
    except PackageNotFoundError:
        return "0.0.0"


def default_rule_pack_dir() -> Path:
    """Bundled opengrep rule pack directory (ships inside the package)."""
    return _package_root() / "data" / "secure-code-audit" / "opengrep-rules"


def default_gitleaks_config() -> Path:
    """Bundled gitleaks config file (ships inside the package)."""
    return (
        _package_root() / "data" / "secure-code-audit" / "gitleaks-rules" / "gitleaks-default.toml"
    )
