"""Harness Engine — processing core for the AI security harness.

Submodules:
    corpus      — population management (discovery, identity, dedup)
    metrics     — hash-chained metrics recording + spend tracking
    portfolio   — source-code dependency graph analysis
    sweep       — class-generalization scan engine
    impact      — language-aware impact analysis
    adapters    — external scanner wrappers (opengrep, osv, gitleaks, ...)
    compliance  — compliance scope + boundary resolution
    reporting   — output format handlers (validate, render, SARIF)
    registry    — model + product resolution
    escaping    — public text-safety helpers (HTML, JSON-in-script, md cells, CSV)
    _util       — leaf utilities (paths, safe_exec, elf, redact)
"""

from traust_engine.assets import harness_version as _harness_version
from traust_engine.engine import HarnessEngine

#: Engine version from installed package metadata (pyproject) — never a hardcoded
#: string that drifts from the wheel. Falls back to "0.0.0" in an uninstalled
#: source tree (see assets.harness_version).
__version__ = _harness_version()

__all__ = ["HarnessEngine"]
