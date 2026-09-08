"""Load modules that formerly lived under traust/scripts/."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

_MIGRATED: dict[str, str] = {
    "corpus": "traust_engine.corpus.resolver",
    "finding_identity": "traust_engine._util.finding_identity",
    "metrics_ledger": "traust_engine.metrics.history",
    "validate_employee": "traust.cli.validate_employee",  # employee verification tool
    "fetch_feeds": "traust.cli.fetch_feeds",
    "check_drift": "traust.cli.check_drift",
    "emit_doc_variance": "traust.cli.emit_doc_variance",
    "check_skill_security": "traust.cli.check_skill_security",
    "countersign": "traust.cli.countersign",
}

_SKILL_LOCAL: dict[str, tuple[str, str]] = {
    "compliance_assert": ("compliance-check", "scripts"),
    "bootstrap_benchmark_targets": ("recall-benchmark", "scripts"),
    "match_benchmark": ("recall-benchmark", "scripts"),
    "validate_compliance_assessment": ("compliance-check", "scripts"),
    "collect_cloud_inventory": ("compliance-check", "scripts"),
    "collect_iac_inventory": ("compliance-check", "scripts"),
    "extract_app_interface_env": ("compliance-check", "scripts"),
    "run_compliance_check": ("compliance-check", "scripts"),
    "enrich_findings_cves": ("secure-code-audit", "scripts"),
}


def load_script(name: str, harness_root: Path) -> ModuleType:
    """Import a migrated engine/CLI module or a skill script."""
    if name in _MIGRATED:
        mod = importlib.import_module(_MIGRATED[name])
        sys.modules[name] = mod
        return mod

    if name in _SKILL_LOCAL:
        skill, sub = _SKILL_LOCAL[name]
        # A skill sits either at skills/<skill>/ or one level deeper under
        # a workflow stage directory, skills/<N>-<stage>/<skill>/ (legacy
        # harnessing/ paths are still tried for older checkouts).
        candidates: list[Path] = []
        for base in ("skills", "harnessing"):
            flat = harness_root / base / skill / sub / f"{name}.py"
            candidates.append(flat)
            candidates.extend(sorted(harness_root.glob(f"{base}/*/{skill}/{sub}/{name}.py")))
        path = next((p for p in candidates if p.is_file()), candidates[0])
        if not path.is_file():
            raise FileNotFoundError(path)
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {name} from {path}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod

    matches: list[Path] = []
    for base in ("skills", "harnessing"):
        matches.extend(sorted(harness_root.glob(f"{base}/**/scripts/{name}.py")))
    if matches:
        path = matches[0]
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {name} from {path}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod

    raise FileNotFoundError(f"no module {name!r} in migrated map or skills/**/scripts/")
