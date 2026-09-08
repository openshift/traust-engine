"""HarnessEngine — the client for the processing core.

Construct once from the loaded config context (or an explicit one), then call
namespaced operations. The engine only ever *receives* its context; it never
reaches for config itself. It runs standalone — contracts + a config home is all
it needs, with no dependency on the app:

    from traust_engine import HarnessEngine

    h = HarnessEngine(ctx)                       # explicit context (tests, app)
    h.metrics.append("census", {"repos": 812})
    ok, issues = h.metrics.verify()

Namespaces mirror the engine's submodules; `.metrics` is the first migrated.
Others (`.corpus`, `.models`, `.compliance`, `.sweep`, …) follow the same shape.
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path

from traust_contracts import HarnessContext, load_context

from traust_engine.adapters.ops import AdaptersOps
from traust_engine.compliance.ops import ComplianceOps
from traust_engine.corpus.ops import CorpusOps
from traust_engine.impact.ops import ImpactOps
from traust_engine.ledger.ops import LedgerOps
from traust_engine.metrics.ops import MetricsOps
from traust_engine.portfolio.ops import PortfolioOps
from traust_engine.registry.ops import ModelsOps
from traust_engine.reporting.ops import ReportingOps
from traust_engine.sweep.ops import SweepOps
from traust_engine.toolchain.ops import ToolchainOps


class HarnessEngine:
    def __init__(self, ctx: HarnessContext) -> None:
        self._ctx = ctx

    @classmethod
    def load(cls, *, config_home: Path | None = None) -> HarnessEngine:
        """Build from config — the one canonical load point (contracts)."""
        return cls(load_context(config_home=config_home))

    @property
    def ctx(self) -> HarnessContext:
        return self._ctx

    @cached_property
    def metrics(self) -> MetricsOps:
        return MetricsOps(self._ctx)

    @cached_property
    def corpus(self) -> CorpusOps:
        return CorpusOps(self._ctx)

    @cached_property
    def models(self) -> ModelsOps:
        return ModelsOps(self._ctx)

    @cached_property
    def compliance(self) -> ComplianceOps:
        return ComplianceOps(self._ctx)

    @cached_property
    def adapters(self) -> AdaptersOps:
        return AdaptersOps(self._ctx)

    @cached_property
    def sweep(self) -> SweepOps:
        return SweepOps(self._ctx)

    @cached_property
    def ledger(self) -> LedgerOps:
        return LedgerOps(self._ctx)

    @cached_property
    def reporting(self) -> ReportingOps:
        return ReportingOps(self._ctx)

    @cached_property
    def portfolio(self) -> PortfolioOps:
        return PortfolioOps(self._ctx)

    @cached_property
    def toolchain(self) -> ToolchainOps:
        return ToolchainOps(self._ctx)

    @cached_property
    def impact(self) -> ImpactOps:
        return ImpactOps(self._ctx)
