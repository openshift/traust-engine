"""``HarnessEngine.portfolio`` — portfolio graph build/query, bound to context.

Paths come from the injected ``HarnessContext``; callers use ``h.portfolio.build()``
where they used to pass ``--spine`` / ``--db`` explicitly.
"""

from __future__ import annotations

from pathlib import Path

from traust_engine import locations
from traust_engine._ops_base import ContextOps
from traust_engine.locations import REPO_GRAPH_REL
from traust_engine.portfolio import graph


class PortfolioOps(ContextOps):
    def _repo_graph(self) -> Path:
        return self._analysis_results() / REPO_GRAPH_REL

    def _portfolio_graph_db(self) -> Path:
        return locations.require(
            locations.local_path(self.portfolio_graph_location()), "portfolio_graph"
        )

    def repo_graph(self) -> Path:
        return self._repo_graph()

    def portfolio_graph_db(self) -> Path:
        return self._portfolio_graph_db()

    def portfolio_graph_location(self) -> str:
        return locations.require(locations.portfolio_graph_location(self._loc), "portfolio_graph")

    def build(
        self,
        *,
        spine: Path | None = None,
        db: Path | None = None,
        limit: int | None = None,
        jobs: int = 8,
        enrich_refs: str | None = None,
        allow_stale: bool = False,
        max_age_days: int = 30,
        ecosystems: str = "all",
        no_universal: bool = False,
        lang_cache: str = graph.DEFAULT_LANG_CACHE,
        stats_out: str | None = None,
        sleep_ms: int = 0,
    ) -> dict:
        return graph.build(
            spine or self.repo_graph(),
            db or self.portfolio_graph_db(),
            limit=limit,
            jobs=jobs,
            enrich_refs=enrich_refs,
            allow_stale=allow_stale,
            max_age_days=max_age_days,
            ecosystems=ecosystems,
            no_universal=no_universal,
            lang_cache=lang_cache,
            stats_out=stats_out,
            sleep_ms=sleep_ms,
        )

    def stats(self, db: Path | None = None, out_dir: Path | None = None) -> dict:
        return graph.stats(db or self.portfolio_graph_db(), out_dir or Path())

    def query(
        self,
        name: str,
        arg: str | None = None,
        *,
        db: Path | None = None,
        limit: int = 20,
        ecosystem: str = "go",
    ):
        return graph.query(
            db or self.portfolio_graph_db(),
            name,
            arg,
            limit=limit,
            ecosystem=ecosystem,
        )
