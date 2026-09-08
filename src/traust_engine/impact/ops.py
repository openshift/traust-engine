"""``HarnessEngine.impact`` — CVE impact analysis, bound to context."""

from __future__ import annotations

from pathlib import Path

from traust_contracts import DeploymentConfigMissing

from traust_engine import locations, storage
from traust_engine._ops_base import ContextOps


class ImpactOps(ContextOps):
    def _analysis_results_location(self) -> str | None:
        return locations.analysis_results_location(self._loc)

    def _portfolio_graph_location(self) -> str:
        return locations.require(locations.portfolio_graph_location(self._loc), "portfolio_graph")

    def _portfolio_graph_db(self) -> Path:
        return locations.require(
            locations.local_path(self._portfolio_graph_location()), "portfolio_graph"
        )

    def results_dir(self) -> Path | None:
        """Localized analysis-results root for SBOM/image tiers."""
        loc = self._analysis_results_location()
        if not loc:
            return None
        try:
            return storage.localize(loc)
        except storage.StorageError:
            return None

    def portfolio_graph_path(self) -> Path:
        """Localized portfolio graph DB for impact analysis."""
        raw = self._portfolio_graph_location()
        try:
            path = storage.localize(raw)
        except storage.StorageError as e:
            raise DeploymentConfigMissing(f"portfolio graph unusable: {e}") from e
        if path is None or not path.exists():
            raise DeploymentConfigMissing(f"portfolio graph not found at {raw}")
        return path

    def analyze(
        self,
        *,
        cve: str,
        module: str,
        ecosystem: str = "go",
        vulnerable_range: str = "",
        fixed_version: str | None = None,
        symbols: str = "",
        packages: str = "",
        feature_desc: str | None = None,
        out: str | None = None,
        jobs: int = 4,
        skip_scan: bool = False,
        db: str | None = None,
    ) -> int:
        from traust_engine.impact.analyzer import ImpactParams, _execute, valid_advisory_id

        if not valid_advisory_id(cve):
            import sys

            print(f"ERROR: '{cve}' is not a valid advisory ID", file=sys.stderr)
            return 2

        params = ImpactParams(
            cve=cve,
            module=module,
            ecosystem=ecosystem,
            vulnerable_range=vulnerable_range,
            fixed_version=fixed_version,
            symbols=symbols,
            packages=packages,
            feature_desc=feature_desc,
            out=out,
            jobs=jobs,
            skip_scan=skip_scan,
        )

        raw_db = db or self._portfolio_graph_location()
        try:
            db_path = storage.localize(raw_db)
        except storage.StorageError as e:
            import sys

            print(f"ERROR: portfolio graph unusable: {e}", file=sys.stderr)
            return 2
        if db_path is None or not db_path.exists():
            import sys

            print(f"ERROR: portfolio graph not found at {raw_db}", file=sys.stderr)
            return 1

        return _execute(params, db_path, self._analysis_results_location())
