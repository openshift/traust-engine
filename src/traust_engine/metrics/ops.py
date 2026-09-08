"""``HarnessEngine.metrics`` — metrics journal, spend, SLA, bound to context."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from traust_engine._ops_base import ContextOps
from traust_engine.locations import (
    FINDINGS_DB_REL,
    METRICS_HISTORY_REL,
    feeds_cache_dir,
)
from traust_engine.metrics import attribute_spend, collect_spend, history, sla, spend


class MetricsOps(ContextOps):
    """Metrics operations bound to one loaded context.

    Paths come from ``ctx.locations``; stateless functions in sibling modules
    receive injected journal/registry/roots — the engine never self-fetches.
    """

    def _journal(self) -> Path:
        return self._progress_tracker() / METRICS_HISTORY_REL

    def _findings_db(self) -> Path:
        return self._analysis_results() / FINDINGS_DB_REL

    def _model_registry(self):
        return self._ctx.model_registry

    def _feeds_cache(self) -> Path | None:
        return feeds_cache_dir(self._loc)

    def workspace(self) -> Path:
        return self._workspace()

    def findings_db(self) -> Path:
        return self._findings_db()

    # --- metrics history -----------------------------------------------------

    def append(self, source: str, metrics: dict, note: str = "", hv: str | None = None) -> dict:
        return history.append(source, metrics, note=note, hv=hv, journal=self._journal())

    def append_if_changed(
        self, source: str, metrics: dict, note: str = "", hv: str | None = None
    ) -> dict | None:
        return history.append_if_changed(source, metrics, note=note, hv=hv, journal=self._journal())

    def rows(self) -> list[dict]:
        return history.rows(self._journal())

    def previous(self, source: str, before: str | None = None) -> dict | None:
        return history.previous(source, before=before, journal=self._journal())

    def series(self, source: str, key: str) -> list[tuple[str, object]]:
        return history.series(source, key, journal=self._journal())

    def verify(self) -> tuple[bool, list[str]]:
        return history.verify(self._journal())

    def render(self) -> tuple[Path, Path]:
        return history.render_exec(self._journal())

    # --- spend dashboard -----------------------------------------------------

    def spend_dashboard_dir(self) -> Path:
        return self._progress_tracker() / "metrics" / "dashboards" / "spend"

    def build_spend_dashboard(
        self, out_dir: Path | None = None, budget_path: Path | None = None, budget_section=None
    ) -> Path:
        return spend.build(
            self._workspace(),
            out_dir or self.spend_dashboard_dir(),
            budget_path=budget_path,
            journal=self._journal(),
            reg=self._model_registry(),
            budget_section=(
                budget_section if budget_section is not None else self._ctx.budget_policy
            ),
        )

    # --- session / attribution spend -----------------------------------------

    def session_project_dirs(self, workspace: Path | None = None) -> list[Path]:
        return collect_spend.workspace_slugs(workspace or self._workspace())

    def collect_session_spend(self, dirs: list[Path], day: str | None = None) -> dict:
        return collect_spend.collect(dirs, day)

    def append_session_spend(self, dirs: list[Path] | None = None) -> int:
        project_dirs = dirs if dirs is not None else self.session_project_dirs()
        return collect_spend.append_rows(self._workspace(), project_dirs, journal=self._journal())

    def collect_attributed(
        self,
        dirs: list[Path],
        day: str | None = None,
        month: str | None = None,
        valid: set[str] | None = None,
    ) -> dict:
        return attribute_spend.collect_attributed(dirs, day, month, valid)

    def attribute_reconcile(
        self, dirs: list[Path], day: str | None = None, month: str | None = None
    ) -> dict:
        return attribute_spend.reconcile(dirs, day, month)

    def append_attribution_rows(self, agg: dict, reg=None) -> int:
        return attribute_spend.append_rows(
            self._workspace(),
            agg,
            reg=reg if reg is not None else self._model_registry(),
            journal=self._journal(),
        )

    def render_attribution(self, agg: dict, month_label: str, reg=None) -> list[str]:
        return attribute_spend.render(
            agg,
            month_label,
            reg=reg if reg is not None else self._model_registry(),
        )

    # --- SLA views -----------------------------------------------------------

    def default_sla_policy(self) -> Path:
        return self._progress_tracker() / "configs" / "sla-policy.yaml"

    def sla_dashboard_dir(self) -> Path:
        return self._progress_tracker() / "metrics" / "dashboards" / "sla"

    def build_sla_view(
        self,
        *,
        db_path: Path | None = None,
        policy_path: Path | None = None,
        profile: str | None = None,
        as_of: dt.date | None = None,
        out_dir: Path | None = None,
        pd_cache_dir: Path | None = None,
    ) -> tuple[dict, Path]:
        db = db_path or self._findings_db()
        policy = policy_path or self.default_sla_policy()
        as_of = as_of or dt.date.today()
        policy_data = sla.load_policy(policy)
        profile_name, profile_data = sla.pick_profile(policy_data, profile)
        map_path = self._optional_config_path("product-definitions-map.yaml", self._ctx.product_map)
        pd_ctx = sla.load_product_context(
            pd_cache_dir or self._feeds_cache(),
            map_path,
        )
        view = sla.build_view(db, policy_data, profile_name, profile_data, as_of, pd_ctx)
        out = out_dir or self.sla_dashboard_dir()
        out.mkdir(parents=True, exist_ok=True)
        sla.write_sla_artifacts(view, out)
        return view, out
