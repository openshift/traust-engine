"""``HarnessEngine.sweep`` — class-generalization sweep stages, bound to context.

Path roots and sweeps layout come from the injected context; stage functions
in ``sweep.engine`` stay stateless and receive resolved paths from here.
"""

from __future__ import annotations

from pathlib import Path

from traust_engine._ops_base import ContextOps
from traust_engine.locations import (
    FINDINGS_REL,
    PHASE0_REL,
    SCAN_TESTING_REL,
    SWEEPS_REL,
    VALIDATION_BENCHMARK_REL,
)

DEFAULT_SWEEP_LIMIT = 40


class SweepOps(ContextOps):
    def _scan_testing(self) -> Path:
        return self._analysis_results() / SCAN_TESTING_REL

    def _benchmark_dir(self) -> Path:
        return self._analysis_results() / VALIDATION_BENCHMARK_REL

    def _sweeps_root(self, override: Path | None = None) -> Path:
        return override or (self._analysis_results() / SWEEPS_REL)

    def collect(
        self,
        *,
        results_root: Path | None = None,
        phase0_root: Path | None = None,
        sweeps_root: Path | None = None,
        force: bool = False,
    ) -> dict:
        from traust_engine.sweep.engine import do_collect

        ar = self._analysis_results()
        return do_collect(
            results_root or ar / FINDINGS_REL,
            phase0_root or ar / PHASE0_REL,
            self._sweeps_root(sweeps_root),
            force=force,
        )

    def draft(
        self,
        pack: Path,
        drafts_dir: Path,
        *,
        sweeps_root: Path | None = None,
    ) -> dict:
        from traust_engine.sweep.engine import do_draft

        return do_draft(self._sweeps_root(sweeps_root), pack, drafts_dir)

    def sweep(
        self,
        rule: str,
        pack: Path,
        drafts_dir: Path,
        *,
        sweeps_root: Path | None = None,
        repos: Path | None = None,
        limit: int = DEFAULT_SWEEP_LIMIT,
        work_dir: Path | None = None,
        opengrep: str = "opengrep",
        timeout: int = 600,
    ) -> dict:
        from traust_engine.sweep.engine import do_sweep

        return do_sweep(
            rule,
            self._sweeps_root(sweeps_root),
            pack,
            drafts_dir,
            self._analysis_results(),
            repos,
            limit,
            work_dir,
            opengrep,
            timeout,
            cfg=self._ctx.corpus,
        )

    def emit(
        self,
        rule: str,
        pack: Path,
        drafts_dir: Path,
        *,
        sweeps_root: Path | None = None,
        force: bool = False,
    ) -> dict:
        from traust_engine.sweep.engine import do_emit

        return do_emit(rule, self._sweeps_root(sweeps_root), pack, drafts_dir, force=force)
