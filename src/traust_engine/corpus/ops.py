"""``HarnessEngine.corpus`` — report-population resolution, bound to a context.

The corpus config and the analysis-results root both come from the injected
context, so callers stop passing them: ``h.corpus.resolve()`` where they used to
write ``resolve(analysis_results_dir(), load_config())``.
"""

from __future__ import annotations

from pathlib import Path

from traust_contracts import CorpusConfig

from traust_engine._ops_base import ContextOps
from traust_engine.corpus import findings_db, precedent, report_store, resolver
from traust_engine.locations import (
    FINDINGS_DB_REL,
    FP_PRECEDENT_CACHE_REL,
    progress_tracker_dir,
)


class CorpusOps(ContextOps):
    def _results_root(self, results_root: Path | None = None) -> Path:
        return results_root if results_root is not None else self._analysis_results()

    def _findings_db(self, results_root: Path | None = None) -> Path:
        return self._results_root(results_root) / FINDINGS_DB_REL

    def _fp_precedent_cache(self) -> Path:
        return self._analysis_results() / FP_PRECEDENT_CACHE_REL

    def config(self) -> CorpusConfig:
        """The typed corpus config from the context (already schema-validated)."""
        return self._ctx.corpus

    def resolve(self, trees: list[str] | None = None, with_repo_urls: bool = False):
        """Resolve the report population from the configured corpus + results root."""
        return self.resolve_under(
            self._analysis_results(), trees=trees, with_repo_urls=with_repo_urls
        )

    def resolve_under(
        self,
        analysis_root: Path,
        trees: list[str] | None = None,
        with_repo_urls: bool = False,
    ):
        """Resolve under *analysis_root* using this deployment's corpus config."""
        return resolver.resolve(
            analysis_root, self._ctx.corpus, trees=trees, with_repo_urls=with_repo_urls
        )

    def active_trees(self):
        return resolver.active_trees(self._ctx.corpus, self._analysis_results())

    def load_resolution(
        self,
        trees: list[str] | None = None,
        with_repo_urls: bool = False,
        *,
        prefer_index: bool = True,
        results_root: Path | None = None,
    ):
        """Population from findings.db when usable, else a tree walk."""
        root = self._results_root(results_root)
        return report_store.load_resolution(
            root,
            self._ctx.corpus,
            trees=trees,
            with_repo_urls=with_repo_urls,
            prefer_index=prefer_index,
        )

    def report_store(self, results_root: Path | None = None) -> report_store.ReportStore:
        """Accessor for report JSON under the configured (or overridden) results root."""
        return report_store.ReportStore(report_store.LocalBackend(self._results_root(results_root)))

    def to_ref(self, value: str | None, results_root: Path | None = None) -> str | None:
        """Relativize an artifact path against the corpus root (symlink-safe)."""
        return report_store.to_ref(value, self._results_root(results_root))

    def build_findings_db(
        self,
        out: Path | None = None,
        trees: list[str] | None = None,
    ) -> tuple[dict, Path]:
        """Build the SQLite findings projection under the configured results root."""
        out_path = out or self._findings_db()
        counts = findings_db.build(
            self._analysis_results(),
            out_path,
            trees=trees,
            cfg=self._ctx.corpus,
            progress_tracker=progress_tracker_dir(self._loc),
        )
        return counts, out_path

    def build_fp_precedent_cache(
        self,
        taxonomy_path: Path | None = None,
        *,
        out: Path | None = None,
    ) -> tuple[dict, Path]:
        """Rebuild the shared-component FP-precedent cache from the corpus."""
        cache = precedent.build_cache(
            self._analysis_results(),
            self._ctx.corpus,
            taxonomy_path=taxonomy_path,
        )
        return cache, out or self._fp_precedent_cache()

    def match_findings(self, cache: dict, findings: list[dict]) -> list[dict]:
        """Annotate findings with FP-precedent matches (never auto-verdict)."""
        return precedent.match_findings(cache, findings)
