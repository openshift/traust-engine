"""Ingest the artifact tree into a traust-contracts storage/v1 store.

This is the seam that makes git-or-database an ADOPTER CHOICE rather than a
fork in the code. An adopter who keeps artifacts in git runs this to
materialise a local SQLite store; an adopter on a database gets the same
rows at submit time. Either way the dashboards read the same views, because
the views are the contract and the loading is not.

Uses `corpus.resolve()` for discovery -- never a hand-rolled walk -- so the
population here is the same population `/census` counts, and the two cannot
silently disagree about what the corpus is.

Binding, and why:

  scope_id    resolved from corpus-config via CorpusConfig.scope_for(tree),
              so a deployment that partitions per business unit gets that
              partition here without a code change.
  subject_id  the corpus repo_key. This is the join key `subject_ownership`
              is keyed on, which is what lets a finding reach its owner.
  run_id      one per repo per import. The audit, its findings-current
              restatement and its triage MUST share a run_id, because
              `findings_summary` joins finding to triage_verdict on it --
              give them different runs and every verdict silently
              disappears from the summary.
  layer_id    one per repo. Layer artifacts are layer-bound, not run-bound.

Idempotent: `artifact_evidence` is content-addressed, so re-running binds
nothing new and reports `already_bound`.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from traust_contracts.config import CorpusConfig
from traust_contracts.v1.storage import Binding, IngestError, Store

from traust_engine.corpus import resolver as corpus

#: Which artifact family a resolved ref belongs to. `report_kind` splits the
#: cloud-config lane off: those documents validate against their own schema
#: and ingesting them as `report` fails on required properties they do not
#: have. Routing by kind rather than by family name is the whole fix.
FAMILY_BY_REF: dict[str, dict[str, str]] = {
    "audit_json": {
        "code-audit": "report",
        "container-audit": "report",
        "cloud-config": "cloud-config-audit",
    },
    "findings_current": {
        "code-audit": "report",
        "container-audit": "report",
        "cloud-config": "cloud-config-findings-current",
    },
    "triage_json": {
        "code-audit": "triage",
        "container-audit": "triage",
        "cloud-config": "triage",
    },
    "findings_layer": {
        "code-audit": "layer",
        "container-audit": "layer",
        "cloud-config": "layer",
    },
}


@dataclass
class IngestReport:
    ingested: int = 0
    already: int = 0
    rejected: int = 0
    missing: int = 0
    unregistered: dict[str, int] = field(default_factory=dict)
    subjects: int = 0
    by_family: dict[str, int] = field(default_factory=dict)
    reasons: dict[str, int] = field(default_factory=dict)
    failures: list[tuple[str, str]] = field(default_factory=list)

    @property
    def considered(self) -> int:
        return self.ingested + self.already + self.rejected

    def rate(self) -> float:
        return (self.ingested + self.already) / self.considered if self.considered else 0.0


def repo_key(record: corpus.ReportRecord) -> str:
    """The corpus identity of one audited subject. Mirrors findings_db."""
    parts = [record.tree]
    if record.product:
        parts.append(record.product)
    parts.extend([record.repo_dir, record.base])
    key = "/".join(parts)
    return f"{key}#cloud-config" if record.report_kind == "cloud-config" else key


def _bindings(family: str, scope: str, subject: str) -> Binding:
    if family == "layer":
        return Binding(scope_id=scope, layer_id=f"corpus:layer:{subject}")
    return Binding(scope_id=scope, subject_id=subject, run_id=f"corpus:run:{subject}")


def plan(results: Path, cfg: CorpusConfig, trees: list[str] | None = None) -> Iterator[tuple]:
    """Yield (family, scope, subject, path) for every ingestable artifact."""
    resolution = corpus.resolve(results, cfg, trees=trees, with_repo_urls=True)
    for record in resolution.records:
        subject = repo_key(record)
        try:
            scope = cfg.scope_for(record.tree)
        except KeyError:
            # corpus-config is the ownership authority. A tree it does not
            # declare has no ownership, so it has no denominator and must
            # not be counted -- but it also must not crash the run. The
            # resolver already surfaces unregistered trees as warnings;
            # this reports them the same way rather than guessing a scope.
            yield ("__unregistered__", record.tree, subject, None)
            continue
        for ref_name, by_kind in FAMILY_BY_REF.items():
            ref = getattr(record, ref_name, None)
            if not ref:
                continue
            family = by_kind.get(record.report_kind)
            if family is None:
                continue
            yield family, scope, subject, results / ref


def build_registry(results: Path, cfg: CorpusConfig, trees: list[str] | None = None) -> dict:
    """A corpus-registry artifact from the resolution.

    Ownership is the denominator every dashboard cut divides by, and it
    lives in corpus-config plus the inventory -- nowhere in the artifacts
    themselves. Without this, subject_ownership is empty and
    v_distinct_owned cannot be computed from storage/v1 at all.

    Unregistered trees are omitted for the same reason they are skipped on
    ingest: corpus-config is the ownership authority and a tree it does not
    declare has no denominator.
    """
    resolution = corpus.resolve(results, cfg, trees=trees, with_repo_urls=True)
    subjects = []
    for record in resolution.records:
        if record.tree not in cfg.trees:
            continue
        meta = cfg.trees[record.tree]
        subject: dict[str, Any] = {
            "subject_id": repo_key(record),
            "tree": record.tree,
            "ownership": meta.ownership,
            "business_unit": meta.business_unit,
            "is_branch_audit": bool(record.is_branch_audit),
        }
        for key, value in (
            ("label", meta.label),
            ("product", record.product),
            ("repo_url", record.repo_url),
            ("ref", record.ref),
        ):
            if value:
                subject[key] = value
        if record.ref_kind in ("branch", "tag", "default", "stream"):
            subject["ref_kind"] = record.ref_kind
        subjects.append(subject)
    return {
        "version": 1,
        "updated": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "subjects": subjects,
    }


def ingest_registry(store: Store, results: Path, cfg: CorpusConfig, trees=None) -> int:
    """Ingest the registry. Returns the subject count."""
    document = build_registry(results, cfg, trees)
    scope = cfg.readable_scopes()[0] if len(cfg.readable_scopes()) == 1 else cfg.scope.id
    payload = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
    store.ingest("corpus-registry", payload, Binding(scope_id=scope))
    return len(document["subjects"])


def ingest_tree(
    store: Store,
    results: Path,
    cfg: CorpusConfig,
    *,
    trees: list[str] | None = None,
    dry_run: bool = False,
) -> IngestReport:
    """Ingest every resolvable artifact. Reports rejections, never hides them."""
    report = IngestReport()
    if not dry_run:
        report.subjects = ingest_registry(store, results, cfg, trees)
    for family, scope, subject, path in plan(results, cfg, trees):
        if family == "__unregistered__":
            report.unregistered[scope] = report.unregistered.get(scope, 0) + 1
            continue
        if not path.exists():
            report.missing += 1
            continue
        payload = path.read_bytes()
        if dry_run:
            report.ingested += 1
            report.by_family[family] = report.by_family.get(family, 0) + 1
            continue
        try:
            result = store.ingest(family, payload, _bindings(family, scope, subject))
        except IngestError as error:
            report.rejected += 1
            reason = str(error).split("validation:", 1)[-1].strip()[:70]
            report.reasons[reason] = report.reasons.get(reason, 0) + 1
            if len(report.failures) < 20:
                report.failures.append((str(path), reason))
            continue
        if result.already_bound:
            report.already += 1
        else:
            report.ingested += 1
        report.by_family[family] = report.by_family.get(family, 0) + 1
    return report


def render(report: IngestReport) -> str:
    lines = [
        f"ingest: {report.ingested} new, {report.already} already bound, "
        f"{report.rejected} rejected, {report.missing} missing "
        f"({report.rate():.1%} of {report.considered} accepted)"
    ]
    for family, count in sorted(report.by_family.items(), key=lambda kv: -kv[1]):
        lines.append(f"  {count:6}  {family}")
    if report.subjects:
        lines.append(f"  {report.subjects:6}  subjects registered (ownership)")
    if report.unregistered:
        lines.append(
            "SKIPPED -- tree not declared in corpus-config, so it has no "
            "ownership and no denominator:"
        )
        for tree, count in sorted(report.unregistered.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {count:6}  {tree}")
    if report.reasons:
        lines.append("rejections:")
        for reason, count in sorted(report.reasons.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {count:6}x {reason}")
    return "\n".join(lines)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
