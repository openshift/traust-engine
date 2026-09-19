"""Tree -> storage/v1 ingest: the seam that makes git-or-database a choice."""

from __future__ import annotations

import json
import sqlite3

import yaml
from traust_contracts.config import CorpusConfig
from traust_contracts.v1.storage import Store

from traust_engine.corpus import store_ingest as si

CONFIG = yaml.safe_load("""
version: 1
trees:
  findings: {label: a, ownership: owned, business_unit: BU}
  cloud-config: {label: b, ownership: owned, business_unit: BU}
""")


def _cfg(**scope):
    payload = dict(CONFIG)
    if scope:
        payload["scope"] = scope
    return CorpusConfig(**payload)


def test_cloud_config_routes_to_its_own_family():
    """Ingesting a cloud-config document as `report` fails on required
    properties it does not have. Routing by report_kind is the fix."""
    assert si.FAMILY_BY_REF["findings_current"]["cloud-config"] == "cloud-config-findings-current"
    assert si.FAMILY_BY_REF["findings_current"]["code-audit"] == "report"
    assert si.FAMILY_BY_REF["audit_json"]["cloud-config"] == "cloud-config-audit"


def test_a_repo_audit_triage_and_current_share_one_run_id():
    """findings_summary joins finding to triage_verdict on run_id. Give them
    different runs and every verdict silently vanishes from the summary."""
    report = si._bindings("report", "local", "tree/repo/base")
    triage = si._bindings("triage", "local", "tree/repo/base")
    assert report.run_id == triage.run_id
    assert report.subject_id == triage.subject_id == "tree/repo/base"


def test_a_layer_binds_by_layer_not_by_run():
    layer = si._bindings("layer", "local", "tree/repo/base")
    assert layer.layer_id and layer.run_id is None and layer.subject_id is None


def test_scope_comes_from_config_so_partitioning_needs_no_code_change():
    assert si._bindings("report", "hybrid-platforms", "s").scope_id == "hybrid-platforms"


def test_an_unregistered_tree_is_skipped_and_reported_not_guessed(tmp_path):
    """corpus-config is the ownership authority. A tree it does not declare
    has no denominator, so it must not be counted -- and must not crash."""
    report = si.IngestReport()
    report.unregistered["lightwell-findings"] = 53
    rendered = si.render(report)
    assert "not declared in corpus-config" in rendered
    assert "lightwell-findings" in rendered


def test_render_surfaces_rejections_rather_than_hiding_them():
    report = si.IngestReport(ingested=10, rejected=2)
    report.reasons["schema rule required at /required"] = 2
    rendered = si.render(report)
    assert "rejections:" in rendered and "2x" in rendered
    assert "83.3%" in rendered or "83" in rendered


def test_repo_key_marks_cloud_config_so_it_cannot_collide():
    """A repo can have both a code audit and a cloud-config audit; they are
    different subjects and must not share an identity."""

    class R:
        tree, product, repo_dir, base = "findings", None, "org", "repo"
        report_kind = "code-audit"

    code = si.repo_key(R())
    R.report_kind = "cloud-config"
    assert si.repo_key(R()) == f"{code}#cloud-config" != code


def test_ingest_is_idempotent(tmp_path):
    """Content-addressed evidence: a second run binds nothing new."""
    results = tmp_path / "results"
    (results / "findings" / "org" / "repo").mkdir(parents=True)
    doc = {
        "metadata": {
            "audit_report": "audit.json",
            "repository": "https://example.test/r",
            "created": "2026-01-01T00:00:00Z",
            "harness_version": "0.1.0",
        },
        "events": [],
        "needs_review": [],
    }
    (results / "findings" / "org" / "repo" / "repo-findings-layer.json").write_text(json.dumps(doc))
    store = Store(sqlite3.connect(":memory:"))
    store.init()
    binding = si._bindings("layer", "local", "findings/org/repo")
    payload = json.dumps(doc).encode()
    first = store.ingest("layer", payload, binding)
    second = store.ingest("layer", payload, binding)
    assert not first.already_bound and second.already_bound
    assert first.binding_id == second.binding_id
