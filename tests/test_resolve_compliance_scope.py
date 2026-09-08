#!/usr/bin/env python3
"""Tests for traust compliance scope — the compliance
boundary resolver (Phase 6). Fail-loud contract throughout:
a mis-scoped compliance run is worse than no run."""

import json

import pytest

from traust_engine.compliance import scope as rcs


def _graph(tmp_path):
    g = {
        "nodes": [
            {"id": "product:service:svc", "type": "product", "label": "Svc"},
            {
                "id": "product:service:other",
                "type": "product",
                "label": "Svc",
            },  # deliberate duplicate label
            {"id": "repo:github.com/org/api", "type": "repo"},
            {"id": "repo:github.com/org/worker", "type": "repo"},
            {"id": "repo:github.com/org/docs", "type": "repo"},
        ],
        "edges": [
            {"from": "product:service:svc", "to": "repo:github.com/org/api", "rel": "ships"},
            {"from": "product:service:svc", "to": "repo:github.com/org/worker", "rel": "ships"},
            {"from": "product:service:svc", "to": "repo:github.com/org/docs", "rel": "ships"},
        ],
    }
    p = tmp_path / "repo-graph.json"
    p.write_text(json.dumps(g))
    return p


def _scope(**boundary):
    base = {
        "frameworks": ["nist-800-53-rev5"],
        "resolves_via": "repo-graph",
        "product": "product:service:svc",
        "declared_by": "jdoe",
        "declared_at": "2026-07-30",
    }
    base.update(boundary)
    return {"version": 1, "updated": "2026-07-30", "boundaries": {"b1": base}}


def test_graph_resolution_with_exclude(tmp_path):
    g = _graph(tmp_path)
    doc = _scope(exclude=[{"repo": "org/docs", "reason": "docs only — outside boundary"}])
    res = rcs.resolve(doc, "b1", g)
    assert res["repos"] == ["org/api", "org/worker"]
    assert res["excluded"] == [{"repo": "org/docs", "reason": "docs only — outside boundary"}]
    assert res["draft"] is False


def test_include_extends_graph_set(tmp_path):
    g = _graph(tmp_path)
    doc = _scope(
        include=[
            {
                "repo": "org/deploy-config",
                "reason": "IaC repo carries the boundary's deployed configuration",
            }
        ]
    )
    res = rcs.resolve(doc, "b1", g)
    assert "org/deploy-config" in res["repos"]
    assert len(res["repos"]) == 4


def test_draft_declarant_flagged(tmp_path):
    g = _graph(tmp_path)
    res = rcs.resolve(_scope(declared_by="draft:jdoe"), "b1", g)
    assert res["draft"] is True


def test_unknown_boundary_fails_loud(tmp_path):
    with pytest.raises(rcs.ScopeError, match="unknown boundary"):
        rcs.resolve(_scope(), "nope", _graph(tmp_path))


def test_unknown_product_fails_loud(tmp_path):
    doc = _scope(product="product:service:ghost")
    with pytest.raises(rcs.ScopeError, match="not found"):
        rcs.resolve(doc, "b1", _graph(tmp_path))


def test_ambiguous_label_fails_loud(tmp_path):
    doc = _scope(product="Svc")  # matches two nodes by label
    with pytest.raises(rcs.ScopeError, match="ambiguous"):
        rcs.resolve(doc, "b1", _graph(tmp_path))


def test_stale_exclude_fails_loud(tmp_path):
    doc = _scope(exclude=[{"repo": "org/removed", "reason": "was retired"}])
    with pytest.raises(rcs.ScopeError, match="stale boundary claim"):
        rcs.resolve(doc, "b1", _graph(tmp_path))


def test_explicit_mode_requires_include(tmp_path):
    doc = _scope(resolves_via="explicit", include=[])
    with pytest.raises(rcs.ScopeError, match="non-empty include"):
        rcs.resolve(doc, "b1", _graph(tmp_path))


def test_explicit_mode_uses_only_include(tmp_path):
    doc = _scope(
        resolves_via="explicit",
        include=[{"repo": "org/only", "reason": "hand-declared boundary with no graph product"}],
    )
    res = rcs.resolve(doc, "b1", _graph(tmp_path))
    assert res["repos"] == ["org/only"]


def test_empty_resolution_fails_loud(tmp_path):
    doc = _scope(
        exclude=[
            {"repo": "org/api", "reason": "x"},
            {"repo": "org/worker", "reason": "x"},
            {"repo": "org/docs", "reason": "x"},
        ]
    )
    with pytest.raises(rcs.ScopeError, match="empty repo set"):
        rcs.resolve(doc, "b1", _graph(tmp_path))


# --------------------------------------------------------------------------
# deployment-iac mode (labeled fiction — no real product names by design;
# see the evidence-grounded-choices rule, 2026-07-30)
# --------------------------------------------------------------------------


def _inventory(tmp_path):
    inv = {
        "metadata": {"note": "FICTION fixture"},
        "services": {
            "fict-svc": {
                "repos": [
                    {
                        "url": "https://gitlab.example/fict/api",
                        "source": "iac:data/services/fict-svc/deploy.yml",
                    },
                    {
                        "url": "https://gitlab.example/fict/worker",
                        "source": "iac:data/services/fict-svc/deploy.yml",
                    },
                ]
            }
        },
    }
    p = tmp_path / "deploy-inventory.json"
    p.write_text(json.dumps(inv))
    return p


def _iac_scope(tmp_path, **over):
    base = {
        "frameworks": ["nist-800-53-rev5"],
        "resolves_via": "deployment-iac",
        "deployment_evidence": {"inventory": "deploy-inventory.json", "service": "fict-svc"},
        "declared_by": "draft:jdoe",
        "declared_at": "2026-07-30",
    }
    base.update(over)
    doc = {
        "version": 1,
        "updated": "2026-07-30",
        "boundaries": {"b1": base},
        "_scope_dir": tmp_path,
    }
    return doc


def test_deployment_iac_resolves_with_citations(tmp_path):
    _inventory(tmp_path)
    res = rcs.resolve(_iac_scope(tmp_path), "b1", tmp_path / "no-graph")
    assert res["repos"] == ["fict/api", "fict/worker"]
    assert {e["repo"]: e["source"] for e in res["evidence"]} == {
        "fict/api": "iac:data/services/fict-svc/deploy.yml",
        "fict/worker": "iac:data/services/fict-svc/deploy.yml",
    }


def test_deployment_iac_unknown_service_fails_loud(tmp_path):
    _inventory(tmp_path)
    doc = _iac_scope(tmp_path)
    doc["boundaries"]["b1"]["deployment_evidence"]["service"] = "ghost"
    with pytest.raises(rcs.ScopeError, match="not in inventory"):
        rcs.resolve(doc, "b1", tmp_path / "no-graph")


def test_deployment_iac_missing_inventory_fails_loud(tmp_path):
    with pytest.raises(rcs.ScopeError, match="inventory not found"):
        rcs.resolve(_iac_scope(tmp_path), "b1", tmp_path / "no-graph")


def test_deployment_iac_row_without_citation_fails_loud(tmp_path):
    inv = {"services": {"fict-svc": {"repos": [{"url": "https://gitlab.example/fict/api"}]}}}
    (tmp_path / "deploy-inventory.json").write_text(json.dumps(inv))
    with pytest.raises(rcs.ScopeError, match="url \\+ source"):
        rcs.resolve(_iac_scope(tmp_path), "b1", tmp_path / "no-graph")


def test_deployment_iac_exclude_still_applies(tmp_path):
    _inventory(tmp_path)
    doc = _iac_scope(
        tmp_path,
        exclude=[{"repo": "fict/worker", "reason": "batch job outside the assessed environment"}],
    )
    res = rcs.resolve(doc, "b1", tmp_path / "no-graph")
    assert res["repos"] == ["fict/api"]
