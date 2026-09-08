"""Scope gating for crypto_audit.py's cluster tier (oc exec = engagement
action; the k8s adapter's exec verb + control-plane hard-deny apply)."""

import json

import pytest

from traust_engine.adapters import crypto_audit as ca

pytest.importorskip("yaml")


def _targets(tmp_path, namespaces):
    f = tmp_path / "targets.yaml"
    f.write_text(
        "engagement: t\nauthorized_by: t\nclusters:\n"
        f"  - context: lab\n    namespaces: {namespaces}\n"
    )
    return f


def test_cluster_requires_targets(tmp_path):
    with pytest.raises(ValueError, match="targets"):
        ca.audit_cluster("lab", ["ns1"], targets="")


def test_denied_namespaces_skipped_and_audited(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    called = []
    monkeypatch.setattr(
        ca,
        "run_cluster",
        lambda ctx, nss, **kw: (
            called.append(nss)
            or {
                "schema": "crypto-audit/v1",
                "tier": "runtime",
                "component": "",
                "facts": [],
                "errors": [],
                "summary": {"total_facts": 0},
            }
        ),
    )
    targets = _targets(tmp_path, "[app-ns]")
    out = tmp_path / "out.json"
    rc = ca.audit_cluster(
        "lab",
        ["app-ns", "openshift-kube-apiserver"],
        targets=targets,
        output=out,
        quiet=True,
    )
    assert rc == 0
    assert called == [["app-ns"]]  # control-plane ns never probed
    audit = (tmp_path / "crypto-audit-scope.jsonl").read_text()
    lines = [json.loads(x) for x in audit.splitlines()]
    assert any(not e["scope_allowed"] and "openshift-kube-apiserver" in e["action"] for e in lines)
    doc = json.loads(out.read_text())
    assert any("scope denied" in e for e in doc["errors"])


def test_control_plane_probeable_only_with_explicit_listing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    called = []
    monkeypatch.setattr(
        ca,
        "run_cluster",
        lambda ctx, nss, **kw: (
            called.append(nss)
            or {
                "schema": "crypto-audit/v1",
                "tier": "runtime",
                "component": "",
                "facts": [],
                "errors": [],
                "summary": {"total_facts": 0},
            }
        ),
    )
    targets = _targets(tmp_path, "[openshift-kube-apiserver]")
    rc = ca.audit_cluster(
        "lab",
        ["openshift-kube-apiserver"],
        targets=targets,
        output=tmp_path / "o.json",
        quiet=True,
    )
    assert rc == 0
    assert called == [["openshift-kube-apiserver"]]


def test_all_denied_is_fail_closed_empty_payload(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ca, "run_cluster", lambda *a, **k: pytest.fail("probed out of scope"))
    targets = _targets(tmp_path, "[app-ns]")
    out = tmp_path / "o.json"
    rc = ca.audit_cluster(
        "OTHER-ctx",
        ["app-ns"],
        targets=targets,
        output=out,
        quiet=True,
    )
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc["facts"] == [] and doc["errors"]
