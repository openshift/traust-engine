"""Tests for traust_engine._util.finding_identity — cross-scan finding identity."""

import json
from pathlib import Path

from traust_engine._util import finding_identity as fi
from traust_engine.ledger import LedgerService


def _ledger(data_dir: Path) -> LedgerService:
    return LedgerService(data_dir=data_dir)


def _finding(fid, path, cwe, title, lines="10-20"):
    return {
        "id": fid,
        "title": title,
        "severity": "high",
        "cwes": [cwe],
        "locations": [{"path": path, "lines": lines}],
        "description": "x" * 60,
        "remediation": "fix it properly",
    }


def _report(repo, findings):
    return {"metadata": {"repository": repo}, "findings": findings}


def test_fingerprint_stable_across_scan_artifacts():
    a = _finding(
        "REPO-abc1234-001",
        "pkg/server/auth.go",
        "CWE-287",
        "Missing auth on sync endpoint",
        lines="10-20",
    )
    b = _finding(
        "REPO-def5678-003",
        "./pkg/server/auth.go",
        "CWE-287",
        "Sync endpoint lacks authentication",
        lines="14-25",
    )
    # different scan id, reworded title, shifted lines, ./ prefix — same identity
    assert fi.fingerprint(a, "https://github.com/org/repo") == fi.fingerprint(
        b, "git@github.com:org/repo.git"
    )


def test_fingerprint_distinguishes_cwe_and_location():
    base = _finding("R-abc1234-001", "a.go", "CWE-287", "t")
    other_cwe = _finding("R-abc1234-002", "a.go", "CWE-89", "t")
    other_path = _finding("R-abc1234-003", "b.go", "CWE-287", "t")
    r = "https://github.com/org/repo"
    assert fi.fingerprint(base, r) != fi.fingerprint(other_cwe, r)
    assert fi.fingerprint(base, r) != fi.fingerprint(other_path, r)


def test_annotate_report_sets_fingerprint_and_profile():
    rep = _report(
        "https://github.com/org/repo", [_finding("R-abc1234-001", "a.go", "CWE-287", "t")]
    )
    n = fi.annotate_report(rep)
    assert n == 2  # fingerprint + inferred audit_profile
    assert rep["metadata"]["audit_profile"] == "code"
    assert len(rep["findings"][0]["fingerprint"]) == 64
    assert fi.annotate_report(rep) == 0  # idempotent

    rpm = _report(
        "https://gitlab.example.com/dist/example/rpms/x",
        [
            dict(
                _finding("RPM_X-abc1234-001", "x.spec", "CWE-829", "unpinned source"),
                category="RPM03: Sources",
            )
        ],
    )
    fi.annotate_report(rpm)
    assert rpm["metadata"]["audit_profile"] == "rpm"


def test_match_ladder_tiers():
    old = _report(
        "https://github.com/org/repo",
        [
            _finding("R-aaa1111-001", "auth.go", "CWE-287", "No auth on sync"),
            _finding("R-aaa1111-002", "db.go", "CWE-89", "SQL injection in query"),
            _finding("R-aaa1111-003", "gone.go", "CWE-798", "Hardcoded key"),
        ],
    )
    new = _report(
        "https://github.com/org/repo",
        [
            # tier 1: same path+cwe -> same fingerprint
            _finding("R-bbb2222-001", "auth.go", "CWE-287", "Sync endpoint unauthenticated"),
            # tier 2 candidate: same path, same cwe would be tier 1 — so make a
            # re-classified CWE at same path with near-identical title -> tier 3
            _finding("R-bbb2222-002", "db.go", "CWE-943", "SQL injection in query builder"),
            # brand new finding
            _finding("R-bbb2222-004", "new.go", "CWE-352", "CSRF"),
        ],
    )
    fi.annotate_report(old)
    fi.annotate_report(new)
    r = fi.match_findings(old, new)
    assert r["mapped"]["R-aaa1111-001"]["matched_by"] == "fingerprint"
    assert r["mapped"]["R-aaa1111-002"]["matched_by"] == "path_set"
    assert r["unmatched_old"] == ["R-aaa1111-003"]
    assert r["unmatched_new"] == ["R-bbb2222-004"]


def test_rebaseline_writes_aliases_and_reviews(tmp_path):
    old = _report(
        "https://github.com/org/repo",
        [
            _finding("R-aaa1111-001", "auth.go", "CWE-287", "No auth"),
            _finding("R-aaa1111-002", "gone.go", "CWE-798", "Key"),
        ],
    )
    new = _report(
        "https://github.com/org/repo", [_finding("R-bbb2222-001", "auth.go", "CWE-287", "Unauth")]
    )
    for rep in (old, new):
        fi.annotate_report(rep)
    po, pn, pl = tmp_path / "old.json", tmp_path / "new.json", tmp_path / "layer.json"
    po.write_text(json.dumps(old))
    pn.write_text(json.dumps(new))
    pl.write_text(json.dumps({"metadata": {}, "events": [], "needs_review": []}))

    r = fi.rebaseline(po, pn, pl, ledger_service=_ledger(tmp_path))
    layer = json.loads(pl.read_text())
    al = layer["metadata"]["finding_aliases"]["R-aaa1111-001"]
    assert al["new_id"] == "R-bbb2222-001" and al["confirmed"] is True
    reasons = [i["queue_reason"] for i in layer["needs_review"]]
    assert reasons == ["rebaseline_unmatched"]
    assert r["unmatched_old"] == ["R-aaa1111-002"]


def test_rebaseline_migrates_superseded_claim_pins(tmp_path):
    # A rebaselined layer whose claim_hashes still pin old ids absent from
    # the new report would fail every future build_cumulative run. Covered
    # ids (mapped, or unmatched-with-queued-review) migrate; the new
    # report's own ids keep their pins untouched.
    old = _report(
        "https://github.com/org/repo",
        [
            _finding("FIND-001", "auth.go", "CWE-287", "No auth"),
            _finding("FIND-002", "gone.go", "CWE-798", "Key"),
        ],
    )
    new = _report(
        "https://github.com/org/repo", [_finding("R-bbb2222-001", "auth.go", "CWE-287", "Unauth")]
    )
    new["metadata"]["commit"] = "bbb2222" + "0" * 33
    for rep in (old, new):
        fi.annotate_report(rep)
    po = tmp_path / "repo-security-audit.json"
    pn = tmp_path / "new.json"
    pl = tmp_path / "layer.json"
    po.write_text(json.dumps(old))
    pn.write_text(json.dumps(new))
    pl.write_text(
        json.dumps(
            {
                "metadata": {
                    "audit_commit": "aaa1111" + "0" * 33,
                    "claim_hashes": {"FIND-001": "h1", "FIND-002": "h2"},
                },
                "events": [],
                "needs_review": [],
            }
        )
    )

    r = fi.rebaseline(po, pn, pl, ledger_service=_ledger(tmp_path))
    layer = json.loads(pl.read_text())
    assert sorted(r["migrated_claims"]) == ["FIND-001", "FIND-002"]
    assert layer["metadata"]["claim_hashes"] == {}
    assert layer["metadata"]["audit_commit"] == "bbb2222" + "0" * 33


def test_rebaseline_batch_mode_keeps_unmatched_pins(tmp_path):
    # --no-review-queue leaves unmatched old ids with no queued decision;
    # their claim pins must stay (the tamper guard would otherwise lose
    # its record without any parked disposition trail).
    old = _report(
        "https://github.com/org/repo", [_finding("FIND-002", "gone.go", "CWE-798", "Key")]
    )
    new = _report(
        "https://github.com/org/repo", [_finding("R-bbb2222-001", "auth.go", "CWE-287", "Unauth")]
    )
    for rep in (old, new):
        fi.annotate_report(rep)
    po = tmp_path / "repo-security-audit.json"
    pn = tmp_path / "new.json"
    pl = tmp_path / "layer.json"
    po.write_text(json.dumps(old))
    pn.write_text(json.dumps(new))
    pl.write_text(
        json.dumps(
            {"metadata": {"claim_hashes": {"FIND-002": "h2"}}, "events": [], "needs_review": []}
        )
    )

    r = fi.rebaseline(po, pn, pl, queue_reviews=False, ledger_service=_ledger(tmp_path))
    layer = json.loads(pl.read_text())
    assert r["migrated_claims"] == []
    assert layer["metadata"]["claim_hashes"] == {"FIND-002": "h2"}


# --- P9 / P9b: rebaseline owes a stamp, and must not write outside the tree ---


def _rebaseline_fixture(tmp_path):
    old = _report(
        "https://github.com/org/repo",
        [_finding("R-aaa1111-001", "auth.go", "CWE-287", "No auth")],
    )
    new = _report(
        "https://github.com/org/repo",
        [_finding("R-bbb2222-001", "auth.go", "CWE-287", "Unauth")],
    )
    for rep in (old, new):
        fi.annotate_report(rep)
    po, pn, pl = tmp_path / "old.json", tmp_path / "new.json", tmp_path / "layer.json"
    po.write_text(json.dumps(old))
    pn.write_text(json.dumps(new))
    pl.write_text(json.dumps({"metadata": {}, "events": [], "needs_review": []}))
    return po, pn, pl


def test_rebaseline_stamps_the_merkle_root_it_invalidates(tmp_path):
    """P9: it mutates the layer, so it owes the stamp every other writer does.

    Without it the declared root goes stale, which verify_merkle_integrity
    reports as an ERROR since traust-ledger 0.1.3.
    """
    from traust_engine.ledger import verify_merkle_integrity

    po, pn, pl = _rebaseline_fixture(tmp_path)

    fi.rebaseline(po, pn, pl, ledger_service=_ledger(tmp_path))

    layer = json.loads(pl.read_text())
    assert layer["metadata"].get("merkle_root"), "rebaseline must stamp before writing"
    errors = [f for f in verify_merkle_integrity(layer) if f.severity.name == "ERROR"]
    assert errors == [], [f.message for f in errors]


def test_rebaseline_refuses_a_layer_outside_the_tree(tmp_path):
    """P9b: a bare path let an operator typo or crafted argument write anywhere."""
    from traust_engine._util.layer_paths import LayerPathOutsideRoot

    po, pn, _ = _rebaseline_fixture(tmp_path)
    outside = tmp_path.parent / "escaped-layer.json"
    outside.write_text(json.dumps({"metadata": {}, "events": [], "needs_review": []}))

    try:
        fi.rebaseline(po, pn, outside, findings_root=tmp_path, ledger_service=_ledger(tmp_path))
    except LayerPathOutsideRoot as e:
        assert "outside the allowed root" in str(e)
    else:
        raise AssertionError("rebaseline wrote a layer outside the findings root")


def test_rebaseline_allows_a_layer_inside_the_declared_root(tmp_path):
    po, pn, pl = _rebaseline_fixture(tmp_path)

    fi.rebaseline(po, pn, pl, findings_root=tmp_path, ledger_service=_ledger(tmp_path))

    assert json.loads(pl.read_text())["metadata"]["finding_aliases"]


def test_confine_layer_path_catches_a_symlink_out_of_the_tree(tmp_path):
    """Realpath containment on both sides — a symlink is caught, not followed."""
    from traust_engine._util.layer_paths import LayerPathOutsideRoot, confine_layer_path

    root = tmp_path / "findings"
    root.mkdir()
    outside = tmp_path / "elsewhere.json"
    outside.write_text("{}")
    link = root / "layer.json"
    link.symlink_to(outside)

    try:
        confine_layer_path(link, [root])
    except LayerPathOutsideRoot:
        pass
    else:
        raise AssertionError("a symlink escaping the root was accepted")

    real = root / "real-layer.json"
    real.write_text("{}")
    assert confine_layer_path(real, [root]) == real.resolve()
