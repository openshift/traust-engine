"""Tests for the append-only hash-chained campaign metrics-history journal."""

import json

import pytest

from traust_engine.metrics import history as ml


@pytest.fixture(autouse=True)
def ledger_file(tmp_path, monkeypatch):
    """The journal is config-located; point it at an isolated tmp file per test."""
    p = tmp_path / "metrics-history.jsonl"
    monkeypatch.setattr(ml, "ledger_path", lambda journal=None: journal or p)
    return p


def test_append_chains_and_verifies():
    r1 = ml.append("executive-summary", {"findings_total": 100}, note="first")
    r2 = ml.append("loc-dashboard", {"total_loc": 5})
    assert r1["prev_sha"] == ""
    assert r2["prev_sha"] == r1["row_sha"]
    ok, issues = ml.verify()
    assert ok, issues


def test_tampering_detected(ledger_file):
    ml.append("executive-summary", {"findings_total": 100})
    ml.append("executive-summary", {"findings_total": 90})
    rows = [json.loads(line) for line in ledger_file.read_text().splitlines()]
    rows[0]["metrics"]["findings_total"] = 1  # rewrite history
    ledger_file.write_text("".join(json.dumps(r) + "\n" for r in rows))
    ok, issues = ml.verify()
    assert not ok
    assert any("altered" in i for i in issues)


def test_deletion_breaks_chain(ledger_file):
    ml.append("a", {"x": 1})
    ml.append("a", {"x": 2})
    ml.append("a", {"x": 3})
    lines = ledger_file.read_text().splitlines()
    ledger_file.write_text("\n".join([lines[0], lines[2]]) + "\n")  # drop the middle row
    ok, issues = ml.verify()
    assert not ok
    assert any("chain break" in i for i in issues)


def test_append_if_changed_dedupes():
    assert ml.append_if_changed("s", {"x": 1}) is not None
    assert ml.append_if_changed("s", {"x": 1}) is None  # identical
    assert ml.append_if_changed("s", {"x": 1}, note="n") is not None  # note forces
    assert ml.append_if_changed("s", {"x": 2}) is not None  # changed
    ok, _ = ml.verify()
    assert ok


def test_previous_and_series_are_per_source():
    ml.append("a", {"x": 1})
    ml.append("b", {"x": 10})
    ml.append("a", {"x": 2})
    assert ml.previous("a")["metrics"]["x"] == 2
    assert ml.previous("b")["metrics"]["x"] == 10
    assert [v for _, v in ml.series("a", "x")] == [1, 2]


def test_trend_line_and_polarity():
    prev = ml.append("executive-summary", {"findings_total": 100, "resolved_findings": 5})
    line = ml.trend_line(
        {"findings_total": 90, "resolved_findings": 9},
        prev,
        ["findings_total", "resolved_findings"],
    )
    assert "↓ 10 (improving)" in line  # fewer findings = good
    assert "↑ 4 (improving)" in line  # more resolved = good
