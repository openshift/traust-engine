"""Tests for traust sweep rule-lane — the rule-mining lane
runner's deterministic delta computation and rendering."""

import json
import shutil
from pathlib import Path

import yaml

from traust_engine.sweep import rule_lane as lane

_FIXTURE_CONFIG = Path(__file__).parent / "fixtures" / "config"


def _with_config_home(monkeypatch, ws: Path, tmp_path: Path):
    home = tmp_path / "cfg"
    shutil.copytree(_FIXTURE_CONFIG, home)
    (home / "locations.yaml").write_text(
        yaml.safe_dump(
            {
                "workspace": str(ws),
                "analysis_results": str(ws / "analysis-results"),
                "progress_tracker": str(ws / "progress-tracker"),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    from traust_engine import HarnessEngine

    return HarnessEngine.load()


def _mining(confirmed=100, ruleable=80, uncovered=None, covered=None, precision=None):
    return {
        "tool": "mine_ledger_truepositives",
        "stats": {"cumulative_reports": 10, "confirmed_tps": confirmed, "ruleable_tps": ruleable},
        "uncovered_clusters": uncovered or [],
        "covered_clusters": covered or [],
        "rule_precision": precision or {},
        "calibration_worklist": [],
    }


def _cluster(cwe, lang, count, examples=None):
    return {
        "cwe": cwe,
        "language": lang,
        "count": count,
        "repos": 2,
        "example_findings": examples or [f"{cwe}-ex-1"],
    }


def test_resolve_emit_drafts_script_sibling_checkout(tmp_path):
    rel = lane._EMIT_DRAFTS_REL_PATHS[0]
    emit = tmp_path / "traust" / rel
    emit.parent.mkdir(parents=True)
    emit.write_text("# stub\n", encoding="utf-8")
    assert lane._resolve_emit_drafts_script(tmp_path, None) == emit.resolve()


def test_resolve_emit_drafts_script_harness_as_workspace(tmp_path):
    rel = lane._EMIT_DRAFTS_REL_PATHS[0]
    emit = tmp_path / rel
    emit.parent.mkdir(parents=True)
    emit.write_text("# stub\n", encoding="utf-8")
    assert lane._resolve_emit_drafts_script(tmp_path, None) == emit.resolve()


def test_resolve_emit_drafts_script_explicit_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("EMIT_RULE_DRAFTS_SCRIPT", "/nope")
    explicit = tmp_path / "custom.py"
    explicit.write_text("# stub\n", encoding="utf-8")
    assert lane._resolve_emit_drafts_script(tmp_path, explicit) == explicit.resolve()


def _prec(promoted, dismissed):
    judged = promoted + dismissed
    return {
        "promoted": promoted,
        "dismissed": dismissed,
        "other": 0,
        "precision": round(promoted / judged, 3) if judged else None,
    }


# ---------------------------------------------------------------------------
# compute_delta
# ---------------------------------------------------------------------------


def test_baseline_run_flags_nothing():
    cur = _mining(uncovered=[_cluster("CWE-78", "go", 5)], precision={"r1": _prec(1, 9)})
    d = lane.compute_delta(None, cur)
    assert d["baseline"] is True
    assert d["new_uncovered_clusters"] == []
    assert d["precision_gate_crossings"] == []
    assert d["attention"]["needed"] is False
    assert d["tp_corpus"]["confirmed_tps"] == 100
    assert d["tp_corpus"]["growth"] is None


def test_identical_runs_produce_empty_delta():
    doc = _mining(uncovered=[_cluster("CWE-78", "go", 5)], precision={"r1": _prec(6, 4)})
    d = lane.compute_delta(doc, json.loads(json.dumps(doc)))
    assert d["baseline"] is False
    assert d["new_uncovered_clusters"] == []
    assert d["resolved_uncovered_clusters"] == []
    assert d["changed_uncovered_clusters"] == []
    assert d["precision_gate_crossings"] == []
    assert d["tp_corpus"]["growth"] == 0
    assert d["attention"]["needed"] is False


def test_new_resolved_and_changed_clusters():
    prev = _mining(uncovered=[_cluster("CWE-78", "go", 5), _cluster("CWE-89", "python", 3)])
    cur = _mining(uncovered=[_cluster("CWE-78", "go", 8), _cluster("CWE-22", "go", 4)])
    d = lane.compute_delta(prev, cur)
    assert [c["cluster"] for c in d["new_uncovered_clusters"]] == ["CWE-22/go"]
    assert [c["cluster"] for c in d["resolved_uncovered_clusters"]] == ["CWE-89/python"]
    assert d["changed_uncovered_clusters"] == [
        {"cluster": "CWE-78/go", "previous_count": 5, "count": 8}
    ]
    assert d["attention"]["needed"] is True
    reasons = " ".join(d["attention"]["reasons"])
    assert "new" in reasons and "grew" in reasons


def test_shrunk_cluster_changes_but_needs_no_attention():
    prev = _mining(uncovered=[_cluster("CWE-78", "go", 8)])
    cur = _mining(uncovered=[_cluster("CWE-78", "go", 3)])
    d = lane.compute_delta(prev, cur)
    assert d["changed_uncovered_clusters"][0]["count"] == 3
    assert d["attention"]["needed"] is False


def test_precision_gate_crossings_both_directions_and_new():
    prev = _mining(
        precision={
            "fell": _prec(6, 4),  # 0.6 -> below
            "rose": _prec(2, 8),  # 0.2 -> above
            "steady": _prec(9, 1),  # stays above
        }
    )
    cur = _mining(
        precision={
            "fell": _prec(2, 8),  # 0.2
            "rose": _prec(7, 3),  # 0.7
            "steady": _prec(9, 1),
            "entered": _prec(1, 9),  # new rule, 0.1
            "unjudged": _prec(0, 0),  # precision None — ignored
        }
    )
    d = lane.compute_delta(prev, cur)
    by_rule = {x["rule"]: x["direction"] for x in d["precision_gate_crossings"]}
    assert by_rule == {
        "fell": "fell_below_gate",
        "rose": "rose_above_gate",
        "entered": "entered_below_gate",
    }
    assert d["attention"]["needed"] is True
    assert any("precision gate" in r for r in d["attention"]["reasons"])


def test_tp_corpus_growth():
    d = lane.compute_delta(_mining(confirmed=100), _mining(confirmed=140))
    assert d["tp_corpus"]["growth"] == 40
    # growth alone is not attention — rules/backlog carry the signal
    assert d["attention"]["needed"] is False


# ---------------------------------------------------------------------------
# render + exit semantics via main()
# ---------------------------------------------------------------------------


def test_render_delta_md_sections():
    prev = _mining(uncovered=[_cluster("CWE-89", "python", 3)], precision={"r1": _prec(6, 4)})
    cur = _mining(
        confirmed=110, uncovered=[_cluster("CWE-22", "go", 4)], precision={"r1": _prec(2, 8)}
    )
    d = lane.compute_delta(prev, cur)
    stages = [{"stage": "mine", "status": "ok", "summary": "ok"}]
    md = lane.render_delta_md(d, stages)
    assert "New uncovered clusters" in md
    assert "CWE-22/go" in md
    assert "Resolved uncovered clusters" in md
    assert "fell_below_gate" in md
    assert "Stage results" in md
    assert "**Attention:** YES" in md


def _fake_stage_runner(monkeypatch, summaries):
    """Replace stage runners with recorded no-ops."""
    calls = []

    def fake(stage, argv, stages):
        calls.append((stage, argv))
        stages.append(
            {"stage": stage, "status": "ok", "returncode": 0, "summary": summaries.get(stage, "")}
        )
        return True

    def fake_mine(findings_root, out, stages):
        return fake("mine", [], stages)

    def fake_collect(ops, ar, stages):
        return fake("sweep-collect", [], stages)

    def fake_draft(engine, ops, ar, stages):
        return fake("sweep-draft", [], stages)

    monkeypatch.setattr(lane, "_run_stage", fake)
    monkeypatch.setattr(lane, "_run_mine_stage", fake_mine)
    monkeypatch.setattr(lane, "_run_sweep_collect_stage", fake_collect)
    monkeypatch.setattr(lane, "_run_sweep_draft_stage", fake_draft)
    return calls


def _mk_ws(tmp_path, prev_doc=None):
    ws = tmp_path / "ws"
    (ws / "analysis-results" / "findings").mkdir(parents=True)
    out = ws / "progress-tracker" / "metrics" / "rule-mining"
    out.mkdir(parents=True)
    if prev_doc is not None:
        (out / "rule-mining.json").write_text(json.dumps(prev_doc))
    return ws, out


def test_main_empty_delta_exits_zero(tmp_path, monkeypatch):
    doc = _mining(uncovered=[_cluster("CWE-78", "go", 5)])
    ws, out = _mk_ws(tmp_path, prev_doc=doc)
    # the faked mine stage leaves rule-mining.json unchanged -> empty
    # delta; the faked draft stages stage nothing
    _fake_stage_runner(
        monkeypatch,
        {
            "sweep-draft": "draft: 0 draft(s) staged (none); 3 class(es) skipped",
            "regression-drafts": "0 draft(s) under rule-drafts — author patterns",
        },
    )
    engine = _with_config_home(monkeypatch, ws, tmp_path)
    rc = lane.execute_rule_lane(workspace=ws, engine=engine)
    assert rc == 0
    delta = json.loads((out / "lane-delta.json").read_text())
    assert delta["attention"]["needed"] is False
    assert delta["drafts_staged"] == 0
    assert (out / "lane-delta.md").is_file()


def test_main_staged_drafts_exit_one(tmp_path, monkeypatch):
    doc = _mining()
    ws, out = _mk_ws(tmp_path, prev_doc=doc)
    _fake_stage_runner(
        monkeypatch,
        {
            "sweep-draft": "draft: 2 draft(s) staged (a, b); 1 class(es) skipped",
            "regression-drafts": "3 draft(s) under rule-drafts — author patterns",
        },
    )
    engine = _with_config_home(monkeypatch, ws, tmp_path)
    rc = lane.execute_rule_lane(workspace=ws, engine=engine)
    assert rc == 1
    delta = json.loads((out / "lane-delta.json").read_text())
    # regression-drafts stays in the harness (EMIT_RULE_DRAFTS_SCRIPT);
    # engine lane only counts sweep-engine drafts.
    assert delta["drafts_staged"] == 2
    assert any("awaiting authoring" in r for r in delta["attention"]["reasons"])


def test_main_baseline_exits_zero(tmp_path, monkeypatch):
    ws, out = _mk_ws(tmp_path, prev_doc=None)

    real_compute = lane.compute_delta

    def fake_mine(findings_root, out_dir, stages):
        (out / "rule-mining.json").write_text(
            json.dumps(_mining(uncovered=[_cluster("CWE-78", "go", 5)]))
        )
        stages.append(
            {"stage": "mine", "status": "ok", "returncode": 0, "summary": ""},
        )
        return True

    def fake_collect(ops, ar, stages):
        stages.append(
            {"stage": "sweep-collect", "status": "ok", "returncode": 0, "summary": ""},
        )
        return True

    def fake_draft(engine, ops, ar, stages):
        stages.append(
            {
                "stage": "sweep-draft",
                "status": "ok",
                "returncode": 0,
                "summary": "draft: 4 draft(s) staged",
            }
        )
        return True

    monkeypatch.setattr(lane, "_run_mine_stage", fake_mine)
    monkeypatch.setattr(lane, "_run_sweep_collect_stage", fake_collect)
    monkeypatch.setattr(lane, "_run_sweep_draft_stage", fake_draft)
    engine = _with_config_home(monkeypatch, ws, tmp_path)
    rc = lane.execute_rule_lane(workspace=ws, engine=engine)
    assert rc == 0  # baseline: inventory, not news
    delta = json.loads((out / "lane-delta.json").read_text())
    assert delta["baseline"] is True
    assert delta["attention"]["needed"] is False
    assert real_compute is lane.compute_delta


def test_main_allowlist_path_from_injected_context(tmp_path, monkeypatch):
    """Delta stage must use the context-injected allowlist path, not
    optional_config_path self-fetch."""
    doc = _mining()
    ws, out = _mk_ws(tmp_path, prev_doc=doc)
    _fake_stage_runner(
        monkeypatch,
        {
            "sweep-draft": "draft: 0 draft(s) staged (none); 0 class(es) skipped",
            "regression-drafts": "0 draft(s) under rule-drafts — author patterns",
        },
    )
    engine = _with_config_home(monkeypatch, ws, tmp_path)
    config_home = tmp_path / "cfg"

    captured: dict[str, Path | None] = {}
    real = lane.allowlist_precision

    def spy(cur, path):
        captured["path"] = path
        return real(cur, path)

    monkeypatch.setattr(lane, "allowlist_precision", spy)
    rc = lane.execute_rule_lane(workspace=ws, engine=engine)
    assert rc == 0
    assert captured["path"] == config_home / "rule-pack-allowlist.yaml"
    delta = json.loads((out / "lane-delta.json").read_text())
    assert delta["allowlist_precision"]["available"] is True


def test_main_missing_findings_tree_exits_two(tmp_path):
    from traust_engine import HarnessEngine

    engine = HarnessEngine.load()
    assert lane.execute_rule_lane(workspace=tmp_path / "nope", engine=engine) == 2


class TestReachabilityWatch:
    """The lane watches whether Stage A is even possible per language, so
    a gate opening is noticed on cadence rather than by hand. Blocked
    languages measured 2026-08-07: max covered-CWE span 1, cpp 0."""

    def _reach(self, **langs):
        return {
            "available": True,
            "gate": 3,
            "packs": {
                "p": {
                    "available": True,
                    "languages": {
                        l: {
                            "repos": 5,
                            "max_span": s,
                            "widest_covered_cwe": "CWE-295",
                            "reachable": s >= 3,
                        }
                        for l, s in langs.items()
                    },
                }
            },
        }

    def test_opening_is_reported(self):
        got = lane.reachability_crossings(self._reach(rust=1), self._reach(rust=3))
        assert len(got) == 1
        assert got[0]["direction"] == "opened"
        assert got[0]["language"] == "rust"

    def test_closing_is_reported_too(self):
        got = lane.reachability_crossings(self._reach(c=3), self._reach(c=2))
        assert got[0]["direction"] == "closed"

    def test_steady_state_is_silent(self):
        """A lane that cried every week about a known-blocked language
        would be noise, and noise gets ignored."""
        assert lane.reachability_crossings(self._reach(cpp=0), self._reach(cpp=0)) == []
        assert lane.reachability_crossings(self._reach(rust=3), self._reach(rust=4)) == []

    def test_first_run_has_no_crossings(self):
        """No prior state is not an opening — else it fires on every
        fresh checkout."""
        assert lane.reachability_crossings(None, self._reach(rust=3)) == []

    def test_unavailable_reachability_is_not_a_crossing(self):
        assert lane.reachability_crossings(self._reach(rust=1), {"available": False}) == []

    def test_uncached_pack_is_skipped_not_called_unreachable(self):
        """A missing clone must never read as 'no ground truth'."""
        cur = {
            "available": True,
            "gate": 3,
            "packs": {"p": {"available": False, "reason": "not cached"}},
        }
        assert lane.reachability_crossings(self._reach(rust=1), cur) == []

    def test_render_shows_the_table_and_any_crossing(self):
        delta = lane.compute_delta(None, _mining())
        delta["reachability"] = self._reach(rust=1, cpp=0)
        delta["reachability_crossings"] = [
            {
                "pack": "p",
                "language": "rust",
                "direction": "opened",
                "max_span": 3,
                "widest_covered_cwe": "CWE-295",
                "repos": 12,
            }
        ]
        body = lane.render_delta_md(delta, [])
        assert "Stage-A gate reachability" in body
        assert "untestable" in body.lower()
        assert "Gate OPENED: rust vs p" in body


class TestAllowlistPrecision:
    """Stage A measures rediscovery before first run; precision only
    exists afterwards. The lane re-checks enabled pack rules against the
    gate so an enabled rule cannot quietly cost triage time forever."""

    def _cur(self, **prec):
        m = _mining()
        m["rule_precision"] = {
            r: {"precision": p, "promoted": 1, "dismissed": 1} for r, p in prec.items()
        }
        return m

    def _allow(self, tmp_path, *ids):
        f = tmp_path / "rule-pack-allowlist.yaml"
        f.write_text("pack:\n" + "".join(f"  - {i}\n" for i in ids))
        return f

    def test_flags_rules_below_the_gate(self, tmp_path):
        got = lane.allowlist_precision(
            self._cur(**{"go-tls-bypass": 0.2, "java-tls-bypass": 0.9}),
            self._allow(tmp_path, "go-tls-bypass", "java-tls-bypass"),
        )
        assert [r["rule"] for r in got["below_gate"]] == ["go-tls-bypass"]

    def test_unmeasured_rules_are_reported_not_passed(self, tmp_path):
        """A rule nobody has judged yet must not read as compliant."""
        got = lane.allowlist_precision(self._cur(**{"a": 0.9}), self._allow(tmp_path, "a", "b"))
        assert got["unmeasured"] == ["b"]
        assert got["below_gate"] == []

    def test_missing_allowlist_is_unavailable_not_empty(self, tmp_path):
        got = lane.allowlist_precision(self._cur(), tmp_path / "nope.yaml")
        assert got["available"] is False

    def test_render_marks_demotions(self, tmp_path):
        delta = lane.compute_delta(None, _mining())
        delta["allowlist_precision"] = lane.allowlist_precision(
            self._cur(**{"go-tls-bypass": 0.1}), self._allow(tmp_path, "go-tls-bypass")
        )
        body = lane.render_delta_md(delta, [])
        assert "**DEMOTE**" in body
        assert "silence is not a pass" in body
