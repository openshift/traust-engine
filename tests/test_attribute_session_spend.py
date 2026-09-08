"""Tests for traust metrics attribute-spend — per-lane spend
attribution (budget-guard widening plan, Phase 0)."""

import json

import pytest

from traust_engine.metrics import attribute_spend as asp
from traust_engine.metrics import collect_spend as css

VALID = {"secure-code-audit", "vuln-scan", "threat-model"}


def _usage(ts, model="m1", out=10, inp=1, cache_read=0, cache_new=0):
    return {
        "timestamp": ts,
        "message": {
            "model": model,
            "usage": {
                "input_tokens": inp,
                "output_tokens": out,
                "cache_read_input_tokens": cache_read,
                "cache_creation_input_tokens": cache_new,
            },
        },
    }


def _skill_call(name):
    return {
        "timestamp": "2026-07-01T00:00:00Z",
        "message": {"content": [{"type": "tool_use", "name": "Skill", "input": {"skill": name}}]},
    }


def _session(tmp_path, name, records):
    d = tmp_path / "proj"
    d.mkdir(exist_ok=True)
    f = d / f"{name}.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return d


class TestDetectSkill:
    def test_skill_tool_call(self):
        assert asp.detect_skill(_skill_call("vuln-scan"), VALID) == "vuln-scan"

    def test_scoped_skill_name_is_stripped(self):
        rec = _skill_call("traust:vuln-scan")
        assert asp.detect_skill(rec, VALID) == "vuln-scan"

    def test_slash_command(self):
        rec = {"message": {"content": "<command-name>/threat-model</command-name>"}}
        assert asp.detect_skill(rec, VALID) == "threat-model"

    def test_skill_md_read(self):
        rec = {
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "name": "Read",
                        "input": {"file_path": "/workspace/skills/vuln-scan/SKILL.md"},
                    }
                ]
            }
        }
        assert asp.detect_skill(rec, VALID) == "vuln-scan"

    def test_unknown_skill_name_is_rejected(self):
        """Gating on the real skills tree stops prose about some
        other tool from inventing a lane."""
        assert asp.detect_skill(_skill_call("not-a-real-skill"), VALID) is None
        rec = {"message": {"content": "<command-name>/nope</command-name>"}}
        assert asp.detect_skill(rec, VALID) is None

    def test_plain_message_has_no_signal(self):
        assert asp.detect_skill(_usage("2026-07-01T00:00:00Z"), VALID) is None

    def test_known_skills_reads_the_real_tree(self, tmp_path):
        for name in ("threat-model", "vuln-scan"):
            skill = tmp_path / name
            skill.mkdir()
            (skill / "SKILL.md").write_text(f"# {name}\n")
        skills = asp.known_skills(tmp_path)
        assert "threat-model" in skills and "vuln-scan" in skills

    def test_known_skills_spans_both_layouts(self, tmp_path):
        """Workflow skills sit under a stage directory and the rest at the
        root (harness skill-usability plan 1.2). Missing the nested half
        would empty `valid`, and attribution would silently mint no lanes
        at all rather than failing."""
        (tmp_path / "census").mkdir()
        (tmp_path / "census" / "SKILL.md").write_text("# census\n")
        nested = tmp_path / "3-audit" / "vuln-scan"
        nested.mkdir(parents=True)
        (nested / "SKILL.md").write_text("# vuln-scan\n")
        # a SKILL.md bundled inside a skill is not a skill of its own
        vendored = tmp_path / "census" / "vendored" / "impostor"
        vendored.mkdir(parents=True)
        (vendored / "SKILL.md").write_text("# impostor\n")
        assert asp.known_skills(tmp_path) == {"census", "vuln-scan"}

    def test_skill_md_signal_reads_a_staged_path(self):
        """The transcript may record either layout: newer runs read
        workspace/skills/<stage>/<skill>/SKILL.md, older ones the flat path, and
        both must attribute to the same lane."""
        for path in (
            "/workspace/skills/3-audit/vuln-scan/SKILL.md",
            "/workspace/skills/vuln-scan/SKILL.md",
        ):
            rec = {
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "name": "Read",
                            "input": {"file_path": path},
                        }
                    ]
                }
            }
            assert asp.detect_skill(rec, VALID) == "vuln-scan", path


class TestAttribution:
    def test_usage_before_any_signal_is_unattributed(self, tmp_path):
        d = _session(
            tmp_path,
            "s1",
            [
                _usage("2026-07-01T00:00:00Z", out=100),
                _skill_call("vuln-scan"),
                _usage("2026-07-01T00:01:00Z", out=50),
            ],
        )
        agg = asp.collect_attributed([d], valid=VALID)
        day = agg["2026-07-01"]
        assert day[asp.UNATTRIBUTED]["m1"]["output_tokens"] == 100
        assert day["vuln-scan"]["m1"]["output_tokens"] == 50

    def test_mid_session_switch_splits_the_session(self, tmp_path):
        """A session that runs two skills must not book all its tokens
        to whichever one it happened to start with."""
        d = _session(
            tmp_path,
            "s1",
            [
                _skill_call("vuln-scan"),
                _usage("2026-07-01T00:00:00Z", out=10),
                _skill_call("threat-model"),
                _usage("2026-07-01T00:01:00Z", out=7),
            ],
        )
        agg = asp.collect_attributed([d], valid=VALID)
        day = agg["2026-07-01"]
        assert day["vuln-scan"]["m1"]["output_tokens"] == 10
        assert day["threat-model"]["m1"]["output_tokens"] == 7
        assert asp.UNATTRIBUTED not in day

    def test_attribution_does_not_leak_across_sessions(self, tmp_path):
        d = _session(
            tmp_path, "s1", [_skill_call("vuln-scan"), _usage("2026-07-01T00:00:00Z", out=10)]
        )
        _session(tmp_path, "s2", [_usage("2026-07-01T00:02:00Z", out=99)])
        agg = asp.collect_attributed([d], valid=VALID)
        day = agg["2026-07-01"]
        assert day["vuln-scan"]["m1"]["output_tokens"] == 10
        assert day[asp.UNATTRIBUTED]["m1"]["output_tokens"] == 99

    def test_day_and_month_filters(self, tmp_path):
        d = _session(
            tmp_path,
            "s1",
            [_usage("2026-07-01T00:00:00Z", out=1), _usage("2026-08-02T00:00:00Z", out=2)],
        )
        assert list(asp.collect_attributed([d], day="2026-07-01", valid=VALID)) == ["2026-07-01"]
        assert list(asp.collect_attributed([d], month="2026-08", valid=VALID)) == ["2026-08-02"]

    def test_synthetic_model_names_are_skipped(self, tmp_path):
        d = _session(tmp_path, "s1", [_usage("2026-07-01T00:00:00Z", model="<synthetic>", out=500)])
        assert asp.collect_attributed([d], valid=VALID) == {}


class TestLossless:
    def test_split_matches_the_existing_collector_exactly(self, tmp_path):
        """The whole point: an attribution that drops tokens is worse
        than no attribution. Totals must equal collect_session_spend."""
        d = _session(
            tmp_path,
            "s1",
            [
                _usage("2026-07-01T00:00:00Z", out=100, inp=5, cache_read=7),
                _skill_call("vuln-scan"),
                _usage("2026-07-01T00:01:00Z", out=50, inp=3, cache_read=9),
                _usage("2026-07-02T00:00:00Z", model="m2", out=11),
            ],
        )
        res = asp.reconcile([d], None, None)
        assert res["lossless"], res["deltas"]
        assert res["attributed"]["output_tokens"] == 161

    def test_reconcile_reports_a_mismatch_rather_than_hiding_it(self, tmp_path, monkeypatch):
        d = _session(tmp_path, "s1", [_usage("2026-07-01T00:00:00Z", out=10)])
        monkeypatch.setattr(
            asp,
            "collect_attributed",
            lambda *a, **k: {
                "2026-07-01": {
                    "x": {
                        "m1": {
                            **{key: 0 for key in asp.TOKEN_KEYS},
                            "output_tokens": 3,
                            "messages": 1,
                            "sessions": set(),
                        }
                    }
                }
            },
        )
        res = asp.reconcile([d], None, None)
        assert res["lossless"] is False
        assert res["deltas"]["output_tokens"] == -7

    def test_cli_reconcile_exits_nonzero_on_mismatch(self, tmp_path, monkeypatch):
        from traust_engine import HarnessEngine

        d = _session(tmp_path, "s1", [_usage("2026-07-01T00:00:00Z", out=10)])
        monkeypatch.setattr(css, "workspace_slugs", lambda ws: [d])
        monkeypatch.setattr(
            asp,
            "reconcile",
            lambda *a, **k: {
                "lossless": False,
                "attributed": {"output_tokens": 1},
                "baseline": {"output_tokens": 2},
                "deltas": {"output_tokens": -1},
            },
        )
        metrics = HarnessEngine.load().metrics
        res = metrics.attribute_reconcile([d], None, "2026-07")
        assert res["lossless"] is False


class TestRender:
    def test_unattributed_is_always_shown(self, tmp_path):
        d = _session(tmp_path, "s1", [_usage("2026-07-01T00:00:00Z", out=10)])
        agg = asp.collect_attributed([d], valid=VALID)
        body = "\n".join(asp.render(agg, "2026-07"))
        assert asp.UNATTRIBUTED in body
        assert "Harness lanes" in body

    def test_unpriced_models_are_named_not_zeroed(self, tmp_path):
        """The declared side reads $0.00 everywhere precisely because a
        missing price rounded to zero. Never repeat that here."""
        d = _session(
            tmp_path, "s1", [_usage("2026-07-01T00:00:00Z", model="no-such-model", out=10)]
        )
        agg = asp.collect_attributed([d], valid=VALID)
        _costs, unpriced = asp.cost_by_skill(agg)
        if unpriced:
            body = "\n".join(asp.render(agg, "2026-07"))
            assert "unpriced" in body and "no-such-model" in body


class TestCliGuards:
    def test_missing_transcripts_exits_3(self, tmp_path, monkeypatch):
        monkeypatch.setattr(css, "workspace_slugs", lambda ws: [])
        assert css.workspace_slugs(tmp_path) == []


class TestLedgerAppend:
    def _agg(self, date="2026-07-01"):
        base = {k: 0 for k in asp.TOKEN_KEYS}
        return {
            date: {
                "vuln-scan": {
                    "m1": base
                    | {"output_tokens": 10, "input_tokens": 2, "messages": 1, "sessions": {"s1"}}
                }
            }
        }

    def test_appends_completed_days(self, tmp_path, monkeypatch):
        calls = []

        monkeypatch.setattr(asp, "already_recorded", lambda ws, journal=None: set())
        monkeypatch.setattr(
            asp.metrics_ledger,
            "append",
            lambda source, metrics, journal=None: calls.append((source, metrics)) or {},
        )
        n = asp.append_rows(tmp_path, self._agg(), reg={})
        assert n == 1 and len(calls) == 1
        source, payload = calls[0]
        assert source == "spend-attribution:vuln-scan"
        assert payload["skill"] == "vuln-scan"
        assert payload["attribution"] == "inferred-from-transcript"
        assert payload["tokens_out"] == 10

    def test_today_is_never_recorded(self, tmp_path, monkeypatch):
        """Appending a partial day would freeze that day's undercount
        permanently, since the row is then 'already recorded'."""
        import datetime as _dt

        today = _dt.date.today().isoformat()
        monkeypatch.setattr(asp, "already_recorded", lambda ws, journal=None: set())
        monkeypatch.setattr(
            asp.metrics_ledger,
            "append",
            lambda *a, **k: pytest.fail("appended today"),
        )
        assert asp.append_rows(tmp_path, self._agg(today), reg={}) == 0

    def test_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            asp,
            "already_recorded",
            lambda ws, journal=None: {("2026-07-01", "vuln-scan", "m1")},
        )
        monkeypatch.setattr(
            asp.metrics_ledger,
            "append",
            lambda *a, **k: pytest.fail("re-appended"),
        )
        assert asp.append_rows(tmp_path, self._agg(), reg={}) == 0

    def test_uses_a_separate_ledger_namespace(self, tmp_path, monkeypatch):
        """spend-attribution:<skill> must NOT collide with the declared
        model-spend:<skill> rows — mixing them is what let a $0.00 table
        look authoritative."""
        seen = []

        monkeypatch.setattr(asp, "already_recorded", lambda ws, journal=None: set())
        monkeypatch.setattr(
            asp.metrics_ledger,
            "append",
            lambda source, metrics, journal=None: seen.append(source) or {},
        )
        asp.append_rows(tmp_path, self._agg(), reg={})
        assert seen == ["spend-attribution:vuln-scan"]
        assert not seen[0].startswith("model-spend:")
