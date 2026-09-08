"""Tests for traust registry models and the shipped registry."""

import unittest
from pathlib import Path

from traust_contracts import load_context

from traust_engine.registry.models import resolve, spend_row, stamp, validate


def _load_registry():
    return load_context().model_registry


class TestShippedRegistry(unittest.TestCase):
    def setUp(self):
        self.reg = _load_registry()

    def test_registry_validates(self):
        self.assertEqual(validate(self.reg), [])

    def test_floor_enforced(self):
        with self.assertRaises(ValueError):
            resolve(self.reg, "deep-audit", "haiku-class")

    def test_resolve_at_floor(self):
        self.assertEqual(resolve(self.reg, "fact-judge"), "claude-sonnet-5")

    def test_escalation_above_floor(self):
        self.assertEqual(resolve(self.reg, "fact-judge", "mythos-class"), "claude-mythos-5")

    def test_unknown_role(self):
        with self.assertRaises(KeyError):
            resolve(self.reg, "no-such-role")

    def test_ledger_writers_are_mythos_floor(self):
        for role, r in self.reg.roles.items():
            if getattr(r, "ledger_validity_writer", False):
                self.assertEqual(
                    r.floor, "mythos-class", f"{role}: validity writers keep frontier floor"
                )

    def test_stamp_carries_registry_sha(self):
        s = stamp(self.reg, "fact-judge", "claude-sonnet-5")
        self.assertEqual(len(s["registry_sha"]), 12)
        self.assertEqual(s["floor"], "sonnet-class")

    def test_spend_row_mythos_priced_from_rate_card(self):
        # rate card filled 2026-07-24: mythos-5 at 10/50 per MTok
        # (1M in = $10) + (100k out = $5) = $15
        row = spend_row(self.reg, "claude-mythos-5", 1_000_000, 100_000)
        self.assertAlmostEqual(row["cost_usd"], 15.0)

    def test_spend_row_cache_aware_cost(self):
        # sonnet list price: 3/15 per MTok; cache read x0.1, write x1.25
        row = spend_row(
            self.reg,
            "claude-sonnet-5",
            1_000_000,
            1_000_000,
            cache_read=10_000_000,
            cache_creation=1_000_000,
        )
        # 3 + 15 + 10*0.3 + 1*3.75 = 24.75
        self.assertAlmostEqual(row["cost_usd"], 24.75, places=2)

    def test_approved_never_below_floor(self):
        # covered by validate(), but assert the invariant directly
        errors = [e for e in validate(self.reg) if "below the floor" in e]
        self.assertEqual(errors, [])


class TestSessionSpendCollector(unittest.TestCase):
    def test_collect_parses_usage_lines(self):
        import json
        import tempfile

        from traust_engine.metrics.collect_spend import collect

        d = Path(tempfile.mkdtemp())
        (d / "abc.jsonl").write_text(
            json.dumps(
                {
                    "timestamp": "2026-07-24T10:00:00Z",
                    "message": {
                        "model": "claude-sonnet-5",
                        "usage": {
                            "input_tokens": 10,
                            "output_tokens": 20,
                            "cache_read_input_tokens": 300,
                            "cache_creation_input_tokens": 40,
                        },
                    },
                }
            )
            + "\n"
            + json.dumps(
                {
                    "timestamp": "2026-07-24T10:01:00Z",
                    "message": {"model": "<synthetic>", "usage": {"output_tokens": 5}},
                }
            )
            + "\n"
        )
        agg = collect([d], "2026-07-24")
        a = agg["2026-07-24"]["claude-sonnet-5"]
        self.assertEqual(a["output_tokens"], 20)
        self.assertEqual(a["cache_read_input_tokens"], 300)
        self.assertNotIn("<synthetic>", agg["2026-07-24"])


if __name__ == "__main__":
    unittest.main()


def test_spend_row_carries_repo_attribution():
    """Calibration tuple (spend, repo, size) for spend attribution."""
    reg = _load_registry()
    row = spend_row(reg, "test-model", 100, 50, repo="my-repo", loc=12345)
    assert row["repo"] == "my-repo" and row["loc"] == 12345
    row2 = spend_row(reg, "test-model", 100, 50)
    assert "repo" not in row2 and "loc" not in row2
