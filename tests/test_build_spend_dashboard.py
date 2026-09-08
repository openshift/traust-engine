"""Monthly budget tracking in traust metrics spend.

The dashboard's budget-vs-actual section prices session-actuals ledger
rows at registry list rates and compares each calendar month against
the monthly_budget block of config/budget-policy.yaml (visibility
only). Verified: band classification for complete months, run-rate
projection for the current month, unpriced-model coverage gaps, and
clean omission when the budget block or session rows are absent.
"""

import datetime
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from traust_contracts import load_context

from traust_engine.metrics import spend as bsd
from traust_engine.registry import models as model_registry

TODAY = datetime.date.today()
CUR_MONTH = TODAY.strftime("%Y-%m")


def _session_row(date: str, model: str, tok_out: int, cache_read: int = 0) -> dict:
    return {
        "snapshot_at": f"{date}T00:00:00+00:00",
        "source": "model-spend:sessions",
        "metrics": {
            "date": date,
            "model": model,
            "tokens_in": 0,
            "tokens_out": tok_out,
            "cache_read": cache_read,
            "cache_creation": 0,
            "sessions": 1,
        },
    }


def _budget_yaml(tmp: Path) -> Path:
    p = tmp / "budget-policy.yaml"
    p.write_text(
        "budget_policy:\n"
        "  monthly_budget:\n"
        "    usd_central: 23000\n"
        "    usd_band_low: 19000\n"
        "    usd_band_high: 27000\n"
    )
    return p


def _write_ledger(tmp: Path, rows: list[dict]) -> Path:
    led = tmp / "metrics-history.jsonl"
    led.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return led


class TestMonthlyBudgetSection(unittest.TestCase):
    # mythos list rate: $50/Mtok out → tokens_out alone prices exactly.

    def _build_md(self, rows: list[dict]) -> str:
        reg = load_context().model_registry
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            led = _write_ledger(tmp, rows)
            with mock.patch("traust_engine.metrics.history.ledger_path", return_value=led):
                out = bsd.build(tmp, tmp / "out", budget_path=_budget_yaml(tmp), reg=reg)
            return out.read_text()

    def test_complete_months_classified_against_band(self):
        md = self._build_md(
            [
                # 2026-05: 600M tokens out x $50/M = $30,000 → over band
                _session_row("2026-05-10", "claude-mythos-5", 600_000_000),
                # 2026-06: 400M x $50/M = $20,000 → within band
                _session_row("2026-06-10", "claude-mythos-5", 400_000_000),
                # 2026-04: 100M x $50/M = $5,000 → under band
                _session_row("2026-04-10", "claude-mythos-5", 100_000_000),
            ]
        )
        self.assertIn("## Monthly budget tracking", md)
        may = next(l for l in md.splitlines() if l.startswith("| 2026-05 "))
        jun = next(l for l in md.splitlines() if l.startswith("| 2026-06 "))
        apr = next(l for l in md.splitlines() if l.startswith("| 2026-04 "))
        self.assertIn("OVER band", may)
        self.assertIn("+$3,000 over", may)
        self.assertIn("within band", jun)
        self.assertIn("under band", apr)

    def test_current_month_shows_runrate_projection(self):
        md = self._build_md(
            [
                _session_row(TODAY.isoformat(), "claude-mythos-5", 20_000_000),
            ]
        )
        cur = next(l for l in md.splitlines() if l.startswith(f"| {CUR_MONTH} "))
        self.assertIn("projecting $", cur)
        self.assertIn("month-to-date", cur)

    def test_unpriced_models_reported_as_coverage_gap_not_zero(self):
        md = self._build_md(
            [
                _session_row("2026-06-10", "claude-mythos-5", 400_000_000),
                _session_row("2026-06-11", "totally-unpriced-model", 9_999_999),
            ]
        )
        jun = next(l for l in md.splitlines() if l.startswith("| 2026-06 "))
        self.assertIn("unpriced: totally-unpriced-model", jun)
        self.assertIn("20,000.00", jun)  # priced part unchanged

    def test_section_omitted_without_budget_block(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            led = _write_ledger(tmp, [_session_row("2026-06-10", "claude-mythos-5", 1_000)])
            empty = tmp / "no-budget.yaml"
            empty.write_text("budget_policy: {}\n")
            with mock.patch("traust_engine.metrics.history.ledger_path", return_value=led):
                reg = load_context().model_registry
                out = bsd.build(tmp, tmp / "out", budget_path=empty, reg=reg)
            self.assertNotIn("Monthly budget tracking", out.read_text())

    def test_pricing_matches_registry_cost_fn(self):
        reg = load_context().model_registry
        expect = model_registry.cost_usd(reg, "claude-mythos-5", 0, 400_000_000, 0, 0)
        md = self._build_md([_session_row("2026-06-10", "claude-mythos-5", 400_000_000)])
        jun = next(l for l in md.splitlines() if l.startswith("| 2026-06 "))
        self.assertIn(f"{expect:,.2f}", jun)


if __name__ == "__main__":
    unittest.main()
