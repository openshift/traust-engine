"""Model-spend dashboard — multi-model-strategy-plan M1.

Aggregates the hash-chained metrics ledger's `model-spend:<skill>` rows
(appended by `traust registry models spend`) into
`metrics/dashboards/spend/spend-dashboard.md`:
spend by skill x model, token totals, cost where the registry carries
prices, and the MTTA-per-dollar headline when MTTA rows exist.

Deterministic full rebuild; rerun after any batch that records spend.
"""

from __future__ import annotations

import calendar
import datetime
from collections import defaultdict
from pathlib import Path

import yaml
from traust_contracts import BudgetPolicy

from traust_engine.metrics import history as metrics_ledger
from traust_engine.registry import models as model_registry


def load_monthly_budget(
    path: Path | None = None, *, budget_section: BudgetPolicy | None = None
) -> dict | None:
    """The monthly_budget block of the budget policy (visibility layer
    only — this module tracks, it never gates). None when absent."""
    if path is not None:
        try:
            bp = (yaml.safe_load(path.read_text()) or {}).get("budget_policy") or {}
        except (OSError, yaml.YAMLError):
            return None
    elif budget_section is not None:
        bp = budget_section.budget_policy or {}
    else:
        return None
    mb = bp.get("monthly_budget") or {}
    if not {"usd_central", "usd_band_low", "usd_band_high"} <= set(mb):
        return None
    return mb


def monthly_budget_section(
    session_rows: list[dict], reg: dict, budget: dict, today: datetime.date
) -> list[str]:
    """Budget-vs-actual per calendar month from session-actuals rows.
    Months are keyed on the row's usage date (metrics.date), priced at
    registry list rates; models without a price are counted as coverage
    gaps per month, never silently as $0."""
    months: dict[str, dict] = defaultdict(lambda: {"usd": 0.0, "days": set(), "unpriced": set()})
    for r in session_rows:
        m = r["metrics"]
        date = str(m.get("date") or "")
        if len(date) < 7:
            continue
        mo = months[date[:7]]
        c = model_registry.cost_usd(
            reg,
            m.get("model", ""),
            int(m.get("tokens_in") or 0),
            int(m.get("tokens_out") or 0),
            int(m.get("cache_read") or 0),
            int(m.get("cache_creation") or 0),
        )
        if c is None:
            mo["unpriced"].add(m.get("model", "?"))
        else:
            mo["usd"] += c
            mo["days"].add(date)
    if not months:
        return []

    low, high = budget["usd_band_low"], budget["usd_band_high"]
    central = budget["usd_central"]
    cur = today.strftime("%Y-%m")
    L = [
        "## Monthly budget tracking",
        "",
        f"_Plan: **${central:,}/month central** (band ${low:,}–${high:,}),"
        f" list prices — `config/budget-policy.yaml` `monthly_budget`"
        f" (example policy; set your own monthly band). Tracking only; nothing"
        f" is gated._",
        "",
        "_Caveats: actuals are list-priced from the registry at "
        "CURRENT rates, recomputed from stored token counts — a rate "
        "correction therefore restates history when registry rates change. "
        "Models with no registry price are named per month, "
        "never counted as $0. Months dominated by one-time experiment "
        "bursts are expected to breach the band — the plan prices "
        "steady-state scanning only._",
        "",
        "| Month | Actual (USD) | vs band | Status | Coverage |",
        "|---|---:|---|---|---|",
    ]
    for month in sorted(months, reverse=True):
        mo = months[month]
        usd = mo["usd"]
        if month == cur:
            days_in = calendar.monthrange(today.year, today.month)[1]
            rate = usd / today.day * days_in if today.day else 0.0
            if rate > high:
                status = f"⚠ projecting ${rate:,.0f} — ABOVE band"
            elif rate < low:
                status = f"✓ projecting ${rate:,.0f} — below band"
            else:
                status = f"✓ projecting ${rate:,.0f} — within band"
            vs = f"month-to-date, day {today.day}/{days_in}"
        else:
            if usd > high:
                status, vs = "⚠ OVER band", f"+${usd - high:,.0f} over"
            elif usd < low:
                status, vs = "✓ under band", f"${low - usd:,.0f} headroom"
            else:
                status, vs = "✓ within band", f"${high - usd:,.0f} to top"
        gaps = (
            f"{len(mo['days'])} days recorded; unpriced: {', '.join(sorted(mo['unpriced']))}"
            if mo["unpriced"]
            else f"{len(mo['days'])} days recorded"
        )
        L.append(f"| {month} | {usd:,.2f} | {vs} | {status} | {gaps} |")
    L.append("")
    return L


LANE_SOURCE_PREFIX = "spend-attribution:"


def lane_attribution_section(
    ws: Path, *, journal: Path | None = None, reg: dict | None = None
) -> list[str]:
    """Per-lane cost from `spend-attribution:<skill>` ledger rows —
    inferred from session transcripts by attribute_session_spend.py,
    which is the ONLY trustworthy per-lane cost source (the declared
    rows below carry zero tokens by contract).

    The lane vs `unattributed` split is the headline: most workstation
    spend is interactive work that never invoked a skill, and judging a
    scanning budget against that total overstates lane cost ~3.6x."""
    rows = [
        r
        for r in metrics_ledger.rows(journal)
        if str(r.get("source") or "").startswith(LANE_SOURCE_PREFIX)
    ]
    if not rows:
        return [
            "## Per-lane attribution",
            "",
            "_Not yet collected. Run `python3 "
            "traust metrics attribute-spend --append` (reads "
            "Claude Code transcripts; completed days only) to "
            "populate. Until then no per-lane cost is known — the "
            "declared rows below are routing markers, not costs._",
            "",
        ]
    by_month: dict = defaultdict(
        lambda: defaultdict(lambda: {"usd": 0.0, "out": 0, "unpriced": False})
    )
    # Reprice from stored TOKENS at current registry rates rather than
    # trusting the `cost_usd` frozen into each row. Without this the
    # monthly-budget section above (which prices at build time) and this
    # table can disagree after a rate correction — same rule as
    # build_financial_report.ledger_series.
    if reg is None:
        raise ValueError(
            "reg is required — pass model_registry from HarnessEngine.models.registry()"
        )
    for r in rows:
        m = r.get("metrics") or {}
        date, skill = str(m.get("date") or ""), str(m.get("skill") or "?")
        if len(date) < 7:
            continue
        cell = by_month[date[:7]][skill]
        usd = m.get("cost_usd")
        if m.get("model"):
            try:
                derived = model_registry.cost_usd(
                    reg,
                    m["model"],
                    int(m.get("tokens_in") or 0),
                    int(m.get("tokens_out") or 0),
                    int(m.get("cache_read") or 0),
                    int(m.get("cache_creation") or 0),
                )
            except Exception:
                derived = None
            if derived is not None:
                usd = derived
        if usd is None:
            cell["unpriced"] = True
        else:
            cell["usd"] += float(usd)
        cell["out"] += int(m.get("tokens_out") or 0)
    L = [
        "## Per-lane attribution (cost source)",
        "",
        "_Inferred from session transcripts — which skill each session "
        "was running — not self-reported by agents. `unattributed` is "
        "workstation sessions that never invoked a skill and is always "
        "shown; a scanning budget should be judged against the lane "
        "subtotal, not the workstation total._",
        "",
    ]
    for month in sorted(by_month, reverse=True)[:2]:
        skills = by_month[month]
        tot = sum(c["usd"] for c in skills.values())
        lane = sum(c["usd"] for s, c in skills.items() if s != "unattributed")
        un = skills.get("unattributed", {}).get("usd", 0.0)
        L += [
            f"### {month}",
            "",
            f"**Harness lanes ${lane:,.2f}** · unattributed "
            f"${un:,.2f} · total ${tot:,.2f}"
            + (f" (lanes = {lane / tot * 100:.1f}%)" if tot else ""),
            "",
            "| Lane | Cost (USD) | Output tokens |",
            "|---|---:|---:|",
        ]
        for skill, c in sorted(skills.items(), key=lambda kv: -kv[1]["usd"]):
            note = " ⚠ unpriced model(s)" if c["unpriced"] else ""
            L.append(f"| {skill} | {c['usd']:,.2f}{note} | {c['out']:,} |")
        L.append("")
    return L


def build(
    ws: Path,
    out_dir: Path,
    budget_path: Path | None = None,
    *,
    journal: Path | None = None,
    reg: dict | None = None,
    budget_section: BudgetPolicy | None = None,
) -> Path:
    all_rows = [
        r
        for r in metrics_ledger.rows(journal)
        if str(r.get("source", "")).startswith("model-spend:")
    ]
    rows = [r for r in all_rows if r["source"] != "model-spend:sessions"]
    session_rows = [r for r in all_rows if r["source"] == "model-spend:sessions"]
    agg: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"runs": 0, "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0, "cost_known": True}
    )
    for r in rows:
        skill = r["source"].split(":", 1)[1]
        m = r.get("metrics", {})
        a = agg[(skill, m.get("model", "?"))]
        a["runs"] += 1
        a["tokens_in"] += int(m.get("tokens_in") or 0)
        a["tokens_out"] += int(m.get("tokens_out") or 0)
        if m.get("cost_usd") is None:
            a["cost_known"] = False
        else:
            a["cost_usd"] += float(m["cost_usd"])

    L = [
        "# Model Spend Dashboard",
        "",
        f"**Generated:** {datetime.date.today().isoformat()} · "
        f"source: hash-chained metrics ledger (`model-spend:*` rows)",
        "",
        "_How tracking works: drivers **declare** per-skill spend "
        "(`model_registry.py spend`); the session collector records "
        "**actuals** from Claude Code transcripts "
        "(`collect_session_spend.py --append`, daily). Real-time view: "
        "`traust metrics collect-spend`. Full chain: "
        "docs/model-routing.md → How spend is tracked._",
        "",
    ]

    if reg is None:
        raise ValueError(
            "reg is required — pass model_registry from HarnessEngine.models.registry()"
        )
    budget = load_monthly_budget(budget_path, budget_section=budget_section)
    if budget and session_rows:
        L += monthly_budget_section(session_rows, reg, budget, datetime.date.today())

    L += lane_attribution_section(ws, journal=journal, reg=reg)

    if not agg:
        L += [
            "_No spend rows recorded yet. Drivers begin appending rows as "
            "the M1 rollout lands; this dashboard renders them on the next "
            "rebuild._",
            "",
        ]
    else:
        L += [
            "## Declared rows (routing markers — NOT a cost source)",
            "",
            "_These are what drivers declare via `model_registry.py "
            "spend`: which skill/model/repo/size ran. **Their token and "
            "cost fields are best-effort and usually zero** — an agent "
            "cannot observe its own usage mid-run, so most declared rows "
            "record 0/0 tokens. Do not read cost from "
            "this table; the per-lane section above is the cost "
            "source._",
            "",
            "| Skill | Model | Runs | Tokens in | Tokens out | Cost (USD) |",
            "|---|---|---:|---:|---:|---:|",
        ]
        for (skill, model), a in sorted(agg.items(), key=lambda kv: -(kv[1]["cost_usd"] or 0)):
            cost = f"{a['cost_usd']:.2f}" if a["cost_known"] else "n/a (no price in registry)"
            L.append(
                f"| {skill} | {model} | {a['runs']} | "
                f"{a['tokens_in']:,} | {a['tokens_out']:,} | {cost} |"
            )
        L.append("")

    # session actuals (day x model), costed from registry list prices
    if session_rows:
        priced_total = 0.0
        unpriced: set = set()
        for r in session_rows:
            m = r["metrics"]
            c = model_registry.cost_usd(
                reg,
                m.get("model", ""),
                int(m.get("tokens_in") or 0),
                int(m.get("tokens_out") or 0),
                int(m.get("cache_read") or 0),
                int(m.get("cache_creation") or 0),
            )
            if c is None:
                unpriced.add(m.get("model", "?"))
            else:
                priced_total += c
        L += [
            "## Session actuals (Claude Code transcripts)",
            "",
            "_Cost = registry LIST prices (cache-aware: read×0.1, "
            "write×1.25 of input) — preliminary until the rate card "
            "lands; unpriced models show n/a._",
            "",
            "| Date | Model | Output tokens | Fresh input | Cache read | "
            "Cache new | Sessions | Est. cost (USD) |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ]
        for r in sorted(
            session_rows,
            key=lambda r: (r["metrics"].get("date", ""), r["metrics"].get("model", "")),
            reverse=True,
        )[:30]:
            m = r["metrics"]
            c = model_registry.cost_usd(
                reg,
                m.get("model", ""),
                int(m.get("tokens_in") or 0),
                int(m.get("tokens_out") or 0),
                int(m.get("cache_read") or 0),
                int(m.get("cache_creation") or 0),
            )
            L.append(
                f"| {m.get('date')} | {m.get('model')} | "
                f"{m.get('tokens_out', 0):,} | {m.get('tokens_in', 0):,} | "
                f"{m.get('cache_read', 0):,} | {m.get('cache_creation', 0):,} | "
                f"{m.get('sessions', 0)} | "
                f"{f'{c:,.2f}' if c is not None else 'n/a'} |"
            )
        L.append("")
        note = f" (excludes unpriced: {', '.join(sorted(unpriced))})" if unpriced else ""
        L.append(
            f"**Estimated session-actuals total (all recorded days): ${priced_total:,.2f}**{note}"
        )
        L.append("")

    # MTTA-per-dollar headline when both series exist
    mtta = [r for r in metrics_ledger.rows(journal) if str(r.get("source", "")).startswith("mtta")]
    total_cost = sum(a["cost_usd"] for a in agg.values() if a["cost_known"])
    if mtta and total_cost:
        L += [
            f"**MTTA-per-dollar inputs available** — latest MTTA rows: "
            f"{len(mtta)}; recorded spend ${total_cost:.2f}. Join lands "
            f"with the Executive-Trends chart.",
            "",
        ]

    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "spend-dashboard.md"
    out.write_text("\n".join(L) + "\n")
    return out
