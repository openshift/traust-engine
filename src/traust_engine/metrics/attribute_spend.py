"""Per-lane spend attribution — Phase 0 of the budget-guard widening plan.

WHY THIS EXISTS. Spend is tracked from two sources (docs/model-routing.md):
drivers *declare* per-skill spend via `model_registry.py spend`, and
`collect_session_spend.py` records session *actuals* from Claude Code
transcripts. In practice the declared side is often empty: most ledger spend
rows carry tokens_in: 0, tokens_out: 0, so the spend dashboard's per-skill
table reports $0.00 for governed lanes while the actuals side shows a large
monthly total with no per-lane breakdown.

That is NOT a bug in the emitters. It is the contract working as
written: 17 SKILL.md files instruct the agent to run
`--tokens-in <N or 0> --tokens-out <N or 0>`, and **an agent cannot
observe its own token usage mid-run** — there is no such API — so every
agent takes the `0` the contract offers. Asking the emitter to try
harder cannot fix it; the number does not exist on that side of the
boundary.

WHAT THIS DOES INSTEAD. The transcripts hold both halves already: real
per-message token usage AND evidence of which skill the session was
running. This collector walks each session in order, tracks which skill
is currently active, and attributes each message's usage to it —
turning the one trustworthy total into a per-lane breakdown without
asking any agent to self-report.

Attribution is INFERRED, so it is reported as such. A session's usage
before any skill signal, or in a session that never invokes one, lands
in an explicit `unattributed` bucket that is always printed. The
reconcile view proves the split is lossless against
collect_session_spend.py's own totals — an attribution that quietly
dropped tokens would be worse than no attribution at all.

Signals, strongest first (all must name a skill that exists in
skills/, so unrelated prose cannot mint a lane):
  1. a `Skill` tool call         -> input.skill
  2. a `<command-name>` block    -> the slash command's name
  3. a read of <skills-dir>/<skill>/SKILL.md (path segment `skills` or legacy `harnessing`)

Usage:
    traust metrics attribute-spend                # month to date
    traust metrics attribute-spend --month 2026-07
    traust metrics attribute-spend --date 2026-07-27
    traust metrics attribute-spend --reconcile    # lossless proof
    traust metrics attribute-spend --json
"""

from __future__ import annotations

import datetime
import json
import re
from collections import defaultdict
from pathlib import Path

from traust_engine.metrics import collect_spend as css
from traust_engine.metrics import history as metrics_ledger

TOKEN_KEYS = css.TOKEN_KEYS
UNATTRIBUTED = "unattributed"

_CMD_RX = re.compile(r"<command-name>\s*/?([A-Za-z0-9_-]+)\s*</command-name>")
# The optional leading segment is a workflow stage directory
# (skills/4-triage/triage/SKILL.md or legacy harnessing/...); the capture is
# always the skill itself. Both spellings must match — older transcripts
# recorded the flat path and are never rewritten.
_SKILL_MD_RX = re.compile(r"(?:harnessing|skills)/(?:[A-Za-z0-9_-]+/)?([A-Za-z0-9_-]+)/SKILL\.md")
# Cheap pre-filter: only these lines can carry a signal or usage, so the
# expensive json.loads is skipped for the bulk of a transcript.
_INTERESTING = ('"usage"', "command-name", "SKILL.md", '"Skill"')


def known_skills(harnessing_dir: Path | None = None) -> set[str]:
    """Skill names that actually exist. Gating on this keeps a prose
    mention of some other tool from inventing a lane."""
    raw = harnessing_dir
    if raw is None or not raw.is_dir():
        return set()
    # Two levels: skills sit at the skills/ root or under a stage
    # directory. Descend only into directories that are not themselves
    # skills, so a SKILL.md bundled inside a skill is not counted as one.
    found = set()
    for child in raw.iterdir():
        if not child.is_dir():
            continue
        if (child / "SKILL.md").is_file():
            found.add(child.name)
            continue
        found.update(g.name for g in child.iterdir() if g.is_dir() and (g / "SKILL.md").is_file())
    return found


def _iter_content(msg: dict):
    content = msg.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                yield block


def detect_skill(rec: dict, valid: set[str]) -> str | None:
    """Strongest available skill signal in one transcript record."""
    msg = rec.get("message") or {}
    # 1. an explicit Skill tool call
    for block in _iter_content(msg):
        if block.get("type") == "tool_use" and block.get("name") == "Skill":
            name = (block.get("input") or {}).get("skill")
            if isinstance(name, str):
                name = name.split(":")[-1].strip()
                if name in valid:
                    return name
    # 2/3. a slash command, or a read of the skill prompt. Both can sit
    # in user text or in tool input, so match over the record's text
    # form rather than guessing which field carries it.
    raw = json.dumps(rec)
    m = _CMD_RX.search(raw)
    if m and m.group(1) in valid:
        return m.group(1)
    m = _SKILL_MD_RX.search(raw)
    if m and m.group(1) in valid:
        return m.group(1)
    return None


def _blank() -> dict:
    return {k: 0 for k in TOKEN_KEYS} | {"messages": 0, "sessions": set()}


def collect_attributed(
    dirs: list[Path],
    day: str | None = None,
    month: str | None = None,
    valid: set[str] | None = None,
) -> dict:
    """-> {date: {skill: {model: {tokens..., messages, sessions}}}}.

    Walks each session IN ORDER so a mid-session skill invocation
    attributes the messages that follow it, not the whole file. Usage
    before any signal is `unattributed` rather than guessed at.
    """
    valid = known_skills() if valid is None else valid
    agg: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(_blank)))
    for d in dirs:
        for f in sorted(d.glob("*.jsonl")):
            sid = f.stem
            current = UNATTRIBUTED
            try:
                fh = f.open(encoding="utf-8", errors="replace")
            except OSError:
                continue
            with fh:
                for line in fh:
                    if not any(tok in line for tok in _INTERESTING):
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    found = detect_skill(rec, valid)
                    if found:
                        current = found
                    msg = rec.get("message") or {}
                    usage = msg.get("usage")
                    model = msg.get("model")
                    if not usage or not model or model.startswith("<"):
                        continue
                    ts = (rec.get("timestamp") or "")[:10]
                    if not ts:
                        continue
                    if day and ts != day:
                        continue
                    if month and not ts.startswith(month):
                        continue
                    a = agg[ts][current][model]
                    for k in TOKEN_KEYS:
                        a[k] += usage.get(k) or 0
                    a["messages"] += 1
                    a["sessions"].add(sid)
    return agg


def totals_by_skill(agg: dict) -> dict:
    """Collapse dates/models -> {skill: {tokens..., messages}}."""
    out: dict = defaultdict(lambda: {k: 0 for k in TOKEN_KEYS} | {"messages": 0, "sessions": set()})
    for _date, skills in agg.items():
        for skill, models in skills.items():
            for _model, a in models.items():
                t = out[skill]
                for k in TOKEN_KEYS:
                    t[k] += a[k]
                t["messages"] += a["messages"]
                t["sessions"] |= a["sessions"]
    return out


def grand_total(agg: dict) -> dict:
    tot = {k: 0 for k in TOKEN_KEYS} | {"messages": 0}
    for skills in agg.values():
        for models in skills.values():
            for a in models.values():
                for k in TOKEN_KEYS:
                    tot[k] += a[k]
                tot["messages"] += a["messages"]
    return tot


def reconcile(dirs: list[Path], day: str | None, month: str | None) -> dict:
    """Prove the attribution split is lossless against the existing
    collector. Any mismatch means tokens were dropped on the floor —
    reported as a failure, never rounded away."""
    attributed = grand_total(collect_attributed(dirs, day, month))
    baseline = {k: 0 for k in TOKEN_KEYS} | {"messages": 0}
    for date, models in css.collect(dirs, day).items():
        if month and not date.startswith(month):
            continue
        for a in models.values():
            for k in TOKEN_KEYS:
                baseline[k] += a[k]
            baseline["messages"] += a["messages"]
    deltas = {k: attributed[k] - baseline[k] for k in [*list(TOKEN_KEYS), "messages"]}
    return {
        "attributed": attributed,
        "baseline": baseline,
        "deltas": deltas,
        "lossless": all(v == 0 for v in deltas.values()),
    }


LEDGER_SOURCE_PREFIX = "spend-attribution:"


def already_recorded(ws: Path, journal: Path | None = None) -> set[tuple[str, str, str]]:
    """(date, skill, model) triples already in the ledger."""
    done = set()
    for r in metrics_ledger.rows(journal):
        src = str(r.get("source") or "")
        if not src.startswith(LEDGER_SOURCE_PREFIX):
            continue
        m = r.get("metrics") or {}
        if m.get("date") and m.get("skill") and m.get("model"):
            done.add((m["date"], m["skill"], m["model"]))
    return done


def append_rows(ws: Path, agg: dict, reg=None, journal: Path | None = None) -> int:
    """Append per (date, skill, model) rows to the hash-chained metrics
    ledger under `spend-attribution:<skill>`. A DELIBERATELY separate
    namespace from `model-spend:<skill>`: those are the driver-declared
    routing markers whose token fields are best-effort and usually zero,
    and mixing the two is what let a $0.00 table look authoritative.

    Idempotent, and only COMPLETED days are recorded — appending a
    partial day would freeze that day's undercount permanently (same
    rule as collect_session_spend.py)."""
    from traust_engine.registry import models as model_registry

    if reg is None:
        raise ValueError(
            "reg is required — pass model_registry from HarnessEngine.models.registry()"
        )
    today = datetime.date.today().isoformat()
    done = already_recorded(ws, journal=journal)
    appended = 0
    for date in sorted(agg):
        if date >= today:
            continue
        for skill, models in sorted(agg[date].items()):
            for model, a in sorted(models.items()):
                if (date, skill, model) in done:
                    continue
                try:
                    usd = model_registry.cost_usd(
                        reg,
                        model,
                        a["input_tokens"],
                        a["output_tokens"],
                        a["cache_read_input_tokens"],
                        a["cache_creation_input_tokens"],
                    )
                except Exception:
                    usd = None
                metrics_ledger.append(
                    f"{LEDGER_SOURCE_PREFIX}{skill}",
                    {
                        "date": date,
                        "skill": skill,
                        "model": model,
                        "tokens_in": a["input_tokens"],
                        "tokens_out": a["output_tokens"],
                        "cache_read": a["cache_read_input_tokens"],
                        "cache_creation": a["cache_creation_input_tokens"],
                        "messages": a["messages"],
                        "sessions": len(a["sessions"]),
                        "cost_usd": usd,
                        "attribution": "inferred-from-transcript",
                    },
                    journal=journal,
                )
                appended += 1
    return appended


def _fmt(n: int) -> str:
    return f"{n:,}"


def cost_by_skill(agg: dict, reg=None) -> tuple[dict, set]:
    """{skill: usd} at registry list prices, plus the set of models with
    no price. Priced per (skill, model) because rates differ by model;
    unpriced models are NAMED, never silently counted as $0 — that
    rounding is how the declared side came to read $0.00 everywhere."""
    try:
        from traust_engine.registry import models as model_registry

        if reg is None:
            return {}, set()
    except Exception:
        return {}, set()
    out: dict = defaultdict(float)
    unpriced: set = set()
    for skills in agg.values():
        for skill, models in skills.items():
            for model, a in models.items():
                try:
                    usd = model_registry.cost_usd(
                        reg,
                        model,
                        a["input_tokens"],
                        a["output_tokens"],
                        a["cache_read_input_tokens"],
                        a["cache_creation_input_tokens"],
                    )
                except Exception:
                    usd = None
                if usd is None:
                    unpriced.add(model)
                    continue
                out[skill] += usd
    return dict(out), unpriced


def render(agg: dict, month_label: str, reg=None) -> list[str]:
    by_skill = totals_by_skill(agg)
    costs, unpriced = cost_by_skill(agg, reg=reg)
    tot_usd = sum(costs.values())
    tot_out = sum(v["output_tokens"] for v in by_skill.values()) or 1
    lines = [
        f"# Per-lane spend attribution — {month_label}",
        "",
        "_Inferred from session transcripts (which skill the session "
        "was running), not self-reported by agents — the declared "
        "side records 0 tokens by contract. `unattributed` is "
        "always shown._",
        "",
        "| Lane | Est. USD | Share | Output tokens | Cache read | Messages | Sessions |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    ordered = sorted(
        by_skill.items(), key=lambda kv: -costs.get(kv[0], kv[1]["output_tokens"] / 1e9)
    )
    for skill, a in ordered:
        usd = costs.get(skill)
        share = f"{usd / tot_usd * 100:.1f}%" if usd is not None and tot_usd else "—"
        lines.append(
            f"| {skill} | {f'{usd:,.2f}' if usd is not None else 'n/a'} | "
            f"{share} | {_fmt(a['output_tokens'])} | "
            f"{_fmt(a['cache_read_input_tokens'])} | "
            f"{_fmt(a['messages'])} | {len(a['sessions'])} |"
        )
    lines += ["", f"**Total priced: ${tot_usd:,.2f}**"]
    lane_usd = sum(v for k, v in costs.items() if k != UNATTRIBUTED)
    if tot_usd:
        lines += [
            f"**Harness lanes: ${lane_usd:,.2f} "
            f"({lane_usd / tot_usd * 100:.1f}%)** · "
            f"unattributed ${costs.get(UNATTRIBUTED, 0):,.2f} "
            f"({costs.get(UNATTRIBUTED, 0) / tot_usd * 100:.1f}%)"
        ]
    else:
        # Nothing priceable (all models unpriced). The lane vs
        # unattributed split is the headline of this report, so fall
        # back to output tokens rather than dropping the line.
        lane_tok = sum(v["output_tokens"] for k, v in by_skill.items() if k != UNATTRIBUTED)
        un_tok = by_skill.get(UNATTRIBUTED, {}).get("output_tokens", 0)
        lines += [
            f"**Harness lanes: {_fmt(lane_tok)} output tokens "
            f"({lane_tok / tot_out * 100:.1f}%)** · unattributed "
            f"{_fmt(un_tok)} ({un_tok / tot_out * 100:.1f}%) — "
            f"no USD: no model in this window has a registry price"
        ]
    if unpriced:
        lines += [
            "",
            f"⚠ unpriced models excluded from the USD column "
            f"(no registry price): {', '.join(sorted(unpriced))}",
        ]
    lines += [
        "",
        f"_Share of output tokens is a cross-check on the USD "
        f"split; total output {_fmt(tot_out)}._",
    ]
    return lines
