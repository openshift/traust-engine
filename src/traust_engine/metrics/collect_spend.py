"""Session-spend collector — the ACTUALS side of spend tracking.

Claude Code writes per-message token usage into its session transcripts
(~/.claude/projects/<project-slug>/*.jsonl → message.usage with model,
input/output/cache_read/cache_creation token counts). This collector
aggregates them so the harness can SEE its own spend:

  live view (default)   today's running totals per model — the real-time
                        answer to "what are we burning right now"
  --date YYYY-MM-DD     one day's totals
  --append              append per-day×model rows to the hash-chained
                        metrics ledger (source `model-spend:sessions`),
                        idempotent: days already recorded are skipped

PLANNED (operator request 2026-07-29): when the central orchestration
platform lands, teach this collector to also read centralized session
transcripts (a --transcripts-root pointing at the platform's transcript
store, same JSONL shape) so the spend-actuals leg stops being the one
dashboard input bound to operator workstations
(docs/continuous-scanning.md, standing-jobs dashboards row).

Two-source design (docs/model-routing.md → "How spend is tracked"):
drivers *declare* per-skill spend via `model_registry.py spend`;
this collector records session *actuals*. The dashboard shows both —
drift between declared and actual is itself a signal.

Cache-aware: cache_read tokens are tracked separately (they price ~an
order of magnitude below fresh input); cost math applies when the
registry carries prices.
"""

from __future__ import annotations

import datetime
import json
from collections import defaultdict
from pathlib import Path

from traust_engine.metrics import history as metrics_ledger

PROJECTS = Path.home() / ".claude" / "projects"
TOKEN_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
)


def workspace_slugs(workspace: Path) -> list[Path]:
    """Project dirs whose slug encodes a path under the workspace."""
    prefix = str(workspace).replace("/", "-")
    if not PROJECTS.is_dir():
        return []
    return [d for d in PROJECTS.iterdir() if d.is_dir() and d.name.startswith(prefix)]


def collect(dirs: list[Path], day: str | None) -> dict:
    """{date: {model: {tokens..., messages, sessions:set}}}"""
    agg: dict = defaultdict(
        lambda: defaultdict(lambda: {k: 0 for k in TOKEN_KEYS} | {"messages": 0, "sessions": set()})
    )
    for d in dirs:
        for f in d.glob("*.jsonl"):
            sid = f.stem
            try:
                fh = f.open(encoding="utf-8", errors="replace")
            except OSError:
                continue
            with fh:
                for line in fh:
                    if '"usage"' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    msg = rec.get("message") or {}
                    usage = msg.get("usage")
                    model = msg.get("model")
                    if not usage or not model or model.startswith("<"):
                        continue
                    ts = (rec.get("timestamp") or "")[:10]
                    if not ts or (day and ts != day):
                        continue
                    a = agg[ts][model]
                    for k in TOKEN_KEYS:
                        a[k] += usage.get(k) or 0
                    a["messages"] += 1
                    a["sessions"].add(sid)
    return agg


def _row(model: str, a: dict) -> dict:
    return {
        "model": model,
        "tokens_in": a["input_tokens"],
        "tokens_out": a["output_tokens"],
        "cache_read": a["cache_read_input_tokens"],
        "cache_creation": a["cache_creation_input_tokens"],
        "messages": a["messages"],
        "sessions": len(a["sessions"]),
    }


def already_recorded(ws: Path, journal: Path | None = None) -> set[tuple[str, str]]:
    done = set()
    for r in metrics_ledger.rows(journal):
        if r.get("source") == "model-spend:sessions":
            m = r.get("metrics", {})
            if m.get("date") and m.get("model"):
                done.add((m["date"], m["model"]))
    return done


def append_rows(ws: Path, dirs: list[Path], journal: Path | None = None) -> int:
    today = datetime.date.today().isoformat()
    agg = collect(dirs, None)
    done = already_recorded(ws, journal=journal)
    appended = 0
    for date in sorted(agg):
        if date >= today:
            continue
        for model, a in sorted(agg[date].items()):
            if (date, model) in done:
                continue
            metrics_ledger.append(
                "model-spend:sessions",
                {"date": date, **_row(model, a)},
                journal=journal,
            )
            appended += 1
    return appended
