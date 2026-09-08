"""Rule-mining lane runner — mine → sweep collect/draft → draft staging → delta.

One orchestrator-neutral entry point for the weekly rule-mining lane
(docs/continuous-scanning.md, "Lane cadences"; the dependency-watch
pattern: identical behavior from an operator session, cron, or any
enterprise scheduler). Deterministic stages ONLY — no model calls; rule
authoring and the test-and-calibrate gate belong to the rule calibration
session this lane's delta report feeds.

Stages (each a shipped deterministic script, invoked in order):

  1. snapshot   read the previous rule-mining.json before it is
                overwritten — the delta baseline
  2. mine       traust sweep mine — TP corpus, pack
                coverage, per-rule precision → rule-mining.{json,md} +
                tp-corpus.jsonl
  3. sweep      traust sweep collect --force, then draft —
                class-generalization state refresh + new candidate-rule
                skeletons for uncovered expressible classes
  4. drafts     skills/mine-ledger/scripts/emit_rule_drafts.py
                (--skip-existing --limit N) — bounded regression-draft
                staging from resolved-at-fix-commit ledger findings
                (--draft-limit 0 skips; existing draft dirs are never
                clobbered). Auto-discovered under the campaign workspace
                unless overridden via --emit-drafts-script or
                EMIT_RULE_DRAFTS_SCRIPT.
  5. delta      compare the fresh rule-mining.json against the snapshot:
                new/resolved/changed uncovered clusters, precision
                movements crossing the ~50% gate, TP-corpus growth →
                lane-delta.{json,md} beside the mining artifacts
  6. reach      Stage-A gate reachability per watched language and
                candidate pack — is calibrating that language possible
                yet? No clones. Attention only when a gate OPENS.
  7. allowlist  precision re-check for rules enabled from an external
                pack via config/rule-pack-allowlist.yaml — the half of
                the promotion gate Stage A cannot measure before a rule
                has ever run

Exit semantics (lane-runner convention):
  0  ran clean, nothing needs attention
  1  attention needed — new/grown uncovered clusters, a rule fell below
     (or entered below) the precision gate, drafts were staged, a
     Stage-A gate opened for a previously blocked language, or an
     enabled external-pack rule dropped below the precision gate; the
     delta report says exactly what
  2  a stage failed (partial results are stated, never silent)

The lane NEVER files findings and never routes externally: sweep hits and
mined candidates route to the triage workflow like any other candidate batch; rule
promotion stays behind the pack's mechanical test-and-calibrate gate.

Usage:
    python3 -m traust_engine.sweep.rule_lane [--workspace DIR]
        [--out DIR] [--draft-limit N] [--skip-sweep]
        [--emit-drafts-script PATH]
"""

from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from traust_contracts import DeploymentConfigMissing

from traust_engine.adapters import opengrep as OG

if TYPE_CHECKING:
    from traust_engine.engine import HarnessEngine

PRECISION_GATE = 0.5  # the opengrep-ruleset plan's ~50% precision gate
DEFAULT_DRAFT_LIMIT = 6

# Languages whose Stage-A calibration is blocked on ground truth rather
# than on tooling (measured 2026-08-07: no argus-covered CWE spans the
# 3 repos the rediscovery gate needs; max span is 1, and cpp shares no
# CWE with the pack at all). Watched here so the gate opening is noticed
# on cadence instead of being rediscovered by hand.
WATCHED_LANGS = ("rust", "c", "cpp", "csharp")
# Candidate external packs to test reachability against. A pack enters
# this list when it is a promotion candidate, not when it is merely
# fetchable.
WATCHED_PACKS = {
    "argus-observe-rules": "https://github.com/smith-xyz/argus-observe-rules"
    "@2a94aebee9a26a7e0325582330c4eed232b984fb",
}


_EMIT_DRAFTS_REL_PATHS = (
    Path("skills/mine-ledger/scripts/emit_rule_drafts.py"),
    Path("harnessing/mine-ledger/scripts/emit_rule_drafts.py"),
)


def _resolve_emit_drafts_script(ws: Path, explicit: Path | None) -> Path | None:
    """Regression-draft staging lives in the harness repo (skill script).

    Resolution order: CLI flag, EMIT_RULE_DRAFTS_SCRIPT env, then the
    conventional paths under the campaign workspace (sibling checkout or
    harness-as-workspace-root).
    """
    if explicit is not None:
        return explicit if explicit.is_file() else None
    env = os.environ.get("EMIT_RULE_DRAFTS_SCRIPT")
    if env:
        p = Path(env)
        return p.resolve() if p.is_file() else None
    for rel in _EMIT_DRAFTS_REL_PATHS:
        for candidate in (ws / "traust" / rel, ws / rel):
            if candidate.is_file():
                return candidate.resolve()
    return None


def _now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cluster_key(c: dict) -> str:
    return f"{c.get('cwe')}/{c.get('language')}"


def compute_reachability(corpus_path: Path, packs: dict | None = None) -> dict:
    """Per-language Stage-A gate reachability for each watched pack.

    Answers "is calibrating this language even possible yet?" without
    cloning anything: a rule clears the rediscovery gate only by firing
    in >=3 repos that share a CWE the pack targets, so if no covered CWE
    spans that many repos the run is unwinnable before it starts.

    Cheap (pure corpus + cached pack read), so it runs every lane pass.
    The point is to notice the gate OPENING on cadence — the alternative
    is rediscovering it by hand, or worse, running a scan that returns a
    table of structural zeros and reading it as a verdict on the pack.
    """
    from traust_engine.sweep import calibration as crp

    corpus = crp.load_corpus(corpus_path)
    if not corpus:
        return {"available": False, "reason": f"no corpus at {corpus_path}"}

    out: dict = {"available": True, "gate": crp.REDISCOVERY_GATE, "packs": {}}
    for name, src in (packs if packs is not None else WATCHED_PACKS).items():
        covered = crp.pack_cwes(src)
        if not covered:
            # Not cached locally: skip rather than guess. Reporting
            # "unreachable" from a missing pack would be a false negative.
            out["packs"][name] = {"available": False, "reason": "pack not cached"}
            continue
        langs = {}
        for lang in WATCHED_LANGS:
            targets = crp.select_targets(corpus, None, langs={lang})
            span, cwe = crp.gate_reachability(targets, covered)
            langs[lang] = {
                "repos": len(targets),
                "max_span": span,
                "widest_covered_cwe": cwe,
                "reachable": span >= crp.REDISCOVERY_GATE,
            }
        out["packs"][name] = {"available": True, "languages": langs}
    return out


def reachability_crossings(prev: dict | None, cur: dict) -> list[dict]:
    """Languages whose gate opened (or closed) since the last lane run.

    An opening is the actionable event — it means a Stage-A run on that
    language is finally worth its clone time.
    """
    if not cur.get("available"):
        return []
    crossings = []
    prev_packs = (prev or {}).get("packs") or {}
    for pack, pdata in sorted((cur.get("packs") or {}).items()):
        if not pdata.get("available"):
            continue
        was = (prev_packs.get(pack) or {}).get("languages") or {}
        for lang, row in sorted((pdata.get("languages") or {}).items()):
            before = (was.get(lang) or {}).get("reachable")
            if before is None or before == row["reachable"]:
                continue
            crossings.append(
                {
                    "pack": pack,
                    "language": lang,
                    "direction": "opened" if row["reachable"] else "closed",
                    "max_span": row["max_span"],
                    "widest_covered_cwe": row["widest_covered_cwe"],
                    "repos": row["repos"],
                }
            )
    return crossings


def allowlist_precision(cur: dict, allowlist_path: Path | None) -> dict:
    """Measured precision for every rule currently enabled via the
    external-pack allowlist.

    Closes the promotion loop. Stage A can only measure rediscovery
    before first run; precision arrives afterwards from
    scanner_correlation, so an enabled rule needs re-checking against
    the ~50% gate on cadence. A rule below it is a demotion candidate —
    the lane reports it and the operator edits one YAML line, rather
    than the pack quietly costing triage time nobody re-examines.
    """
    if allowlist_path is None or not allowlist_path.is_file():
        return {"available": False, "reason": "no rule-pack-allowlist.yaml"}
    try:
        allow, _ = OG.load_rule_allowlist(f"@{allowlist_path}")
    except (ImportError, SystemExit) as e:
        return {"available": False, "reason": f"allowlist unreadable: {e}"}

    prec = cur.get("rule_precision") or {}
    rows, unmeasured = [], []
    for rid in sorted(allow or ()):
        p = (prec.get(rid) or {}).get("precision")
        if p is None:
            # Expected until the rule has run in enough audits; silence
            # is not a pass, so it is reported separately rather than
            # folded in as "fine".
            unmeasured.append(rid)
            continue
        rows.append(
            {
                "rule": rid,
                "precision": p,
                "below_gate": p < PRECISION_GATE,
                "promoted": (prec.get(rid) or {}).get("promoted"),
                "dismissed": (prec.get(rid) or {}).get("dismissed"),
            }
        )
    return {
        "available": True,
        "enabled": len(allow or ()),
        "measured": rows,
        "unmeasured": unmeasured,
        "below_gate": [r for r in rows if r["below_gate"]],
    }


def compute_delta(prev: dict | None, cur: dict) -> dict:
    """Pure delta between two rule-mining.json documents.

    A missing/unreadable previous artifact is a BASELINE run: the
    existing picture is inventory, not news (release-events convention)
    — all delta lists stay empty and `baseline` is set.
    """
    delta: dict = {
        "generated_at": _now_iso(),
        "precision_gate": PRECISION_GATE,
        "baseline": prev is None,
        "tp_corpus": {},
        "new_uncovered_clusters": [],
        "resolved_uncovered_clusters": [],
        "changed_uncovered_clusters": [],
        "precision_gate_crossings": [],
        "attention": {"needed": False, "reasons": []},
    }
    cur_stats = cur.get("stats") or {}
    delta["tp_corpus"] = {
        "confirmed_tps": cur_stats.get("confirmed_tps"),
        "ruleable_tps": cur_stats.get("ruleable_tps"),
        "growth": None,
    }
    if prev is None:
        delta["attention"]["reasons"].append(
            "baseline run — no previous rule-mining.json to diff against"
        )
        return delta

    prev_stats = prev.get("stats") or {}
    if isinstance(prev_stats.get("confirmed_tps"), int) and isinstance(
        cur_stats.get("confirmed_tps"), int
    ):
        delta["tp_corpus"]["growth"] = cur_stats["confirmed_tps"] - prev_stats["confirmed_tps"]

    prev_unc = {_cluster_key(c): c for c in prev.get("uncovered_clusters") or []}
    cur_unc = {_cluster_key(c): c for c in cur.get("uncovered_clusters") or []}
    for key in sorted(set(cur_unc) - set(prev_unc)):
        c = cur_unc[key]
        delta["new_uncovered_clusters"].append(
            {
                "cluster": key,
                "count": c.get("count"),
                "repos": c.get("repos"),
                "example_findings": (c.get("example_findings") or [])[:3],
            }
        )
    for key in sorted(set(prev_unc) - set(cur_unc)):
        delta["resolved_uncovered_clusters"].append(
            {
                "cluster": key,
                "previous_count": prev_unc[key].get("count"),
            }
        )
    for key in sorted(set(prev_unc) & set(cur_unc)):
        p_n, c_n = prev_unc[key].get("count"), cur_unc[key].get("count")
        if p_n != c_n:
            delta["changed_uncovered_clusters"].append(
                {
                    "cluster": key,
                    "previous_count": p_n,
                    "count": c_n,
                }
            )

    prev_prec = prev.get("rule_precision") or {}
    cur_prec = cur.get("rule_precision") or {}
    for rid in sorted(cur_prec):
        cp = (cur_prec[rid] or {}).get("precision")
        if cp is None:
            continue
        pp = (prev_prec.get(rid) or {}).get("precision")
        row = {"rule": rid, "previous_precision": pp, "precision": cp}
        if pp is None:
            if cp < PRECISION_GATE:
                delta["precision_gate_crossings"].append({**row, "direction": "entered_below_gate"})
        elif pp >= PRECISION_GATE > cp:
            delta["precision_gate_crossings"].append({**row, "direction": "fell_below_gate"})
        elif pp < PRECISION_GATE <= cp:
            delta["precision_gate_crossings"].append({**row, "direction": "rose_above_gate"})

    reasons = delta["attention"]["reasons"]
    if delta["new_uncovered_clusters"]:
        reasons.append(
            f"{len(delta['new_uncovered_clusters'])} new "
            "uncovered cluster(s) — rule-authoring backlog grew"
        )
    grown = [
        c
        for c in delta["changed_uncovered_clusters"]
        if isinstance(c["count"], int)
        and isinstance(c["previous_count"], int)
        and c["count"] > c["previous_count"]
    ]
    if grown:
        reasons.append(
            f"{len(grown)} uncovered cluster(s) grew — the gap is accumulating confirmed TPs"
        )
    below = [
        x
        for x in delta["precision_gate_crossings"]
        if x["direction"] in ("fell_below_gate", "entered_below_gate")
    ]
    if below:
        reasons.append(
            f"{len(below)} rule(s) below the "
            f"{PRECISION_GATE:.0%} precision gate — tighten "
            "or retire per the plan"
        )
    delta["attention"]["needed"] = bool(reasons)
    return delta


def render_delta_md(delta: dict, stages: list[dict]) -> str:
    a = delta["attention"]
    L = [
        "# Rule-mining lane — delta report",
        "",
        f"_Generated {delta['generated_at']} by "
        f"`python3 -m traust_engine.sweep.rule_lane` (deterministic stages only; "
        f"authoring + calibration follow in the scheduled rule calibration "
        f"session)._",
        "",
    ]
    if delta["baseline"]:
        L += [
            "**Baseline run** — no previous rule-mining.json; the "
            "current picture is inventory, not news.",
            "",
        ]
    tc = delta["tp_corpus"]
    growth = tc.get("growth")
    attention = "YES — " + "; ".join(a["reasons"]) if a["needed"] else "none"
    L += [
        f"- **TP corpus:** {tc.get('confirmed_tps')} confirmed "
        f"({tc.get('ruleable_tps')} rule-able)"
        + (f", **{growth:+d}** vs the previous mine" if isinstance(growth, int) else ""),
        f"- **Attention:** {attention}",
        "",
    ]
    if delta["new_uncovered_clusters"]:
        L += [
            "## New uncovered clusters",
            "",
            "| Cluster | TPs | Repos | Example findings |",
            "|---|---|---|---|",
        ]
        for c in delta["new_uncovered_clusters"]:
            L.append(
                f"| {c['cluster']} | {c['count']} | {c['repos']} | "
                f"{', '.join(c['example_findings'] or [])} |"
            )
        L.append("")
    if delta["changed_uncovered_clusters"]:
        L += [
            "## Changed uncovered clusters",
            "",
            "| Cluster | Previous TPs | TPs |",
            "|---|---|---|",
        ]
        for c in delta["changed_uncovered_clusters"]:
            L.append(f"| {c['cluster']} | {c['previous_count']} | {c['count']} |")
        L.append("")
    if delta["resolved_uncovered_clusters"]:
        L += ["## Resolved uncovered clusters (covered or emptied)", ""]
        for c in delta["resolved_uncovered_clusters"]:
            L.append(f"- {c['cluster']} (was {c['previous_count']} TPs)")
        L.append("")
    if delta["precision_gate_crossings"]:
        L += [
            f"## Precision movements across the {delta['precision_gate']:.0%} gate",
            "",
            "| Rule | Previous | Now | Direction |",
            "|---|---|---|---|",
        ]
        for x in delta["precision_gate_crossings"]:
            prev = "n/a" if x["previous_precision"] is None else f"{x['previous_precision']:.0%}"
            L.append(f"| {x['rule']} | {prev} | {x['precision']:.0%} | {x['direction']} |")
        L.append("")
    reach = delta.get("reachability") or {}
    if reach.get("available"):
        gate = reach.get("gate")
        L += [
            f"## Stage-A gate reachability (gate = {gate} repos)",
            "",
            "Can a language be calibrated at all yet? A rule clears the "
            "gate only by firing in >= gate repos that share a CWE the "
            "pack targets, so an unreachable language returns a table of "
            "structural zeros — untestable, **not** a verdict on the "
            "pack.",
            "",
        ]
        for pack, pdata in sorted((reach.get("packs") or {}).items()):
            if not pdata.get("available"):
                L += [f"**{pack}** — skipped ({pdata.get('reason')})", ""]
                continue
            L += [
                f"**{pack}**",
                "",
                "| Language | Repos | Widest covered CWE | Max span | Reachable |",
                "|---|---:|---|---:|---|",
            ]
            for lang, r in sorted((pdata.get("languages") or {}).items()):
                L.append(
                    f"| {lang} | {r['repos']} | "
                    f"{r['widest_covered_cwe'] or '—'} | "
                    f"{r['max_span']} | "
                    f"{'**YES**' if r['reachable'] else 'no'} |"
                )
            L.append("")
    for c in delta.get("reachability_crossings") or []:
        L += [
            f"> **Gate {c['direction'].upper()}: {c['language']} vs "
            f"{c['pack']}** — {c['widest_covered_cwe']} now spans "
            f"{c['max_span']} of {c['repos']} repos.",
            "",
        ]
    ap = delta.get("allowlist_precision") or {}
    if ap.get("available"):
        L += [
            f"## Enabled external-pack rules vs the {delta['precision_gate']:.0%} precision gate",
            "",
            f"{ap['enabled']} rule(s) enabled via "
            "`config/rule-pack-allowlist.yaml`; "
            f"{len(ap['measured'])} have measured precision, "
            f"{len(ap['unmeasured'])} not yet judged in any audit "
            "(silence is not a pass).",
            "",
        ]
        if ap["measured"]:
            L += ["| Rule | Precision | Promoted | Dismissed | |", "|---|---:|---:|---:|---|"]
            for r in sorted(ap["measured"], key=lambda x: x["precision"]):
                L.append(
                    f"| {r['rule']} | {r['precision']:.0%} | "
                    f"{r['promoted']} | {r['dismissed']} | "
                    f"{'**DEMOTE**' if r['below_gate'] else 'ok'} |"
                )
            L.append("")
    L += ["## Stage results", "", "| Stage | Status | Summary |", "|---|---|---|"]
    for s in stages:
        L.append(f"| {s['stage']} | {s['status']} | {s.get('summary', '')[:200]} |")
    L.append("")
    return "\n".join(L)


def _record_stage(stages: list[dict], stage: str, rc: int, summary: str) -> bool:
    stages.append(
        {
            "stage": stage,
            "status": "ok" if rc == 0 else "failed",
            "returncode": rc,
            "summary": summary,
        }
    )
    if rc != 0:
        print(f"[{stage}] FAILED (rc {rc}): {summary[:400]}", file=sys.stderr)
    else:
        print(f"[{stage}] {summary}")
    return rc == 0


def _run_stage(stage: str, argv: list[str], stages: list[dict]) -> bool:
    """Run one external-script stage; record its tail line. True on rc 0."""
    cmd = [sys.executable, *argv]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    tail = [ln for ln in (proc.stdout or "").strip().splitlines() if ln]
    summary = tail[-1] if tail else (proc.stderr or "").strip()[-200:]
    return _record_stage(stages, stage, proc.returncode, summary)


def _run_mine_stage(findings_root: Path, out: Path, stages: list[dict]) -> bool:
    import io
    from contextlib import redirect_stderr, redirect_stdout

    from traust_engine.sweep.mining import mine

    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        rc = mine(findings_root, out)
    tail = [ln for ln in buf.getvalue().strip().splitlines() if ln]
    return _record_stage(stages, "mine", rc, tail[-1] if tail else "")


def _run_sweep_collect_stage(ops, ar: Path, stages: list[dict]) -> bool:
    from traust_engine.locations import FINDINGS_REL, PHASE0_REL, SWEEPS_REL

    try:
        res = ops.collect(
            results_root=ar / FINDINGS_REL,
            phase0_root=ar / PHASE0_REL,
            sweeps_root=ar / SWEEPS_REL,
            force=True,
        )
    except Exception as e:
        return _record_stage(stages, "sweep-collect", 1, str(e))
    if res["skipped"]:
        summary = f"collect: state exists, skipping ({res['state']}) — use --force to re-collect"
    else:
        summary = (
            f"collect: {res['confirmed_findings']} confirmed "
            f"finding(s) ({res['by_source']}); "
            f"{res['rule_expressible']} rule-expressible across "
            f"{res['classes']} class(es); "
            f"{res['not_expressible']} not expressible (reasons "
            f"recorded) -> {res['state']}"
        )
    return _record_stage(stages, "sweep-collect", 0, summary)


def _run_sweep_draft_stage(engine, ops, ar: Path, stages: list[dict]) -> bool:
    from traust_engine.locations import SWEEPS_REL, rule_drafts_dir

    drafts = rule_drafts_dir(engine.ctx.locations)
    if drafts is None:
        return _record_stage(
            stages,
            "sweep-draft",
            1,
            "rule drafts dir not configured — set rule_drafts "
            "or progress_tracker in locations.yaml",
        )
    try:
        pack = engine.adapters.rule_pack_dir()
        res = ops.draft(pack, drafts, sweeps_root=ar / SWEEPS_REL)
    except Exception as e:
        return _record_stage(stages, "sweep-draft", 1, str(e))
    summary = (
        f"draft: {len(res['emitted'])} draft(s) staged "
        f"({', '.join(res['emitted']) or 'none'}); "
        f"{len(res['skipped'])} class(es) skipped — author "
        "patterns, calibrate via mine-ledger, then `sweep` runs "
        "by default"
    )
    return _record_stage(stages, "sweep-draft", 0, summary)


def execute_rule_lane(
    *,
    workspace: Path | None = None,
    out: Path | None = None,
    draft_limit: int = DEFAULT_DRAFT_LIMIT,
    skip_sweep: bool = False,
    emit_drafts_script: Path | None = None,
    engine: HarnessEngine,
) -> int:
    ops = engine.sweep
    allowlist_path = engine.adapters.rule_pack_allowlist_path()
    if workspace is not None:
        ws = workspace.resolve()
    else:
        try:
            ws = ops._workspace()
        except DeploymentConfigMissing:
            print(
                "workspace required: pass --workspace or set locations.workspace", file=sys.stderr
            )
            return 2
    try:
        ar = ops._analysis_results()
    except DeploymentConfigMissing as e:
        print(str(e), file=sys.stderr)
        return 2
    try:
        pt = ops._progress_tracker()
    except DeploymentConfigMissing as e:
        print(str(e), file=sys.stderr)
        return 2
    findings_root = ar / "findings"
    out_dir = (out or pt / "metrics" / "rule-mining").resolve()
    if not findings_root.is_dir():
        print(f"not a findings tree: {findings_root}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    stages: list[dict] = []

    # 1. snapshot the previous artifact before the miner overwrites it
    prev = None
    prev_path = out_dir / "rule-mining.json"
    if prev_path.is_file():
        try:
            prev = json.loads(prev_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prev = None
    # ...and the previous lane-delta, which carries the prior
    # reachability state this run diffs against.
    prev_delta = None
    prev_delta_path = out_dir / "lane-delta.json"
    if prev_delta_path.is_file():
        try:
            prev_delta = json.loads(prev_delta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prev_delta = None
    stages.append(
        {
            "stage": "snapshot",
            "status": "ok",
            "returncode": 0,
            "summary": (
                "previous rule-mining.json loaded"
                if prev
                else "no previous artifact — baseline run"
            ),
        }
    )

    # 2. mine — the corpus of record; a failure here is fatal (no
    #    current picture to diff)
    if not _run_mine_stage(findings_root, out_dir, stages):
        return 2

    # 3. sweep-engine collect (--force: state must reflect this run's
    #    ledgers) + draft (idempotent — existing drafts skipped)
    failed = False
    if skip_sweep:
        stages.append(
            {
                "stage": "sweep-collect",
                "status": "skipped",
                "returncode": 0,
                "summary": "--skip-sweep",
            }
        )
        stages.append(
            {
                "stage": "sweep-draft",
                "status": "skipped",
                "returncode": 0,
                "summary": "--skip-sweep",
            }
        )
    else:
        ok = _run_sweep_collect_stage(ops, ar, stages)
        if ok:
            ok = _run_sweep_draft_stage(engine, ops, ar, stages)
        failed = failed or not ok

    # 4. bounded regression-draft staging (never clobbers existing
    #    drafts — authored-but-unpromoted patterns survive re-runs)
    if draft_limit > 0:
        drafts_script = _resolve_emit_drafts_script(ws, emit_drafts_script)
        if drafts_script is None:
            stages.append(
                {
                    "stage": "regression-drafts",
                    "status": "skipped",
                    "returncode": 0,
                    "summary": "emit_rule_drafts script not configured",
                }
            )
        else:
            ok = _run_stage(
                "regression-drafts",
                [
                    str(drafts_script),
                    "--results-root",
                    str(ar),
                    "--limit",
                    str(draft_limit),
                    "--skip-existing",
                ],
                stages,
            )
            failed = failed or not ok
    else:
        stages.append(
            {
                "stage": "regression-drafts",
                "status": "skipped",
                "returncode": 0,
                "summary": "--draft-limit 0",
            }
        )

    # 5. delta vs the snapshot
    try:
        cur = json.loads(prev_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"cannot read the fresh rule-mining.json: {e}", file=sys.stderr)
        return 2
    delta = compute_delta(prev, cur)

    # staged drafts are authoring work for the scheduled session —
    # attention, except on a baseline run (inventory, not news)
    drafts_staged = 0
    for s in stages:
        m = None
        if s["stage"] == "sweep-draft" and s["status"] == "ok":
            m = re.search(r"draft:\s*(\d+) draft", s.get("summary") or "")
        elif s["stage"] == "regression-drafts" and s["status"] == "ok":
            m = re.match(r"(\d+) draft", s.get("summary") or "")
        if m:
            drafts_staged += int(m.group(1))
    delta["drafts_staged"] = drafts_staged
    if drafts_staged and not delta["baseline"]:
        delta["attention"]["reasons"].append(
            f"{drafts_staged} rule draft(s) staged awaiting authoring"
        )
        delta["attention"]["needed"] = True

    # 6. Stage-A gate reachability for the languages blocked on ground
    #    truth. No clones; the previous lane-delta carries the prior
    #    state, so an opening is detected the pass after it happens.
    delta["reachability"] = compute_reachability(out_dir / "tp-corpus.jsonl")
    crossings = reachability_crossings(
        (prev_delta or {}).get("reachability"), delta["reachability"]
    )
    delta["reachability_crossings"] = crossings
    for c in crossings:
        if c["direction"] != "opened":
            continue
        delta["attention"]["reasons"].append(
            f"Stage-A gate OPENED for {c['language']} vs {c['pack']} "
            f"({c['widest_covered_cwe']} now spans {c['max_span']} repos) "
            f"— calibrating that language is finally worth the clone time"
        )
        delta["attention"]["needed"] = True

    # 7. precision re-check for rules already enabled from an external
    #    pack — the other half of the promotion gate, which Stage A
    #    structurally cannot supply before first run.
    delta["allowlist_precision"] = allowlist_precision(cur, allowlist_path)
    below = delta["allowlist_precision"].get("below_gate") or []
    if below:
        delta["attention"]["reasons"].append(
            f"{len(below)} enabled pack rule(s) below the "
            f"{PRECISION_GATE:.0%} precision gate "
            f"({', '.join(r['rule'] for r in below[:3])}"
            f"{'...' if len(below) > 3 else ''}) — demote in "
            "config/rule-pack-allowlist.yaml or tighten"
        )
        delta["attention"]["needed"] = True

    delta["stages"] = stages
    (out_dir / "lane-delta.json").write_text(json.dumps(delta, indent=2) + "\n", encoding="utf-8")
    (out_dir / "lane-delta.md").write_text(render_delta_md(delta, stages), encoding="utf-8")

    a = delta["attention"]
    tc = delta["tp_corpus"]
    growth = tc.get("growth")
    print(
        f"rule-mining lane: TPs {tc.get('confirmed_tps')}"
        + (f" ({growth:+d})" if isinstance(growth, int) else "")
        + f"; uncovered clusters +{len(delta['new_uncovered_clusters'])}"
        f" new / {len(delta['resolved_uncovered_clusters'])} resolved"
        f" / {len(delta['changed_uncovered_clusters'])} changed;"
        f" gate crossings {len(delta['precision_gate_crossings'])};"
        f" attention: "
        + ("; ".join(a["reasons"]) if a["needed"] else "none")
        + f" -> {out_dir}/lane-delta.{{json,md}}"
    )
    if failed:
        return 2
    return 1 if a["needed"] else 0
