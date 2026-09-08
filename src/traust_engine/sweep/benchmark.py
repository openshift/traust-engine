"""Validation-lane benchmark — validation-improvement-plan P7.

Measures the validate* lanes the way recall-benchmark measures the
auditor: known-exploitable fixtures the lanes must CONFIRM
(confirm-recall) and known-safe twins they must REFUTE with sound
evidence (refute-precision, a live test of the P1 positive controls),
plus severity accuracy against planted CVSS vectors (P9).

Hybrid cadence (decision 2026-07-25): run on release-cuts that touch
validation-lane paths (`--check-trigger`) AND monthly for drift
(`/drift-watch` flags a stale benchmark).

Modes:
  plan                       emit the benchmark worklist: fixture pairs,
                             synthetic benchmark-findings.json (the
                             claims the lanes will validate), deploy
                             commands. No cluster, no spend.
  check-trigger --since REF  exit 10 if validation-lane paths changed
                             since REF (benchmark required before the
                             release), 0 otherwise. Deterministic.
  score --report FILE --variant vuln|safe
                             score one lane run's validation report
                             against expectations; write/update the
                             scorecard. Exits 1 below floors.
  scorecard                  print the current scorecard state.

Flow per run: `plan` → deploy vuln fixtures to the disposable cluster →
run /validate-findings against benchmark-findings.json → `score
--variant vuln` → redeploy safe twins → re-run → `score --variant safe`.
Results land in analysis-results/scan-testing/validation-benchmark/
(harness-QA tree — excluded from campaign metrics) and the scorecard
appends to the hash-chained metrics ledger (source
validation-benchmark).
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
from pathlib import Path

from traust_engine import locations


def _benchmark_dir(args) -> Path:
    if args.benchmark_dir:
        return args.benchmark_dir
    configured = locations.benchmark_dir(locations.configured_locations())
    if configured is not None:
        return configured
    raise SystemExit(
        "benchmark dir required: pass --benchmark-dir or set locations.analysis_results"
    )


# Paths whose change requires a benchmark run before release (hybrid
# trigger, decision 2026-07-25). Prefixes are repo-root-relative in the
# mono checkout (traust/…, traust-contracts/…).
TRIGGER_PATHS = (
    "traust/harnessing/5-validate/validate-findings/",
    "traust/harnessing/5-validate/validate-core-ocp/",
    "traust/harnessing/5-validate/validate-browser-finding/",
    "traust/harnessing/5-validate/validate-operator-live/",
    "traust/src/traust/cli/emit_validation_ledger_events.py",
    "traust/src/traust/cli/attest_target.py",
    "traust/src/traust/cli/build_cumulative.py",
)

CONTRACTS_TRIGGER_PATHS = ("schemas/v1/validation.schema.json",)


def load_expected(bench: Path) -> dict:
    return json.loads((bench / "expected.json").read_text(encoding="utf-8"))


def cmd_plan(args, *, results_dir: Path) -> int:
    bench = _benchmark_dir(args)
    exp = load_expected(bench)
    results = results_dir
    results.mkdir(parents=True, exist_ok=True)
    findings = []
    for fx in exp["fixtures"]:
        c = fx["claim"]
        findings.append(
            {
                "id": fx["id"],
                "title": c["title"],
                "severity": c["severity"],
                "cvss_score": c["cvss"],
                "cvss_vector": c["cvss_vector"],
                "cwes": c["cwes"],
                "category": c["category"],
                "description": (
                    f"Validation benchmark fixture {fx['id']} "
                    f"(probe class {fx['probe_class']}). "
                    f"Hints: {fx['controls_hint']}"
                ),
                "locations": [{"path": f"benchmark/fixtures/{fx['vuln_manifest']}"}],
                "validation_status": "not_verified",
            }
        )
    doc = {
        "metadata": {"benchmark": True, "namespace": exp["namespace"], "generated_at": _now()},
        "findings": findings,
    }
    out = results / "benchmark-findings.json"
    out.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"benchmark worklist: {len(findings)} claims → {out}")
    print("\nDeploy (vuln variant):")
    print(f"  oc new-project {exp['namespace']} 2>/dev/null || true")
    for fx in exp["fixtures"]:
        print(f"  oc apply -f {bench}/fixtures/{fx['vuln_manifest']}")
    print(f"\nThen: /validate-findings {out} --namespace {exp['namespace']}")
    print("Then: run_validation_benchmark.py score --report <report> --variant vuln")
    print("Swap each fixture to its .safe.yaml twin and repeat with --variant safe.")
    return 0


def cmd_check_trigger(args) -> int:
    repo = args.repo_root
    if repo is None:
        raise SystemExit("--repo-root required")
    r = subprocess.run(
        ["git", "-C", str(repo), "diff", "--name-only", f"{args.since}..HEAD"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        print(r.stderr.strip(), file=sys.stderr)
        return 2
    hits = sorted({f for f in r.stdout.splitlines() if any(f.startswith(p) for p in TRIGGER_PATHS)})
    if hits:
        print(
            f"validation-lane paths changed since {args.since} — benchmark REQUIRED before release:"
        )
        for h in hits:
            print(f"  {h}")
        return 10
    print(f"no validation-lane changes since {args.since} — benchmark not required")
    return 0


def _score_variant(exp: dict, report: dict, variant: str) -> dict:
    expected_verdict = {fx["id"]: fx["expected"][variant] for fx in exp["fixtures"]}
    claimed_cvss = {fx["id"]: fx["claim"]["cvss"] for fx in exp["fixtures"]}
    rows, hits, sev_ok, sev_n = [], 0, 0, 0
    by_id = {}
    for vf in report.get("validated_findings") or []:
        fid = str(vf.get("source_id") or "").rsplit("/", 1)[-1]
        by_id[fid] = vf
    for fid, want in expected_verdict.items():
        vf = by_id.get(fid)
        got = (vf or {}).get("verdict") or "missing"
        flag = (vf or {}).get("soundness_flag")
        ok = got == want and not flag
        hits += ok
        row = {"fixture": fid, "expected": want, "got": got, "soundness_flag": flag, "ok": ok}
        if variant == "vuln" and got == "confirmed":
            sv = (vf or {}).get("severity_validation") or {}
            est = sv.get("demonstrated_score_estimate")
            if est is not None:
                sev_n += 1
                within = abs(est - claimed_cvss[fid]) <= exp["floors"]["severity_within"]
                sev_ok += within
                row["severity_within_floor"] = within
        rows.append(row)
    n = len(expected_verdict)
    metric = "confirm_recall" if variant == "vuln" else "refute_precision"
    return {
        "variant": variant,
        metric: round(hits / n, 3) if n else None,
        "severity_accuracy": (round(sev_ok / sev_n, 3) if sev_n else None),
        "rows": rows,
        "n": n,
    }


def cmd_score(args, *, results_dir: Path) -> int:
    bench = _benchmark_dir(args)
    exp = load_expected(bench)
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    result = _score_variant(exp, report, args.variant)
    results = results_dir
    results.mkdir(parents=True, exist_ok=True)
    card_path = results / "scorecard.json"
    card = json.loads(card_path.read_text()) if card_path.is_file() else {"runs": []}
    result["scored_at"] = _now()
    result["report"] = str(args.report)
    card["runs"].append(result)
    card_path.write_text(json.dumps(card, indent=1) + "\n")

    metric = "confirm_recall" if args.variant == "vuln" else "refute_precision"
    floor = exp["floors"][metric]
    val = result[metric]
    print(json.dumps(result["rows"], indent=1))
    print(
        f"{metric}: {val} (floor {floor})"
        + (
            f" · severity_accuracy: {result['severity_accuracy']}"
            if result["severity_accuracy"] is not None
            else ""
        )
    )

    # ledger row (best effort)
    payload = json.dumps(
        {
            metric: val,
            "severity_accuracy": result["severity_accuracy"],
            "variant": args.variant,
            "n": result["n"],
        }
    )
    # Best-effort metrics append, gated on the metrics destination being
    # configured (locations.progress_tracker) rather than a WORKSPACE env var.
    if locations.progress_tracker_dir(locations.configured_locations()) is not None:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "traust_engine.metrics.history",
                "append",
                "--source",
                "validation-benchmark",
                "--metrics-json",
                "-",
            ],
            input=payload,
            text=True,
        )
    if val is not None and val < floor:
        print(
            f"BELOW FLOOR — a lane change that drops {metric} under {floor} must not ship",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_scorecard(args, *, results_dir: Path) -> int:
    card_path = results_dir / "scorecard.json"
    if not card_path.is_file():
        print("no benchmark runs recorded yet (plan → deploy → validate → score)")
        return 0
    card = json.loads(card_path.read_text())
    for run in card["runs"][-10:]:
        metric = "confirm_recall" if run["variant"] == "vuln" else "refute_precision"
        print(
            f"{run['scored_at']}  {run['variant']:4s}  "
            f"{metric}={run.get(metric)}  "
            f"severity={run.get('severity_accuracy')}  n={run['n']}"
        )
    return 0


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
