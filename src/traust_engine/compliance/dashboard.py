"""Compliance posture dashboard (Phase 5).

Aggregates every compliance-assessment artifact under
analysis-results/compliance/ (the assessment-output tree of record) into one posture view
per (target, framework) — newest artifact per pair wins — and renders
`metrics/dashboards/compliance/compliance-dashboard.{json,md}` with the
campaign's reporting discipline intact:

  - **population block** (corpus.py — never a hand-rolled denominator):
    what the corpus is, and how many of its targets have any compliance
    assessment at all ("compliance-assessed" coverage — the census-cut
    line, computed on census's own resolver)
  - **coverage honesty**: per-framework tables carry the transparency
    rows (not_assessed, out-of-scope, skipped-with-reason) verbatim;
    there is NO blended compliance percentage anywhere
  - **per-team not_satisfied table** where attributable: findings
    cross-filed with `control_refs` join to owner teams through
    findings.db + the repo-graph owned-by edges; environment-target
    results without a repo owner report "(unattributed — environment
    target)" rather than a guess
  - **trend**: each run appends a summary snapshot to
    compliance-history.jsonl; the trend section renders once >=2
    snapshots exist (never from a single point)

Usage:
    traust compliance dashboard
        [--assessments <dir>] [--out-dir <dir>]
        [--findings-db <db>] [--results-root <analysis-results>]
"""

from __future__ import annotations

import datetime
import json
import sqlite3
from pathlib import Path

from traust_contracts import CorpusConfig


def _progress_tracker(progress_tracker: Path | None = None) -> Path | None:
    return progress_tracker


def collect_assessments(root: Path) -> list[dict]:
    from traust_contracts.models import ComplianceAssessment

    docs = []
    for p in sorted(root.rglob("*compliance-assessment.json")) if root.is_dir() else []:
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if (raw.get("metadata") or {}).get("artifact") != "compliance-assessment":
            continue
        doc = ComplianceAssessment.from_dict(raw).to_dict()
        skipped = (raw.get("metadata") or {}).get("skipped_frameworks")
        if skipped:
            doc["metadata"]["skipped_frameworks"] = skipped
        doc["_path"] = str(p)
        docs.append(doc)
    return docs


def _tid(d: dict) -> str:
    t = d["metadata"].get("target") or {}
    return t.get("environment") or t.get("product") or ",".join(t.get("repos") or []) or "(unnamed)"


def latest_per_target_framework(docs: list[dict]) -> dict[tuple, dict]:
    """(target-id, framework) -> newest assessment covering it.
    Per-framework selection so a newer single-framework run (e.g.
    SOC 2 only) NEVER hides older coverage of other frameworks for the
    same target — each framework row shows its own newest assessment,
    dated."""
    sel: dict[tuple, dict] = {}
    for d in docs:
        tid = _tid(d)
        fws = set(d.get("coverage") or {}) | set(d["metadata"].get("skipped_frameworks") or {})
        for fw in fws:
            cur = sel.get((tid, fw))
            if cur is None or d["metadata"].get("generated_at", "") > cur["metadata"].get(
                "generated_at", ""
            ):
                sel[(tid, fw)] = d
    return sel


def population_block(results_root: Path, cfg: CorpusConfig) -> list[str]:
    try:
        from traust_engine.corpus import resolver as corpus

        res = corpus.resolve(results_root, cfg)
        block = corpus.render_population_block(
            res,
            tool="build_compliance_dashboard.py",
            unit="assessment targets (products/environments)",
            filters=(
                "newest assessment artifact per target; skipped "
                "frameworks shown with reasons, never dropped"
            ),
            denominator=(
                "corpus resolver (census authority); "
                "compliance-assessed targets are the cut, "
                "corpus repos are the base"
            ),
        )
        return block.splitlines()[2:]  # our md supplies the heading
    except Exception as e:
        return [f"_population block unavailable: {e}_"]  # say so loudly


def team_table(findings_db: Path) -> list[tuple[str, int, int]]:
    """(team, open control_refs findings, distinct controls) via
    findings.db + owned-by edges."""
    if not findings_db.is_file():
        return []
    con = sqlite3.connect(findings_db)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT f.control_refs, COALESCE("
            "  (SELECT REPLACE(ge.from_id,'owner-team:','') "
            "   FROM graph_edges ge WHERE ge.rel='owned-by' AND "
            "   ge.to_id='repo:'||REPLACE(REPLACE("
            "     COALESCE(r.repo_url,''),'https://',''),'.git','')"
            "   LIMIT 1), '(unassigned)') AS team "
            "FROM v_open f JOIN repos r USING (repo_key) "
            "WHERE f.control_refs IS NOT NULL"
        ).fetchall()
    except sqlite3.OperationalError:
        con.close()
        return []
    con.close()
    agg: dict[str, dict] = {}
    for r in rows:
        t = agg.setdefault(r["team"], {"n": 0, "controls": set()})
        t["n"] += 1
        for ref in json.loads(r["control_refs"]):
            t["controls"].add(ref)
    return sorted(
        ((team, v["n"], len(v["controls"])) for team, v in agg.items()),
        key=lambda x: -x[1],
    )


def boundary_coverage(
    scope_path: Path, graph_path: Path, findings_db: Path, docs: list[dict]
) -> list[dict]:
    """Per-boundary in-scope coverage (Phase 6) — the auditor's
    question: of the repos DECLARED in scope, which have assessment
    evidence at all? Three cuts per boundary: resolved size, repos with
    findings-db presence (findings evidence exists), and the newest
    assessment run that cited this boundary. Resolution failures are
    reported as rows, never silently dropped."""
    if not scope_path or not scope_path.is_file():
        return []
    from traust_engine.compliance.scope import ScopeError, load_scope, resolve

    try:
        scope_doc = load_scope(scope_path)
    except ScopeError as e:
        return [{"boundary": "(registry unreadable)", "error": str(e)}]

    # newest assessment per boundary id
    newest: dict[str, str] = {}
    for d in docs:
        sc = ((d.get("metadata") or {}).get("target") or {}).get("scope")
        if sc and sc.get("boundary"):
            gen = (d.get("metadata") or {}).get("generated_at", "")
            if gen > newest.get(sc["boundary"], ""):
                newest[sc["boundary"]] = gen

    evidence_urls: set[str] = set()
    if findings_db.is_file():
        try:
            con = sqlite3.connect(f"file:{findings_db}?mode=ro", uri=True)
            evidence_urls = {
                (r[0] or "").lower().rstrip("/")
                for r in con.execute("SELECT DISTINCT repo_url FROM repos")
            }
            con.close()
        except sqlite3.Error:
            pass

    rows = []
    for bid in sorted(scope_doc.get("boundaries") or {}):
        try:
            res = resolve(scope_doc, bid, graph_path)
        except ScopeError as e:
            rows.append({"boundary": bid, "error": str(e)})
            continue
        with_evidence = sum(
            1
            for r in res["repos"]
            if any(u.endswith(f"github.com/{r}".lower()) for u in evidence_urls)
        )
        rows.append(
            {
                "boundary": bid,
                "frameworks": res["frameworks"],
                "draft": res["draft"],
                "declared_by": res["declared_by"],
                "declared_at": res["declared_at"],
                "in_scope_repos": len(res["repos"]),
                "with_findings_evidence": with_evidence,
                "excluded": len(res["excluded"]),
                "last_assessed": newest.get(bid),
            }
        )
    return rows


def build(
    assessments_dir: Path,
    findings_db: Path,
    results_root: Path,
    cfg: CorpusConfig,
    scope_path: Path | None = None,
    graph_path: Path | None = None,
    progress_tracker: Path | None = None,
) -> dict:
    docs = collect_assessments(assessments_dir)
    sel = latest_per_target_framework(docs)
    by_tid: dict[str, dict] = {}
    for (tid, fw), d in sorted(sel.items()):
        m = d["metadata"]
        entry = by_tid.setdefault(
            tid,
            {
                "target": tid,
                "kind": (m.get("target") or {}).get("kind"),
                "generated_at": "",
                "harness_version": m.get("harness_version"),
                "registry_hash": (m.get("registry_hash") or "")[:12],
                "snapshot_id": ((m.get("target") or {}).get("snapshot_id") or "")[:12],
                "frameworks": {},
                "skipped_frameworks": {},
                "coverage": {},
                "assessed_at": {},
                "not_satisfied": [],
            },
        )
        gen = m.get("generated_at", "")
        if gen > entry["generated_at"]:
            entry.update(
                generated_at=gen,
                harness_version=m.get("harness_version"),
                registry_hash=(m.get("registry_hash") or "")[:12],
                snapshot_id=((m.get("target") or {}).get("snapshot_id") or "")[:12],
            )
        if fw in (d.get("coverage") or {}):
            entry["coverage"][fw] = d["coverage"][fw]
            entry["assessed_at"][fw] = gen
            for f in m.get("frameworks") or []:
                if f["id"] == fw and f.get("caveat"):
                    entry["frameworks"][fw] = {"caveat": f["caveat"]}
            entry["not_satisfied"].extend(
                {
                    "framework": r["framework"],
                    "control_id": r["control_id"],
                    "check_id": r.get("check_id"),
                    "evidence_items": len(r.get("evidence") or []),
                }
                for r in d.get("results") or []
                if r.get("verdict") == "not_satisfied" and r.get("framework") == fw
            )
        elif fw in (m.get("skipped_frameworks") or {}):
            entry["skipped_frameworks"][fw] = m["skipped_frameworks"][fw]
    # one winner per (target, framework), so covered-vs-skipped is
    # already the newest state — no reconciliation needed here
    targets = [by_tid[k] for k in sorted(by_tid)]
    return {
        "metadata": {
            "artifact": "compliance-dashboard",
            "role": (
                "posture aggregation — per-framework coverage with "
                "transparency rows; no blended compliance "
                "percentage exists; census remains the denominator "
                "authority"
            ),
            "assessments_found": len(docs),
            "targets": len(by_tid),
            "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "population_block": population_block(results_root, cfg),
        "compliance_assessed": {
            "targets_with_assessments": len(by_tid),
            "note": (
                "census-cut line: corpus denominators in the "
                "population block above; a target counts once "
                "regardless of framework count"
            ),
        },
        "targets": targets,
        "boundary_coverage": boundary_coverage(
            scope_path
            or (
                _progress_tracker(progress_tracker)
                / "configs"
                / "compliance"
                / "compliance-scope.yaml"
                if _progress_tracker(progress_tracker)
                else None
            ),
            graph_path,
            findings_db,
            docs,
        ),
        "team_table": [
            {"team": t, "open_findings": n, "distinct_controls": c}
            for t, n, c in team_table(findings_db)
        ],
    }


def render_md(doc: dict, history: list[dict]) -> str:
    L = ["# Compliance Posture Dashboard", ""]
    A = L.append
    m = doc["metadata"]
    A(
        f"_Generated {m['generated_at']} · {m['targets']} target(s) from "
        f"{m['assessments_found']} assessment artifact(s). Per-framework "
        f"numbers are never blended; the census remains the denominator "
        f"authority._"
    )
    A("")
    A("## Population")
    A("")
    L.extend(doc["population_block"])
    A("")
    A(
        f"**Compliance-assessed targets:** "
        f"{doc['compliance_assessed']['targets_with_assessments']} — "
        + doc["compliance_assessed"]["note"]
    )
    A("")
    for t in doc["targets"]:
        A(f"## Target: {t['target']} ({t['kind']})")
        A("")
        A(
            f"_Assessed {t['generated_at']} · harness "
            f"{t['harness_version']} · registry {t['registry_hash']}… · "
            f"snapshot {t['snapshot_id']}…_"
        )
        A("")
        A(
            "| Framework | Assessed | In scope | Satisfied | "
            "Not satisfied | Not applicable | Not assessed |"
        )
        A("|---|---|---:|---:|---:|---:|---:|")
        for fw, cov in sorted(t["coverage"].items()):
            when = (t.get("assessed_at", {}).get(fw) or "")[:10]
            A(
                f"| {fw} | {when} | {cov['total_in_scope']} | "
                f"{cov['satisfied']} | **{cov['not_satisfied']}** | "
                f"{cov['not_applicable']} | {cov['not_assessed']} |"
            )
        for fw, reason in sorted(t["skipped_frameworks"].items()):
            A(f"| {fw} | — | — | — | — | — | _{reason}_ |")
        A("")
        caveats = {fw: v["caveat"] for fw, v in t["frameworks"].items() if v.get("caveat")}
        for fw, c in sorted(caveats.items()):
            A(f"- **{fw} caveat:** {c}")
        if t["not_satisfied"]:
            A("")
            A("**Not satisfied:**")
            for r in t["not_satisfied"]:
                A(
                    f"- `{r['framework']}:{r['control_id']}` via "
                    f"`{r['check_id']}` ({r['evidence_items']} evidence "
                    f"item(s))"
                )
        A("")
    bc = doc.get("boundary_coverage") or []
    if bc:
        A("## Declared boundaries — in-scope coverage (scope registry)")
        A("")
        A(
            "_The auditor's cut: of the repos DECLARED in each compliance "
            "boundary, how many have findings evidence, and when was the "
            "boundary last assessed. DRAFT = unsigned declaration._"
        )
        A("")
        A(
            "| Boundary | Frameworks | In-scope repos | With findings "
            "evidence | Excluded | Last assessed | Declared |"
        )
        A("|---|---|---:|---:|---:|---|---|")
        for b in bc:
            if b.get("error"):
                A(f"| {b['boundary']} | — | — | — | — | — | RESOLUTION FAILED: {b['error'][:80]} |")
                continue
            draft = " **DRAFT**" if b["draft"] else ""
            A(
                f"| {b['boundary']}{draft} | "
                f"{', '.join(b['frameworks'])} | {b['in_scope_repos']} | "
                f"{b['with_findings_evidence']} | {b['excluded']} | "
                f"{b.get('last_assessed') or 'never'} | "
                f"{b['declared_by']} {b['declared_at']} |"
            )
        A("")
    A("## Per-team open control-linked findings")
    A("")
    if doc["team_table"]:
        A("| Team | Open findings with control_refs | Distinct controls |")
        A("|---|---:|---:|")
        for row in doc["team_table"]:
            A(f"| {row['team']} | {row['open_findings']} | {row['distinct_controls']} |")
    else:
        A(
            "_None yet — populated as not_satisfied controls cross-file "
            "findings with `control_refs` (environment-target results "
            "without a repo owner stay unattributed rather than "
            "guessed)._"
        )
    A("")
    A("## Trend")
    A("")
    if len(history) >= 2:
        A("| Run | Targets | Not satisfied (total) | Not assessed (total) |")
        A("|---|---:|---:|---:|")
        for h in history[-6:]:
            A(
                f"| {h['generated_at'][:10]} | {h['targets']} | "
                f"{h['not_satisfied_total']} | {h['not_assessed_total']} |"
            )
    else:
        A(
            "_Trend renders once ≥2 snapshots exist "
            f"({len(history)} so far) — never from a single point._"
        )
    A("")
    return "\n".join(L) + "\n"
