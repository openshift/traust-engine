"""Deterministic disposition merge engine.

Replays a findings-disposition layer (layer.schema.json) over its
security-audit report (report.schema.json) and derives the two-axis
disposition state (validity x resolution) for each finding.

Merge rules (keep in sync with skills/track-findings/SKILL.md):
  validity   — EVIDENCE-CLASS precedence (harness >= 0.27.0): class 1
               execution-verified sources (validation_report,
               verification_report) > class 2 human static determinations >
               class 3 machine static (triage_report and other machine
               events). Latest wins within the deciding class. A machine
               false_positive NEVER sets validity on its own — it raises
               refuted_awaiting_signoff until a verified human
               countersigns — EXCEPT auto_accept_tier events (unanimous,
               lint-clean, high-confidence, low/informational-claimed
               triage FPs), which may set validity directly.
               A class-1 'confirmed' overrides any human false_positive
               (fp_overridden — loud, attributed). After execution-verified
               confirmation, re-asserting false_positive requires TWO
               distinct verified humans post-dating the proof
               (two-person rule; a single attempt sets
               fp_reassertion_blocked).
  assurance  — highest evidence class that has spoken on validity:
               execution_proven > human_reviewed > machine_verified >
               claimed.
  resolution — verification_report events > jira events > everything else;
               latest wins within the highest populated tier.
  conflict   — both 'confirmed' and 'false_positive' appear anywhere in the
               finding's events. Surfaced, never silently resolved.
"""

from __future__ import annotations

import json
import sys

from traust_contracts.v1.enums import DispositionResolution, Validity

from traust_engine.ledger import compute_claim_hash, derive_disposition

RESOLUTION_KEYS = [e.value for e in DispositionResolution]
VALIDITY_KEYS = [e.value for e in Validity]


def verify_claim_hashes(audit, layer):
    """Refuse to build from a tampered baseline.

    Returns (errors, warnings): errors are silent in-place edits or deleted
    baselined findings; 'corrected' drift and not-yet-baselined appends are
    warnings (the cumulative build proceeds, the next `baseline_claims.py
    record` pins them)."""
    hashes = (layer.get("metadata") or {}).get("claim_hashes") or {}
    if not hashes:
        return [], []
    findings = {f.get("id"): f for f in audit.get("findings", [])}
    errors, warnings = [], []
    for fid, recorded in sorted(hashes.items()):
        f = findings.get(fid)
        if f is None:
            errors.append(f"{fid}: baselined finding missing from the audit report")
        elif compute_claim_hash(f) != recorded:
            if f.get("validation_status") == "corrected":
                warnings.append(f"{fid}: 'corrected' claim drift — re-baseline it")
            else:
                errors.append(f"{fid}: claim hash mismatch — edited in place")
    unbaselined = sorted(set(findings) - set(hashes))
    if unbaselined:
        warnings.append(f"{len(unbaselined)} finding(s) not yet baselined")
    return errors, warnings


def build_cumulative(audit, layer, layer_ref, generated_at):
    """Return the cumulative report dict, or raise ValueError on bad refs."""
    findings = {f["id"]: f for f in audit.get("findings", [])}

    raw_aliases = (layer.get("metadata") or {}).get("finding_aliases") or {}

    ns_aliases = {}
    for k, v in raw_aliases.items():
        if ":" in k:
            ns_aliases.setdefault(k.split(":", 1)[1], []).append(v)

    def _alias_for(ref):
        a = raw_aliases.get(ref)
        if a is not None:
            return a
        cands = ns_aliases.get(ref) or []
        return cands[0] if len(cands) == 1 else None

    def _has_alias(ref):
        return ref in raw_aliases or ref in ns_aliases

    queued_unmatched = {
        i.get("suggested_finding_ref")
        for i in layer.get("needs_review", [])
        if i.get("queue_reason") == "rebaseline_unmatched" and i.get("status") == "pending"
    }

    def resolve(ref, _seen=None):
        _seen = _seen or set()
        a = _alias_for(ref)
        if not a or not a.get("confirmed") or ref in _seen:
            return ref
        _seen.add(ref)
        return resolve(a["new_id"], _seen)

    by_finding = {}
    unknown = []
    parked = []
    for e in layer.get("events", []):
        ref = resolve(e["finding_ref"])
        if ref not in findings:
            if (
                _has_alias(e["finding_ref"])
                or _has_alias(ref)
                or e["finding_ref"] in queued_unmatched
            ):
                parked.append(ref)
                continue
            unknown.append(ref)
        by_finding.setdefault(ref, []).append(e)
    if unknown:
        raise ValueError(
            "layer references finding IDs not in the audit report: "
            + ", ".join(sorted(set(unknown)))
        )
    if parked:
        print(
            f"WARN: {len(set(parked))} superseded finding id(s) have "
            f"unconfirmed or unmatched rebaseline dispositions — their "
            f"events are parked until the mapping is confirmed or closed "
            f"via countersign/needs_review",
            file=sys.stderr,
        )

    report = json.loads(json.dumps(audit))
    for f in report.get("findings", []):
        disp = derive_disposition(f, by_finding.get(f["id"], []), generated_at)
        f["disposition"] = disp
        f["validation_status"] = disp["validity"]
        ov = disp.get("severity_override")
        f["effective_severity"] = ov["severity"] if ov else f.get("severity")

    all_disp = [f["disposition"] for f in report.get("findings", [])]
    pending = [i for i in layer.get("needs_review", []) if i.get("status") == "pending"]
    report["disposition_summary"] = {
        "layer_ref": layer_ref,
        "generated_at": generated_at,
        "by_resolution": {
            k: sum(1 for d in all_disp if d["resolution"] == k) for k in RESOLUTION_KEYS
        },
        "by_validity": {k: sum(1 for d in all_disp if d["validity"] == k) for k in VALIDITY_KEYS},
        "severity_overrides": [
            {"finding": f["id"], "from": f.get("severity"), **f["disposition"]["severity_override"]}
            for f in report.get("findings", [])
            if f["disposition"].get("severity_override")
        ],
        "conflicts": [
            f["id"] for f in report.get("findings", []) if f["disposition"].get("conflict")
        ],
        "needs_review_count": len(pending),
    }

    if not report["title"].endswith("— Cumulative Findings Status"):
        report["title"] = report["title"] + " — Cumulative Findings Status"
    meta = report.setdefault("metadata", {})
    additional = meta.setdefault("additional", {})
    additional["cumulative"] = {
        "source_audit": layer["metadata"]["audit_report"],
        "layer": layer_ref,
        "original_report_date": meta.get("date"),
        "generated_at": generated_at,
    }
    meta["date"] = generated_at[:10]
    return report


VALIDITY_LABEL = {
    "confirmed": "✅ confirmed",
    "corrected": "✏️ corrected",
    "false_positive": "🚫 false positive",
    "not_verified": "⬜ not verified",
    "hardening": "🛡️ hardening",
}
RESOLUTION_LABEL = {
    "open": "❌ open",
    "fix_in_progress": "🔧 fix in progress",
    "resolved": "✅ resolved",
    "partially_resolved": "⚠️ partially resolved",
    "risk_accepted": "📋 risk accepted",
    "regression_introduced": "🆕 regression introduced",
}


def render_markdown(report, layer):
    """Render the cumulative report to Markdown."""
    meta = report["metadata"]
    ds = report["disposition_summary"]
    cumulative = meta.get("additional", {}).get("cumulative", {})
    lines = []
    add = lines.append

    add(f"# {report['title']}")
    add("")
    add("| Field | Value |")
    add("|-------|-------|")
    add(f"| **Generated** | {ds['generated_at']} |")
    add(
        f"| **Original Report** | {cumulative.get('source_audit', '?')} "
        f"({cumulative.get('original_report_date', '?')}) |"
    )
    add(f"| **Disposition Layer** | {ds['layer_ref']} |")
    if meta.get("repository"):
        add(f"| **Repository** | {meta['repository']} |")
    if meta.get("commit"):
        add(f"| **Audited Commit** | `{meta['commit']}` |")
    add("")

    add("## Disposition Summary")
    add("")
    add("| Resolution | Count | | Validity | Count |")
    add("|---|---|---|---|---|")
    rows = max(len(RESOLUTION_KEYS), len(VALIDITY_KEYS))
    for i in range(rows):
        rk = RESOLUTION_KEYS[i] if i < len(RESOLUTION_KEYS) else None
        vk = VALIDITY_KEYS[i] if i < len(VALIDITY_KEYS) else None
        left = f"{RESOLUTION_LABEL[rk]} | {ds['by_resolution'][rk]}" if rk else " | "
        right = f"{VALIDITY_LABEL[vk]} | {ds['by_validity'][vk]}" if vk else " | "
        add(f"| {left} | | {right} |")
    add("")

    if ds.get("severity_overrides"):
        add("## Severity overrides (human, verified)")
        add("")
        add(
            "Original severities are preserved on each finding; the "
            "effective severity below is what current prioritization "
            "should use."
        )
        add("")
        add("| Finding | Original | Effective | By | When |")
        add("|---|---|---|---|---|")
        for ov in ds["severity_overrides"]:
            add(
                f"| `{ov['finding']}` | {ov.get('from', '?')} | "
                f"**{ov['severity']}** | {ov['by']} | {ov['at'][:10]} |"
            )
        add("")

    if ds.get("conflicts"):
        add("## ⚠️ Conflicts — needs human re-review")
        add("")
        add(
            "These findings carry both 'confirmed' and 'false positive' "
            "determinations. The ledger keeps both; a human must adjudicate."
        )
        add("")
        for fid in ds["conflicts"]:
            add(f"- `{fid}`")
        add("")

    awaiting = [
        f for f in report.get("findings", []) if f["disposition"].get("refuted_awaiting_signoff")
    ]
    if awaiting:
        add("## ⏳ Refuted by machine validation — awaiting human sign-off")
        add("")
        add(
            "Machine evidence refuted these findings, but a false-positive "
            "determination requires a verified human countersignature. "
            "Build the decision-card inbox with the harness countersign CLI "
            "(or run the track-findings workflow interactively)."
        )
        add("")
        for f in awaiting:
            add(f"- `{f['id']}` — {f['title']}")
        add("")

    overridden = [f for f in report.get("findings", []) if f["disposition"].get("fp_overridden")]
    if overridden:
        add("## ⚡ False-positive assertions overridden by execution evidence")
        add("")
        add(
            "A reproducing exploit/crash confirmed these findings over a "
            "prior human false-positive determination. Both events remain "
            "in the ledger with attribution. Re-asserting false positive "
            "now requires two independent verified humans "
            "(two-person rule)."
        )
        add("")
        for f in overridden:
            add(f"- `{f['id']}` — {f['title']}")
        add("")

    blocked = [
        f for f in report.get("findings", []) if f["disposition"].get("fp_reassertion_blocked")
    ]
    if blocked:
        add("## 🔒 FP re-assertion blocked (two-person rule)")
        add("")
        add(
            "A single human re-asserted false positive against an "
            "execution-verified confirmation. A second independent "
            "verified human must concur before validity changes."
        )
        add("")
        for f in blocked:
            add(f"- `{f['id']}` — {f['title']}")
        add("")

    pending = [i for i in layer.get("needs_review", []) if i.get("status") == "pending"]
    if pending:
        add(f"## 📋 Needs review — {len(pending)} pending statement(s)")
        add("")
        for item in pending:
            add(f"- **{item['author']}** at {item['source_ref']}:")
            quote = item.get("quote") or item.get("note") or "(no statement text)"
            add(f"  > {quote}")
            if item.get("suggested_finding_ref"):
                sugg = item.get("suggested_disposition") or {}
                axis = sugg.get("validity") or sugg.get("resolution") or "?"
                add(
                    f"  - suggested: `{item['suggested_finding_ref']}` → {axis} "
                    f"({item.get('queue_reason', 'unclassified')})"
                )
        add("")

    add("## Findings")
    add("")
    add("| ID | Severity | Title | Validity | Resolution | Last Updated |")
    add("|---|---|---|---|---|---|")
    for f in report.get("findings", []):
        d = f["disposition"]
        add(
            f"| `{f['id']}` | {f['severity']} | {f['title']} "
            f"| {VALIDITY_LABEL[d['validity']]} "
            f"| {RESOLUTION_LABEL[d['resolution']]} "
            f"| {d['last_updated'][:10]} |"
        )
    add("")

    events_by_id = {e["event_id"]: e for e in layer.get("events", [])}
    detailed = [f for f in report.get("findings", []) if f["disposition"]["events"]]
    if detailed:
        add("## Event History")
        add("")
        for f in detailed:
            add(f"### {f['id']}: {f['title']}")
            add("")
            for eid in f["disposition"]["events"]:
                e = events_by_id[eid]
                actor = e["source"]["actor"]
                who = actor.get("display_name") or actor.get("identity") or actor["kind"]
                disp = e["disposition"]
                axis = ", ".join(f"{k}: {v}" for k, v in disp.items())
                add(f"- **{e['recorded_at'][:10]}** — [{e['source']['type']}] {who} → {axis}")
                add(f"  > {e['rationale']}")
                add(f"  - source: {e['source']['ref']}")
            add("")

    add("---")
    add(
        "*Generated by the track-findings skill. The disposition layer is "
        "append-only; corrections are new events, never edits.*"
    )
    add("")
    return "\n".join(lines)
