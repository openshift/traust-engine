"""Central append-only campaign metrics ledger, shared by every dashboard.

This module used to be called "ledger" but it really isn't the ledger. Due to that confusion
renamed to history since its an additional tamper-evidence history tracker.

One JSONL file — `metrics/metrics-history.jsonl` — holds one
immutable row per dashboard snapshot, namespaced by `source` (the dashboard
slug). Rows are hash-chained for tamper evidence:

    row_sha  = sha256(canonical-json of the row minus row_sha)
    prev_sha = row_sha of the previous row in the file ("" for genesis)

`verify` recomputes every hash and walks the chain, so any edit, deletion, or
reordering of a committed row is detectable (git history provides the second,
independent record). Rows are NEVER revised: methodology changes appear as new
snapshots with a `note`, keeping every as-reported number forever.

The journal location is config-owned (locations.progress_tracker); no function
takes a workspace — the operator dictates where it lives.

Library API (dashboards import this module):
    previous(source)              -> latest row for a source, or None
    append(source, metrics, note="", hv=None) -> row
    rows()                        -> all rows
    series(source, key)           -> [(date, value), ...]
    trend_line(cur, prev_row, keys) -> "Δ vs <prior-date>: findings 1,234 (↓ 56) · ..."
    verify()                      -> (ok: bool, issues: [str])

CLI:
    python3 -m traust_engine.metrics.history append \\
        --source SLUG --metrics-json FILE|- [--note TEXT]
    python3 -m traust_engine.metrics.history latest --source SLUG
    python3 -m traust_engine.metrics.history verify
    python3 -m traust_engine.metrics.history render-exec

`render-exec` writes the executive trends dashboard
(`metrics/Executive-Trends.{md,html}`) — the
leadership-facing view of every tracked series.
"""

import datetime
import hashlib
import json
from pathlib import Path

from traust_contracts import DeploymentConfigMissing

from traust_engine.assets import harness_version as _engine_version

try:
    from traust_contracts.models import MetricsRecord

    HAS_CONTRACTS = True
except ImportError:
    HAS_CONTRACTS = False


# Metric key -> human label, per source. Drives the executive dashboard and
# each dashboard's trend line; unknown keys still land in the ledger.
KEY_LABELS = {
    "repos_audited": "Reports (repos/branches audited)",
    "unique_repos": "Unique repositories",
    "findings_total": "Findings",
    "sev_critical": "Critical",
    "sev_high": "High",
    "unique_critical": "Unique Critical",
    "unique_high": "Unique High",
    "repos_with_critical": "Repos with >=1 Critical",
    "repos_with_high": "Repos with >=1 High",
    "credential_findings": "Credential findings (unique)",
    "hardening_backlog": "Hardening backlog",
    "dispositioned_repos": "Repos with disposition ledger",
    "ledger_coverage_pct": "Ledger coverage %",
    "resolved_findings": "Findings resolved",
    "open_ledger_view": "Open findings (ledger replay)",
    "mean_cvss_open": "Mean CVSS of open findings (0-10 — legacy)",
    "owasp_risk_critical": "OWASP risk rating: Critical (open)",
    "owasp_risk_high": "OWASP risk rating: High (open)",
    "owasp_risk_medium": "OWASP risk rating: Medium (open)",
    "owasp_risk_low": "OWASP risk rating: Low/Note (open)",
    "owasp_risk_high_plus_pct": "OWASP High+Critical share of open (%)",
    "risk_index": "Risk index (CVSS sum over open — unnormalized, legacy)",
    "risk_index_combined": "Combined risk index (CVSS sum + hardening — unnormalized, legacy)",
    "hardening_risk_index": "Hardening risk index (lambda-weighted CVSS sum — legacy)",
    "confirmed_exploitable": "Confirmed exploitable (live)",
    "refuted": "False positives refuted (live)",
    "validation_reports": "Live-validation reports",
    "checks_attempted": "Finding-checks attempted",
    "fuzz_bugs": "Fuzz-confirmed bugs",
    "threat_models": "Threat models",
    "threats_open": "Open threats",
    "team_packages": "Team packages delivered",
    "jira_tickets": "Jira defects filed",
    "total_loc": "Lines of code scanned",
    "repos_with_loc": "Repos with LoC data",
    "languages": "Languages",
    "code_findings": "Source-code findings (patterns)",
    "distinct_cwes": "Distinct CWEs",
    "pattern_repos": "Repos with >=1 pattern",
    "chains_confirmed": "Attack chains with confirmed step",
    "threats_unmitigated": "Unmitigated threats",
    "threats_partial": "Partially mitigated threats",
    "quick_wins": "Threat quick wins available",
    "pqc_repos_assessed": "PQC repos assessed (Phase 1 sweep)",
    "pqc_sweep_coverage_pct": "PQC sweep coverage %",
    "pqc_ready": "PQC ready (repos)",
    "pqc_partial": "PQC partial (repos)",
    "pqc_not_ready": "PQC not-ready (repos)",
    "pqc_clock_items": "PQC 2030/2035 clock items (burndown)",
    "pqc_hndl_repos": "PQC HNDL-priority repos",
    "pqc_tagged_findings": "PQC-tagged findings (general audits)",
    "pqc_regressions": "PQC regressions (verify-remediation)",
    "pqc_2030_clock_items": "PQC 2030-clock items (urgent burndown)",
    "pqc_hybrid_blockers": "PQC hybrid-TLS group/KEX blockers (burndown)",
    "pqc_toolchain_quickwins": "PQC go-directive quick wins (burndown)",
    "attack_techniques_covered": "ATT&CK techniques covered (any evidence)",
    "attack_techniques_observed": "ATT&CK techniques observed (confirmed chains)",
    "attack_techniques_modeled": "ATT&CK techniques modeled (threat models)",
    "attack_tactics_covered": "ATT&CK tactics covered",
}

# Metrics where DOWN is good (risk/exposure); everything else up-is-good or
# neutral. Used only for coloring/labeling, never for the numbers themselves.
DOWN_IS_GOOD = {
    "findings_total",
    "sev_critical",
    "sev_high",
    "unique_critical",
    "unique_high",
    "repos_with_critical",
    "repos_with_high",
    "credential_findings",
    "open_ledger_view",
    "mean_cvss_open",
    "risk_index",
    "risk_index_combined",
    "hardening_risk_index",
    "threats_open",
    "owasp_risk_critical",
    "owasp_risk_high",
    "owasp_risk_medium",
    "owasp_risk_low",
    "owasp_risk_high_plus_pct",
    "pqc_not_ready",
    "pqc_clock_items",
    "pqc_hndl_repos",
    "pqc_regressions",
    "pqc_2030_clock_items",
    "pqc_hybrid_blockers",
    "pqc_toolchain_quickwins",
    "hardening_backlog",
    "code_findings",
    "threats_unmitigated",
    "threats_partial",
}


def ledger_path(journal: Path | None = None) -> Path:
    """The metrics-history journal path.

    An injected ``journal`` (passed by HarnessEngine from the loaded context)
    wins; otherwise it resolves from the config-owned metrics journal root. The
    operator dictates where this lives — never a workspace-relative assumption.
    """
    if journal is None:
        raise DeploymentConfigMissing(
            "metrics-history journal not provided — load via HarnessEngine.metrics "
            "(the journal is resolved from the injected context, not the environment)."
        )
    return journal


def _canonical(row: dict) -> str:
    return json.dumps(
        {k: v for k, v in row.items() if k != "row_sha"}, sort_keys=True, separators=(",", ":")
    )


def _sha(row: dict) -> str:
    return hashlib.sha256(_canonical(row).encode("utf-8")).hexdigest()


def rows(journal: Path | None = None) -> list[dict]:
    p = ledger_path(journal)
    out = []
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def previous(source: str, before: str | None = None, journal: Path | None = None) -> dict | None:
    """Latest row for a source (optionally strictly before an ISO timestamp)."""
    cand = [
        r
        for r in rows(journal)
        if r.get("source") == source and (before is None or r.get("snapshot_at", "") < before)
    ]
    return cand[-1] if cand else None


def series(source: str, key: str, journal: Path | None = None) -> list[tuple[str, object]]:
    return [
        (r["snapshot_at"][:10], r["metrics"].get(key))
        for r in rows(journal)
        if r.get("source") == source and r.get("metrics", {}).get(key) is not None
    ]


METRICS_SOURCE = "traust-engine-metrics"


def append(
    source: str,
    metrics: dict,
    note: str = "",
    hv: str | None = None,
    journal: Path | None = None,
) -> dict:
    """Append one immutable, hash-chained snapshot row."""
    existing = rows(journal)
    prev_sha = existing[-1].get("row_sha", "") if existing else ""
    row = {
        "snapshot_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "source": source,
        "harness_version": hv or _engine_version(),
        "note": note or "",
        "metrics": {k: v for k, v in metrics.items() if v is not None},
        "prev_sha": prev_sha,
    }
    row["row_sha"] = _sha(row)
    p = ledger_path(journal)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    return row


def append_if_changed(
    source: str,
    metrics: dict,
    note: str = "",
    hv: str | None = None,
    journal: Path | None = None,
) -> dict | None:
    """Append only when the metrics differ from the source's previous row
    (or a note is supplied). Dashboards rebuild frequently and often
    idempotently — identical re-runs must not spam the ledger."""
    prev = previous(source, journal=journal)
    clean = {k: v for k, v in metrics.items() if v is not None}
    if prev and not note and prev.get("metrics") == clean:
        return None
    return append(source, clean, note=note, hv=hv, journal=journal)


def verify(journal: Path | None = None) -> tuple[bool, list[str]]:
    """Recompute every row hash and walk the chain."""
    issues = []
    prev = ""
    for i, r in enumerate(rows(journal), 1):
        if "row_sha" not in r:
            issues.append(f"row {i}: missing row_sha (pre-chain legacy row)")
            prev = r.get("row_sha", "")
            continue
        if _sha(r) != r["row_sha"]:
            issues.append(
                f"row {i} ({r.get('snapshot_at')}, "
                f"{r.get('source')}): row_sha mismatch — row was "
                f"altered after being written"
            )
        if r.get("prev_sha", "") != prev:
            issues.append(
                f"row {i} ({r.get('snapshot_at')}, "
                f"{r.get('source')}): chain break — prev_sha does "
                f"not match preceding row (insertion/deletion/"
                f"reordering)"
            )
        prev = r["row_sha"]
    return (not issues), issues


# ---------------------------------------------------------------------------
# trend rendering helpers (used by the dashboards)
# ---------------------------------------------------------------------------


def _fmt(v):
    if isinstance(v, int):
        return f"{v:,}"
    if isinstance(v, float):
        return f"{v:,.1f}"
    return str(v)


def _to_num(v):
    try:
        return float(str(v).replace(",", ""))
    except (TypeError, ValueError):
        return None


def delta(key: str, cur, prev) -> str | None:
    """'1,234 (↓ 56 · improving)' style cell, or None if not comparable."""
    c, p = _to_num(cur), _to_num(prev)
    if c is None or p is None:
        return None
    d = c - p
    if d == 0:
        return "→ unchanged"
    arrow = "↑" if d > 0 else "↓"
    good = (d < 0) if key in DOWN_IS_GOOD else (d > 0)
    tone = "improving" if good else "worsening"
    mag = _fmt(int(abs(d)) if float(abs(d)).is_integer() else abs(d))
    return f"{arrow} {mag} ({tone})"


def trend_line(current: dict, prev_row: dict | None, keys: list[str]) -> str:
    """One-line trend summary vs the previous snapshot, for embedding in a
    dashboard header. Empty string when there is no prior snapshot."""
    if not prev_row:
        return ""
    parts = []
    for k in keys:
        d = delta(k, current.get(k), prev_row.get("metrics", {}).get(k))
        if d:
            parts.append(f"{KEY_LABELS.get(k, k)}: {d}")
    if not parts:
        return ""
    return f"Trend vs {prev_row['snapshot_at'][:10]} — " + " · ".join(parts)


# ---------------------------------------------------------------------------
# executive trends dashboard
# ---------------------------------------------------------------------------

_EXEC_SERIES = [
    # (source, key) pairs charted for leadership, in display order.
    (METRICS_SOURCE, "findings_total"),
    (METRICS_SOURCE, "sev_critical"),
    (METRICS_SOURCE, "sev_high"),
    (METRICS_SOURCE, "open_ledger_view"),
    # OWASP Risk Rating Methodology (likelihood x impact, factors derived
    # from each finding's CVSS vector) — % of open findings rated High or
    # Critical risk. Replaces the earlier mean-CVSS and unnormalized
    # CVSS-sum series, which stay in the ledger as history only. See
    # docs/risk-rating-methodology.md.
    (METRICS_SOURCE, "owasp_risk_high_plus_pct"),
    (METRICS_SOURCE, "hardening_backlog"),
    (METRICS_SOURCE, "ledger_coverage_pct"),
    (METRICS_SOURCE, "resolved_findings"),
    (METRICS_SOURCE, "confirmed_exploitable"),
    (METRICS_SOURCE, "threats_open"),
    ("executive-summary", "credential_findings"),
    ("loc-dashboard", "total_loc"),
    ("insecure-patterns", "code_findings"),
    ("validation-fuzz", "checks_attempted"),
    ("threat-register", "threats_unmitigated"),
    ("threat-register", "quick_wins"),
    # Coverage metrics (up is good — not in DOWN_IS_GOOD): fleet ATT&CK
    # technique coverage from the deterministic /attack-coverage roll-up.
    ("attack-coverage", "attack_techniques_observed"),
    ("attack-coverage", "attack_techniques_modeled"),
    # PQC Phase-1 sweep: coverage climbs (up-good), clock items burn down.
    ("pqc-readiness", "pqc_sweep_coverage_pct"),
    ("pqc-readiness", "pqc_clock_items"),
    # PQC Phase-2 roll-up views: ready count climbs; the
    # 2030-clock, not-ready, HNDL, blocker and quick-win series burn down.
    ("pqc-readiness", "pqc_ready"),
    ("pqc-readiness", "pqc_not_ready"),
    ("pqc-readiness", "pqc_hndl_repos"),
    ("pqc-readiness", "pqc_2030_clock_items"),
    ("pqc-readiness", "pqc_hybrid_blockers"),
    ("pqc-readiness", "pqc_toolchain_quickwins"),
]


def render_exec(journal: Path | None = None) -> tuple[Path, Path]:
    all_rows = rows(journal)
    bysrc: dict[str, list[dict]] = {}
    for r in all_rows:
        bysrc.setdefault(r.get("source", "?"), []).append(r)

    today = datetime.date.today().isoformat()
    md = ["# Executive Trends", ""]
    md.append(
        f"**Generated:** {today} · from the append-only, hash-chained "
        f"metrics ledger (`metrics/metrics-history.jsonl`, "
        f"{len(all_rows)} snapshots across {len(bysrc)} sources). "
        f"As-reported numbers are never revised — every movement below "
        f"is a real change or a *noted* methodology change, and the "
        f"chain is verifiable with "
        f"`python3 -m traust_engine.metrics.history verify`."
    )
    md.append("")
    md.append("| Metric | Earliest | Latest | Trend | Snapshots |")
    md.append("|---|---:|---:|---|---:|")

    chart_payload = []
    seen_keys = set()
    for source, key in _EXEC_SERIES:
        pts = [(d, v) for d, v in series(source, key, journal)]
        if len(pts) == 0 or (source, key) in seen_keys:
            continue
        seen_keys.add((source, key))
        label = KEY_LABELS.get(key, key)
        first_d, first_v = pts[0]
        last_d, last_v = pts[-1]
        tr = delta(key, last_v, first_v) or "—"
        md.append(
            f"| {label} | {_fmt(first_v)} ({first_d}) | "
            f"{_fmt(last_v)} ({last_d}) | {tr} | {len(pts)} |"
        )
        nums = [(d, _to_num(v)) for d, v in pts]
        if all(n is not None for _, n in nums):
            chart_payload.append(
                {
                    "label": label,
                    "down_good": key in DOWN_IS_GOOD,
                    "points": [{"x": d, "y": n} for d, n in nums],
                }
            )

    notes = [(r["snapshot_at"][:10], r.get("source"), r["note"]) for r in all_rows if r.get("note")]
    if notes:
        md += ["", "## Methodology / snapshot notes", ""]
        md += [f"- **{d}** (`{s}`) — {n}" for d, s, n in notes]

    ok, issues = verify(journal)
    md += [
        "",
        "**Ledger integrity:** "
        + (
            "✓ chain verified"
            if ok
            else f"⚠ {len(issues)} issue(s) — run `python3 -m traust_engine.metrics.history verify` for details"
        ),
    ]

    out_dir = ledger_path(journal).parent
    md_path = out_dir / "Executive-Trends.md"
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")

    charts_html = "".join(
        f'<div class="card"><h2>{c["label"]}'
        f"{' <span class=badge>lower is better</span>' if c['down_good'] else ''}"
        f'</h2><div class="box"><canvas id="c{i}"></canvas></div></div>'
        for i, c in enumerate(chart_payload)
    )
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Executive Trends</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
 body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;margin:0;background:#fafafa;color:#151515}}
 header{{background:#151515;color:#fff;padding:20px 28px;border-bottom:4px solid #ee0000}}
 header h1{{margin:0;font-size:22px}} header .sub{{color:#d2d2d2;font-size:13px}}
 main{{max-width:1280px;margin:0 auto;padding:24px 28px 60px;display:grid;grid-template-columns:1fr 1fr;gap:22px}}
 @media(max-width:960px){{main{{grid-template-columns:1fr}}}}
 .card{{background:#fff;border:1px solid #d2d2d2;border-radius:8px;padding:16px 18px}}
 .card h2{{margin:0 0 10px;font-size:15px}} .box{{position:relative;height:220px}}
 .badge{{font-size:10px;font-weight:600;color:#6a6e73;border:1px solid #d2d2d2;border-radius:9px;padding:1px 7px;vertical-align:2px}}
 footer{{grid-column:1/-1;color:#6a6e73;font-size:12px}}
</style></head><body>
<header><h1>Executive Trends</h1>
<div class="sub">Generated {today} · append-only hash-chained metrics ledger ·
{len(all_rows)} snapshots · integrity {"✓ verified" if ok else "⚠ check failed"}</div></header>
<main>{charts_html}
<footer>Source: <code>metrics/metrics-history.jsonl</code> —
as-reported snapshots, never revised; methodology changes carry notes.
Verify the chain: <code>python3 -m traust_engine.metrics.history verify</code>.
Rebuild: <code>traust-engine-metrics</code>.</footer></main>
<script>
const S={json.dumps(chart_payload)};
S.forEach((c,i)=>new Chart(document.getElementById('c'+i),{{type:'line',
 data:{{datasets:[{{label:c.label,data:c.points,borderColor:c.down_good?'#ec7a08':'#0066cc',
  backgroundColor:'transparent',tension:.2,pointRadius:4}}]}},
 options:{{responsive:true,maintainAspectRatio:false,parsing:{{xAxisKey:'x',yAxisKey:'y'}},
  plugins:{{legend:{{display:false}}}},scales:{{x:{{type:'category'}},y:{{beginAtZero:false}}}}}}}}));
</script></body></html>"""
    html_path = out_dir / "Executive-Trends.html"
    html_path.write_text(html, encoding="utf-8")
    return md_path, html_path


def append_typed(record: MetricsRecord, journal: Path | None = None) -> dict:
    """Append a typed metrics record to the ledger."""
    if not HAS_CONTRACTS:
        raise ImportError("traust_contracts required")
    return append(
        record.source,
        record.metrics,
        note=record.note,
        hv=record.harness_version or None,
        journal=journal,
    )


def read_typed(journal: Path | None = None) -> list[MetricsRecord]:
    """Read ledger and return typed records."""
    if not HAS_CONTRACTS:
        raise ImportError("traust_contracts required")
    return [
        MetricsRecord(
            timestamp=r.get("snapshot_at", ""),
            source=r.get("source", ""),
            harness_version=r.get("harness_version", ""),
            metrics=r.get("metrics", {}),
            note=r.get("note", ""),
        )
        for r in rows(journal)
    ]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
