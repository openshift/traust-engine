"""Shared-component FP-precedent cache builder.

Measured basis: shared-component false positives are re-litigated across
repos. The same false positive gets re-litigated per repo.
This projection lets the triage workflow ANNOTATE a finding with a matching
precedent so verifiers stop re-deriving settled refutations from
scratch, and lets /secure-code-audit cite a precedent as Precision Gate
evidence (downgrade-not-drop; never silent suppression).

POPULATION RULE (tiered, Phase-4 build 2026-07-27 — supersedes the
v0.151.0 human-only rule, which shipped a permanently-empty cache while
the re-refutation treadmill kept running). Each precedent carries a
`strength`:

  human_countersigned   strongest. Events whose actor is an
                        verified human with a non-empty identity —
                        the countersign workbench's interactive markers
                        (traust.cli.countersign build_human_event +
                        verify_identity) or an external tracker
                        decision-maker event. Guard: the finding's
                        CURRENT derived validity (build_cumulative.
                        derive_disposition over its full event history)
                        must still equal the precedent verdict
                        (fp_overridden / reopened / two-person-rule
                        holds are excluded).

  machine_refuted_sound weaker. Machine false_positive / hardening
                        adjudications from the triage or remediation-
                        verification protocols, and live-validation
                        refutations that PASS the Phase-1 soundness gate
                        (skills/validate-findings/soundness.py,
                        re-derived per event against the referenced
                        validation report). Guards: excluded when the
                        soundness gate flags the refutation
                        (machine-refuted-UNSOUND — the measured
                        ~70%-unsound class NEVER seeds a precedent),
                        when the validation report / entry cannot be
                        resolved (unverifiable = excluded), when any
                        `confirmed` event contests the finding (P6
                        conflict), or when the current derived validity
                        is confirmed/corrected or fp_overridden.

Consumption contract: a precedent is CITEABLE PRIOR ADJUDICATION, never
an auto-verdict. Triage workflow (Phase 2g): a human_countersigned match routes
the finding to the reduced 1-vote tier; a machine_refuted_sound match is
annotation-only (full votes). /secure-code-audit (Precision Gate,
fp-precedent gate): a human_countersigned match is citeable gate
evidence for a downgrade-not-drop disposition; machine-tier matches are
context only. Every consumer treats an empty or missing cache as a
clean no-op.

Keys: each cached precedent is indexed by the finding's `fingerprint`
(traust_engine._util.finding_identity — repo-scoped cross-scan identity) AND by a
repo-independent COMPONENT SIGNATURE:

    sha256( sorted vendor-normalized location paths | primary CWE |
            category slug | sink )

Vendor normalization strips vendor roots (vendor/, third_party/, ...) so
two repos vendoring the same file produce the same signature. `sink` is a
reserved slot (the report schema carries no sink field today; it hashes
as the empty string until one exists).

Taxonomy join: when the FP-persistence analysis
(analysis-results/scan-testing/phase-0/fp-persistence-analysis.json)
is present, externally countersigned precedents are annotated with its
`phase2_rule` / `failure_class` attribution (joined deterministically on
the ticket id in the event's source.ref) so consumers see WHICH
Precision Gate rule the precedent instantiates.

Idempotent rebuild: regenerated from scratch on every run, like the
other analysis-results/graph/ projections. Population counts live in
`metadata` (corpus.py resolves the report population — never a
hand-rolled walker).

CLI:
    traust corpus precedent build \\
        [--analysis-results PATH] [--config PATH] [--out PATH] \\
        [--taxonomy PATH]
    traust corpus precedent match --cache PATH \\
        --findings PATH [--json-out PATH]
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust_contracts.config import CorpusConfig

from traust_engine._util.actor import is_actor_verified as _actor_is_verified
from traust_engine._util.finding_identity import (
    canon_path,
    primary_cwe,
)
from traust_engine._util.finding_identity import (
    fingerprint as compute_fingerprint,
)
from traust_engine.corpus import report_store
from traust_engine.corpus import resolver as corpus
from traust_engine.corpus.disposition import derive_disposition
from traust_engine.locations import (
    analysis_results_dir,
    configured_locations,
)
from traust_engine.validation import soundness as _soundness_mod


def _soundness():
    return _soundness_mod


EPOCH = "1970-01-01T00:00:00+00:00"
RATIONALE_EXCERPT_CAP = 280
EVIDENCE_REFS_CAP = 6

PRECEDENT_VERDICTS = ("false_positive", "hardening")
STRENGTH_HUMAN = "human_countersigned"
STRENGTH_MACHINE = "machine_refuted_sound"
MACHINE_SOURCE_TYPES = ("triage_report", "verification_report", "validation_report")

DEFAULT_TAXONOMY_REL = "scan-testing/phase-0/fp-persistence-analysis.json"

POPULATION_RULE = (
    "Tiered population (Phase-4 build 2026-07-27; supersedes the "
    "v0.151.0 human-only rule). strength=human_countersigned: "
    "false_positive/hardening events from a verified human actor "
    "(interactive countersign markers or external tracker decision-maker), "
    "guarded by the finding's CURRENT derived validity still matching "
    "the verdict. strength=machine_refuted_sound: machine "
    "false_positive/hardening adjudications from triage / remediation-"
    "verification protocols, and live-validation refutations that PASS "
    "the Phase-1 soundness gate re-derived per event against the "
    "referenced validation report. Machine-refuted-UNSOUND refutations "
    "(soundness-flagged, or unresolvable reports/entries) are EXCLUDED "
    "— the measured ~70%-unsound class never seeds a precedent. "
    "Findings contested by any confirmed event (P6 conflict), "
    "fp_overridden, or currently confirmed/corrected are excluded. An "
    "empty or missing cache is a clean no-op for every consumer; "
    "matches are citeable prior adjudications that reduce verifier "
    "votes spent (human tier) or annotate (machine tier) and NEVER "
    "auto-verdict."
)

# Vendor roots across ecosystems: the path portion after the LAST such
# marker identifies the shared component independent of where a repo
# chose to vendor it.
VENDOR_ROOT_RX = re.compile(
    r"(?:^|/)(?:vendor|_vendor|vendored|third_party|thirdparty|"
    r"third-party|external|externals|node_modules|bundled|"
    r"Godeps/_workspace/src)/"
)

CWE_RX = re.compile(r"^CWE-\d+$", re.IGNORECASE)
JIRA_TICKET_RX = re.compile(r"/browse/([A-Z][A-Z0-9]+-\d+)")


# ---------------------------------------------------------------------------
# component signature
# ---------------------------------------------------------------------------


def normalize_vendor_path(path: str | None) -> str:
    """Canonical path with everything up to the LAST vendor-root marker
    stripped, so `vendor/github.com/acme/widget/parse.go` and
    `third_party/github.com/acme/widget/parse.go` normalize identically."""
    s = canon_path(path)
    last = None
    for m in VENDOR_ROOT_RX.finditer(s):
        last = m
    return s[last.end() :] if last else s


def _category_slug(finding: dict) -> str:
    return str(finding.get("category") or "").strip().lower()


def _sink(finding: dict) -> str:
    # Reserved slot: report.schema.json findings carry no sink field
    # today; when one lands it joins the signature here.
    return str(finding.get("sink") or "").strip()


def component_paths(finding: dict) -> list[str]:
    paths = {
        normalize_vendor_path(loc.get("path"))
        for loc in (finding.get("locations") or [])
        if loc.get("path")
    }
    if not paths and finding.get("file"):  # triage-normalized shape
        paths = {normalize_vendor_path(finding["file"])}
    return sorted(p for p in paths if p)


def component_signature(paths: list[str], cwe: str, category: str, sink: str = "") -> str:
    payload = "|".join(
        [";".join(sorted(paths)), cwe.upper().strip(), category.strip().lower(), sink]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def finding_component(finding: dict) -> dict:
    """The repo-independent component identity of one audit finding."""
    return {
        "paths": component_paths(finding),
        "cwe": primary_cwe(finding),
        "category": _category_slug(finding),
        "sink": _sink(finding),
    }


def signature_of(finding: dict) -> str:
    c = finding_component(finding)
    return component_signature(c["paths"], c["cwe"], c["category"], c["sink"])


# ---------------------------------------------------------------------------
# event qualifiers
# ---------------------------------------------------------------------------


def is_countersigned_refutation(event: dict) -> bool:
    """True only for the exact event shape the countersign workbench
    records for a human false-positive determination (kept for the `via`
    annotation; the human tier is `is_human_adjudication`).

    Markers — keep in sync with traust.cli.countersign
    (build_human_event + verify_identity)."""
    if (event.get("disposition") or {}).get("validity") != "false_positive":
        return False
    source = event.get("source") or {}
    if source.get("type") != "interactive":
        return False
    if not str(source.get("ref") or "").startswith("interactive:"):
        return False
    actor = source.get("actor") or {}
    return (
        actor.get("kind") == "human" and _actor_is_verified(actor) and bool(actor.get("identity"))
    )


def is_human_adjudication(event: dict) -> bool:
    """Any verified human FP/hardening determination — interactive
    countersign or external tracker decision-maker event."""
    if (event.get("disposition") or {}).get("validity") not in PRECEDENT_VERDICTS:
        return False
    actor = ((event.get("source") or {}).get("actor")) or {}
    return (
        actor.get("kind") == "human" and _actor_is_verified(actor) and bool(actor.get("identity"))
    )


def is_machine_adjudication(event: dict) -> bool:
    """A machine FP/hardening event from an adjudication-protocol
    source. Soundness (for validation_report events) is checked
    separately."""
    if (event.get("disposition") or {}).get("validity") not in PRECEDENT_VERDICTS:
        return False
    source = event.get("source") or {}
    actor = source.get("actor") or {}
    return actor.get("kind") == "machine" and source.get("type") in MACHINE_SOURCE_TYPES


def _human_via(event: dict) -> str:
    return (
        "interactive"
        if is_countersigned_refutation(event)
        else str((event.get("source") or {}).get("type") or "")
    )


def _excerpt(text: str | None, cap: int = RATIONALE_EXCERPT_CAP) -> str:
    s = " ".join(str(text or "").split())
    return s[:cap] + ("…" if len(s) > cap else "")


# ---------------------------------------------------------------------------
# Phase-1 soundness re-derivation for validation_report events
# ---------------------------------------------------------------------------


class SoundnessResolver:
    """Re-derives the Phase-1 soundness flag for a live-validation
    refutation event by loading the referenced validation report and
    gating its validated_findings entry (same join as
    traust.ops.lint_refutation_soundness). Reports are parsed once."""

    def __init__(self, analysis_results: Path):
        self.root = Path(analysis_results)
        self.store = report_store.ReportStore(report_store.LocalBackend(self.root))
        self._reports: dict[str, dict | None] = {}
        self._install_failed: dict[str, bool] = {}

    def _report(self, ref: str):
        if ref not in self._reports:
            doc = None
            p = self.root / ref
            try:
                doc = self.store.get_json(ref)
            except (OSError, ValueError, json.JSONDecodeError):
                doc = None
            self._reports[ref] = doc
            # run_install_failed probes the sibling RUN DIRECTORY, not the report,
            # so it stays filesystem-bound. Residual coupling, tracked in the plan:
            # a validation run dir has no object-storage analogue yet.
            run_dir = p.parent
            try:
                self._install_failed[ref] = _soundness().run_install_failed(run_dir)
            except Exception:
                self._install_failed[ref] = False
        return self._reports[ref], self._install_failed.get(ref, False)

    def check(self, event: dict) -> tuple[bool, str | None]:
        """(sound, reason). Unresolvable reports/entries are UNSOUND by
        policy — a refutation whose evidence cannot be re-examined never
        seeds a precedent."""
        ref = str((event.get("source") or {}).get("ref") or "")
        finding_ref = str(event.get("finding_ref") or "")
        if not ref or not finding_ref:
            return False, "unresolvable:no-source-ref"
        doc, install_failure = self._report(ref)
        if doc is None:
            return False, "unresolvable:report-missing"
        for vf in doc.get("validated_findings") or []:
            src_id = str(vf.get("source_id") or "")
            if src_id.rsplit("/", 1)[-1] == finding_ref or vf.get("finding_ref") == finding_ref:
                flag = _soundness().flag_validated_finding(vf, install_failure=install_failure)
                if flag:
                    return False, str(flag)
                return True, None
        return False, "unresolvable:entry-not-found"


# ---------------------------------------------------------------------------
# taxonomy join (fp-persistence-analysis.json)
# ---------------------------------------------------------------------------


def load_taxonomy(path: Path | None) -> dict[str, dict]:
    """ticket-id -> {phase2_rule, failure_class} from the FP-persistence
    analysis's countersigned_22 array. Absent/unreadable = empty join."""
    if path is None or not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    out = {}
    for row in doc.get("countersigned_22") or []:
        ticket = str(row.get("ticket") or "").strip()
        if ticket:
            out[ticket] = {
                "phase2_rule": row.get("phase2_rule"),
                "failure_class": row.get("failure_class"),
            }
    return out


def _taxonomy_for(event: dict, taxonomy: dict[str, dict]) -> dict | None:
    if not taxonomy:
        return None
    ref = str((event.get("source") or {}).get("ref") or "")
    m = JIRA_TICKET_RX.search(ref)
    if m and m.group(1) in taxonomy:
        t = taxonomy[m.group(1)]
        return {"ticket": m.group(1), **{k: v for k, v in t.items() if v}}
    return None


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


def _select_precedent_event(
    events: list[dict], resolver: SoundnessResolver, counters: dict
) -> tuple[dict | None, str | None]:
    """Choose one finding's precedent event and its strength tier.
    Human tier wins outright; otherwise the latest SOUND machine
    adjudication. Returns (event, strength) or (None, None)."""
    human = [e for e in events if is_human_adjudication(e)]
    if human:
        return human[-1], STRENGTH_HUMAN
    machine = [e for e in events if is_machine_adjudication(e)]
    for ev in reversed(machine):
        if (ev.get("source") or {}).get("type") == "validation_report":
            sound, reason = resolver.check(ev)
            if not sound:
                counters["excluded_unsound"] += 1
                counters.setdefault("unsound_reasons", {})
                key = str(reason)
                counters["unsound_reasons"][key] = counters["unsound_reasons"].get(key, 0) + 1
                continue
        return ev, STRENGTH_MACHINE
    return None, None


def build_cache(
    analysis_results: Path,
    cfg: CorpusConfig,
    taxonomy_path: Path | None = None,
) -> dict:
    res = report_store.load_resolution(analysis_results, cfg)
    store = report_store.ReportStore(report_store.LocalBackend(analysis_results))
    if taxonomy_path is None:
        cand = Path(analysis_results) / DEFAULT_TAXONOMY_REL
        taxonomy_path = cand if cand.is_file() else None
    taxonomy = load_taxonomy(taxonomy_path)
    resolver = SoundnessResolver(analysis_results)

    components: dict[str, dict] = {}
    fingerprints: dict[str, list[str]] = {}
    counters = {
        "layers_scanned": 0,
        "human_countersigned": 0,
        "machine_refuted_sound": 0,
        "excluded_unsound": 0,
        "excluded_contested": 0,
        "excluded_stale_disposition": 0,
    }

    for rec in res.records:
        if not rec.findings_layer or not rec.audit_json:
            continue
        layer_ref = report_store.to_ref(rec.findings_layer, analysis_results)
        try:
            layer = store.get_json(layer_ref)
            audit = store.get_json(report_store.to_ref(rec.audit_json, analysis_results))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        counters["layers_scanned"] += 1
        findings = {f.get("id"): f for f in audit.get("findings") or []}
        repo_url = (audit.get("metadata") or {}).get("repository")

        events_by_ref: dict[str, list[dict]] = {}
        for e in layer.get("events") or []:
            if e.get("finding_ref"):
                events_by_ref.setdefault(e["finding_ref"], []).append(e)

        for ref, events in sorted(events_by_ref.items()):
            events = sorted(events, key=lambda e: str(e.get("recorded_at") or ""))
            if not any(is_human_adjudication(e) or is_machine_adjudication(e) for e in events):
                continue
            finding = findings.get(ref)
            if finding is None:
                continue  # superseded id — precedent re-enters on rebaseline
            # P6 conflict guard: a finding contested by ANY confirmed
            # event never seeds a machine precedent (human events still
            # can — derive_disposition adjudicates the winner below).
            contested = any(
                (e.get("disposition") or {}).get("validity") == "confirmed" for e in events
            )
            disp = derive_disposition(finding, events, EPOCH)
            ev, strength = _select_precedent_event(events, resolver, counters)
            if ev is None:
                continue
            verdict = ev["disposition"]["validity"]
            if strength == STRENGTH_HUMAN:
                # Guard: current derived validity must still equal the
                # precedent verdict (fp_overridden / reopened /
                # two-person-rule holds drop out here).
                if disp.get("validity") != verdict:
                    counters["excluded_stale_disposition"] += 1
                    continue
            else:
                if contested:
                    counters["excluded_contested"] += 1
                    continue
                if disp.get("validity") in ("confirmed", "corrected") or disp.get("fp_overridden"):
                    counters["excluded_stale_disposition"] += 1
                    continue

            counters[strength] += 1
            actor = (ev.get("source") or {}).get("actor") or {}
            fp = finding.get("fingerprint") or compute_fingerprint(finding, repo_url)
            sig = signature_of(finding)
            entry = components.setdefault(
                sig,
                {
                    "component": finding_component(finding),
                    "precedents": [],
                },
            )
            precedent = {
                "fingerprint": fp,
                "finding_id": ref,
                "source_repo": rec.base_slug,
                "tree": rec.tree,
                "product": rec.product,
                "repository": repo_url,
                # was a third hand-rolled path->ref that also called resolve(),
                # so a symlinked layer was recorded under its target's name
                "layer": layer_ref,
                "event_id": ev.get("event_id"),
                "verdict": verdict,
                "strength": strength,
                "source_type": (ev.get("source") or {}).get("type"),
                "countersigned": strength == STRENGTH_HUMAN,
                "date": str(ev.get("occurred_at") or ev.get("recorded_at") or "")[:10],
                "rationale_excerpt": _excerpt(ev.get("rationale")),
            }
            if strength == STRENGTH_HUMAN:
                precedent["countersigner"] = actor.get("identity")
                if actor.get("display_name"):
                    precedent["countersigner_display"] = actor["display_name"]
                precedent["countersign_via"] = _human_via(ev)
            else:
                precedent["adjudicator"] = actor.get("identity")
            refs = [str(r) for r in (ev.get("evidence_refs") or [])]
            if refs:
                precedent["evidence_refs"] = refs[:EVIDENCE_REFS_CAP]
            tax = _taxonomy_for(ev, taxonomy)
            if tax:
                precedent["taxonomy"] = tax
            entry["precedents"].append(precedent)
            fingerprints.setdefault(fp, [])
            if sig not in fingerprints[fp]:
                fingerprints[fp].append(sig)

    for entry in components.values():
        entry["precedents"].sort(
            key=lambda p: (
                p["strength"] != STRENGTH_HUMAN,
                p["date"],
                p["source_repo"],
                p["finding_id"],
            )
        )

    unsound_reasons = counters.pop("unsound_reasons", {})
    return {
        "metadata": {
            "artifact": "fp-precedent-cache",
            "generated": datetime.now(UTC).isoformat(timespec="seconds"),
            "harness_version": corpus.harness_version(),
            "builder": "traust_engine.corpus.precedent",
            "population_rule": POPULATION_RULE,
            "layers_scanned": counters["layers_scanned"],
            "population": {
                "human_countersigned": counters["human_countersigned"],
                "machine_refuted_sound": counters["machine_refuted_sound"],
                "excluded_unsound": counters["excluded_unsound"],
                "excluded_unsound_reasons": dict(sorted(unsound_reasons.items())),
                "excluded_contested": counters["excluded_contested"],
                "excluded_stale_disposition": counters["excluded_stale_disposition"],
            },
            "taxonomy_source": (str(taxonomy_path) if taxonomy and taxonomy_path else None),
            # kept for pre-0.193.0 readers: the human-tier count
            "countersigned_refutations": counters["human_countersigned"],
            "entries": len(components),
        },
        "components": dict(sorted(components.items())),
        "fingerprints": dict(sorted(fingerprints.items())),
    }


# ---------------------------------------------------------------------------
# match (consumer helper — deterministic, annotation-only)
# ---------------------------------------------------------------------------


def _finding_class(finding: dict) -> tuple[str | None, str]:
    """(cwe, category-slug) from either report-schema or
    triage-normalized findings."""
    cwes = finding.get("cwes") or []
    cwe = str(cwes[0]).upper().strip() if cwes else None
    category = _category_slug(finding)
    if cwe is None and CWE_RX.match(category or ""):
        cwe = category.upper()
    return cwe, category


def match_findings(cache: dict, findings: list[dict]) -> list[dict]:
    """Match findings against the cache. A match requires a
    vendor-normalized path hit on a cached component AND an agreeing
    class (fingerprint equal, exact signature equal, or CWE/category
    equal). Path-only overlap never matches. Returns annotation records —
    verdicts are never authored here. `max_strength` tells the consumer
    which routing tier applies (human_countersigned outranks
    machine_refuted_sound)."""
    matches = []
    components = cache.get("components") or {}
    fingerprints = cache.get("fingerprints") or {}
    for f in findings:
        hits = []
        fp = f.get("fingerprint")
        if fp and fp in fingerprints:
            hits = [(sig, "fingerprint") for sig in fingerprints[fp]]
        else:
            paths = set(component_paths(f))
            if not paths:
                continue
            sig = signature_of(f)
            cwe, category = _finding_class(f)
            for csig, entry in components.items():
                comp = entry["component"]
                if csig == sig:
                    hits.append((csig, "signature"))
                elif paths & set(comp["paths"]) and (
                    (cwe and cwe == comp["cwe"]) or (category and category == comp["category"])
                ):
                    hits.append((csig, "component"))
        for csig, how in hits:
            entry = components.get(csig)
            if not entry:
                continue
            strengths = {p.get("strength") for p in entry["precedents"]}
            matches.append(
                {
                    "finding": f.get("id"),
                    "component_signature": csig,
                    "matched_by": how,
                    "max_strength": (
                        STRENGTH_HUMAN if STRENGTH_HUMAN in strengths else STRENGTH_MACHINE
                    ),
                    "component": entry["component"],
                    "precedents": entry["precedents"],
                }
            )
    return matches


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _find_analysis_results(arg: str | None) -> Path:
    if arg:
        return Path(arg)
    ar = analysis_results_dir(configured_locations())
    if ar and ar.is_dir():
        return ar
    sys.exit("analysis-results not found; pass --analysis-results")
