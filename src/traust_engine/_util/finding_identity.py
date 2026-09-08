"""Stable finding identity across scans — fingerprints and rebaselining.

Campaign finding IDs ({REPO_SLUG}-{SHORTSHA}-{NNN}) are scan-scoped by
design: they are provenance, and the disposition ledger's immutability
depends on a finding_ref never being reinterpreted. But a full re-audit
mints a new report with new IDs, orphaning the old report's ledger history.
This module closes that gap with two pieces:

1. FINGERPRINT — a deterministic, script-computed (never model-authored)
   secondary correlation key stored on each finding:

       fingerprint = sha256(
           canonical repo URL | sorted normalized location paths
           (line numbers dropped) | primary CWE )

   The primary CWE is included deliberately: it disambiguates two distinct
   weakness classes at the same location, at the cost that a re-scan which
   re-classifies the same bug breaks tier-1 correlation — the tier-2
   path-match in the rebaseline ladder catches those.

2. REBASELINE — an explicit correlation operation when a new audit
   supersedes an old one. Match ladder:

       tier 1  fingerprint equal            -> auto-map
       tier 2  same path set + same CWE     -> queued for human review
       tier 2b same path set (unique cand.) -> queued for human review
               (independent re-audits routinely re-classify the same bug's
               CWE — observed live: CWE-863 -> CWE-266 on the same file)
       tier 3  title similarity >= 0.6      -> queued for human review
               (max of sequence and token-set similarity; model runs reword
               titles freely)
       unmatched old finding                -> needs_review (fixed? moved?
                                               dropped?) — never silently lost

   Only tier 1 auto-confirms; every looser tier is a PROPOSAL a human
   accepts or rejects, so recall matters more than precision there.

   The old->new mapping is recorded as `metadata.finding_aliases` in the
   DISPOSITION LAYER — events are never rewritten; build_cumulative.py
   resolves aliases at replay time so old history attaches to new IDs.

Fingerprints do not perturb claim hashes: baseline_claims/validate_report
canonicalize the fixed CLAIM_FIELDS tuple (id, title, severity, cwes,
locations, description, remediation) and `fingerprint` is not in it.

ONE IMPLEMENTATION — canon_repo/canon_path/primary_cwe/fingerprint live in
traust-ledger's SDK tier (`traust_ledger.identity`) and are re-exported through
`traust_engine.ledger` as the single import surface. Edit them in traust-ledger,
never redefine here. traust-engine uses these as pure computation tools;
state-changing operations (stamp+sign, submit) also route through
`traust_engine.ledger` which calls traust-ledger in-process.

The recipe used to be an external contract with a cross-language oracle, because
consumers reimplemented it in other languages. Ledger plan decision **D7**
(2026-08-18) ends that: **only the harness computes identity.** Consumers read
the stamped fingerprint and fail closed when it is absent, and no non-harness
producer computes one either — a producer that mints findings routes through the
harness. The shared golden-vector suite in traust-contracts was retired with
that decision (contracts 0.5.0), and the recipe's regression fixtures moved to
traust-ledger, beside the implementation:

    traust-ledger/tests/fixtures/identity-recipe-vectors.json  (12 cases)
    traust-ledger/tests/test_identity_recipe_vectors.py        (replays them)
    traust-ledger/scripts/gen_identity_recipe_vectors.py       (regenerates; refuses
                                                              to rewrite hashes
                                                              under an unchanged
                                                              ALGO_VERSION)

A hash change is still a recipe change and still invalidates stored fingerprints:
bump `ALGO_VERSION` in `traust_ledger/identity.py`, regenerate, and pair it with a
re-stamp migration. A v1 -> v2 move may need hundreds of them; keep a restamp
worklist alongside the identity migration plan.

CLI:
    python3 -m traust_engine._util.finding_identity fingerprint <audit.json> [--write]
    python3 -m traust_engine._util.finding_identity backfill <findings-root> [--dry-run]
    python3 -m traust_engine._util.finding_identity rebaseline <old-audit.json> \\
        <new-audit.json> <layer.json> [--dry-run]
"""

from __future__ import annotations

import difflib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust_engine._util.layer_paths import confine_layer_path
from traust_engine.ledger import (
    canon_path,
    fingerprint,
    primary_cwe,
)

RPM_CATEGORY_RX = re.compile(r"^RPM(0[1-9]|10)\b")
CANONICAL_FINDING_ID = re.compile(r"^[A-Z][A-Z0-9_]*-[0-9a-f]{7,12}-\d{3}$")

_AUTOLINK_RX = re.compile(r"^<\s*(.*?)\s*>$", re.S)
_BARE_HOST_REPO_RX = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}/[^/\s]+/[^\s]+$", re.I)


def normalize_repository(raw):
    """Repair unambiguously-malformed `metadata.repository`, or return as-is.

    NOT part of the identity recipe — repairs data before hashing."""
    if not isinstance(raw, str):
        return raw
    s = raw.strip()
    m = _AUTOLINK_RX.match(s)
    if m:
        s = m.group(1).strip()
    if "://" not in s and _BARE_HOST_REPO_RX.match(s):
        s = "https://" + s
    return s or raw


def annotate_report(report: dict) -> int:
    """Set/refresh `fingerprint` on every finding. Returns count changed.

    Normalizes `metadata.repository` first (see `normalize_repository`) so a
    transcription artefact cannot survive long enough to be hashed into a
    finding's identity. Also infers `metadata.audit_profile` when absent (rpm
    when any finding carries an RPM01-RPM10 category, else code)."""
    md0 = report.setdefault("metadata", {})
    raw_repo = md0.get("repository")
    changed = 0
    if isinstance(raw_repo, str):
        fixed = normalize_repository(raw_repo)
        if fixed != raw_repo:
            md0["repository"] = fixed
            changed += 1
    repo = md0.get("repository")
    for f in report.get("findings") or []:
        fp = fingerprint(f, repo)
        if f.get("fingerprint") != fp:
            f["fingerprint"] = fp
            changed += 1
    md = report.setdefault("metadata", {})
    if "audit_profile" not in md:
        is_rpm = any(
            RPM_CATEGORY_RX.match(str(f.get("category") or ""))
            for f in report.get("findings") or []
        )
        md["audit_profile"] = "rpm" if is_rpm else "code"
        changed += 1
    return changed


# ---------------------------------------------------------------------------
# rebaseline match ladder
# ---------------------------------------------------------------------------


def _path_set(f: dict) -> frozenset:
    return frozenset(
        canon_path(loc.get("path")) for loc in (f.get("locations") or []) if loc.get("path")
    )


def _title_sim(a: str, b: str) -> float:
    """Max of character-sequence and token-set similarity — re-audits
    reorder/reword titles, so token overlap catches what sequences miss."""
    a, b = (a or "").lower(), (b or "").lower()
    seq = difflib.SequenceMatcher(None, a, b).ratio()
    ta = {t for t in re.split(r"[^a-z0-9]+", a) if len(t) > 2}
    tb = {t for t in re.split(r"[^a-z0-9]+", b) if len(t) > 2}
    jac = len(ta & tb) / len(ta | tb) if ta | tb else 0.0
    return max(seq, jac)


def match_findings(old: dict, new: dict) -> dict:
    """Propose old->new finding mappings between two audit reports.
    Returns {"mapped": {old_id: {...}}, "unmatched_old": [...],
             "unmatched_new": [...]}."""
    old_fs = list(old.get("findings") or [])
    new_fs = list(new.get("findings") or [])
    old_repo = (old.get("metadata") or {}).get("repository")
    new_repo = (new.get("metadata") or {}).get("repository")

    mapped: dict[str, dict] = {}
    taken_new: set[str] = set()

    def claim(o, n, tier):
        mapped[o["id"]] = {"new_id": n["id"], "matched_by": tier}
        taken_new.add(n["id"])

    # tier 1 — fingerprint equal (auto)
    new_by_fp: dict[str, list] = {}
    for n in new_fs:
        new_by_fp.setdefault(n.get("fingerprint") or fingerprint(n, new_repo), []).append(n)
    for o in old_fs:
        fp = o.get("fingerprint") or fingerprint(o, old_repo)
        cands = [n for n in new_by_fp.get(fp, []) if n["id"] not in taken_new]
        if len(cands) == 1:
            claim(o, cands[0], "fingerprint")

    # tier 2 — same path set + same primary CWE (review)
    for o in old_fs:
        if o["id"] in mapped:
            continue
        cands = [
            n
            for n in new_fs
            if n["id"] not in taken_new
            and _path_set(n) == _path_set(o)
            and _path_set(o)
            and primary_cwe(n) == primary_cwe(o)
        ]
        if len(cands) == 1:
            claim(o, cands[0], "path_cwe")

    # tier 2b — overlapping path sets, CWE re-classified (review). Real
    # re-audits cite overlapping-but-not-identical location sets, so exact
    # equality misses; Jaccard >= 0.5 with the best (overlap, title) pick is
    # still review-gated — a wrong proposal costs one human "reject".
    def _pj(a, b):
        return len(a & b) / len(a | b) if a | b else 0.0

    for o in old_fs:
        if o["id"] in mapped or not _path_set(o):
            continue
        scored = [
            (n, _pj(_path_set(o), _path_set(n)), _title_sim(o.get("title"), n.get("title")))
            for n in new_fs
            if n["id"] not in taken_new
        ]
        scored = [t for t in scored if t[1] >= 0.5]
        if scored:
            best = max(scored, key=lambda t: (t[1], t[2]))
            claim(o, best[0], "path_set")
            mapped[o["id"]]["similarity"] = round(best[2], 3)
            mapped[o["id"]]["path_overlap"] = round(best[1], 3)

    # tier 3 — title similarity (review)
    for o in old_fs:
        if o["id"] in mapped:
            continue
        scored = sorted(
            (
                (n, _title_sim(o.get("title"), n.get("title")))
                for n in new_fs
                if n["id"] not in taken_new
            ),
            key=lambda t: -t[1],
        )
        if scored and scored[0][1] >= 0.6:
            claim(o, scored[0][0], "title")
            mapped[o["id"]]["similarity"] = round(scored[0][1], 3)

    return {
        "mapped": mapped,
        "unmatched_old": [o["id"] for o in old_fs if o["id"] not in mapped],
        "unmatched_new": [n["id"] for n in new_fs if n["id"] not in taken_new],
    }


def rebaseline(
    old_path: Path,
    new_path: Path,
    layer_path: Path,
    dry_run: bool = False,
    queue_reviews: bool = True,
    findings_root: Path | None = None,
    ledger_service: object | None = None,
) -> dict:
    """queue_reviews=False (batch mode): non-fingerprint proposals and
    unmatched-old findings are still recorded (unconfirmed aliases /
    summary counts) but do NOT each enqueue a needs_review item — a
    portfolio-scale batch would otherwise flood the countersign queue.
    The aliases table remains the reviewable record."""
    # P9b: never write a ledger outside the tree it belongs to. Raises
    # LayerPathOutsideRoot; callers decide the exit code.
    roots = [findings_root] if findings_root else [Path(new_path).resolve().parent, Path.cwd()]
    layer_path = confine_layer_path(layer_path, roots, what="layer")

    old = json.loads(old_path.read_text(encoding="utf-8"))
    new = json.loads(new_path.read_text(encoding="utf-8"))
    layer = json.loads(layer_path.read_text(encoding="utf-8"))
    result = match_findings(old, new)
    now = datetime.now(UTC).isoformat(timespec="seconds")

    aliases = layer.setdefault("metadata", {}).setdefault("finding_aliases", {})
    # Legacy ids (FIND-NNN etc.) are only unique WITHIN a report — several
    # branch variants of one component reuse them, so bare keys would
    # collide in the shared main layer. Namespace non-canonical old ids
    # with their source-report slug; canonical campaign ids stay bare.
    old_slug = (
        old_path.name[: -len("-security-audit.json")]
        if old_path.name.endswith("-security-audit.json")
        else old_path.stem
    )

    def alias_key(fid: str) -> str:
        return fid if CANONICAL_FINDING_ID.match(fid) else f"{old_slug}:{fid}"

    queued = 0
    for old_id, m in result["mapped"].items():
        entry = dict(m, mapped_at=now, from_report=old_path.name)
        auto = m["matched_by"] == "fingerprint"
        entry["confirmed"] = auto
        key = alias_key(old_id)
        settled = aliases.get(key, {})
        if settled.get("confirmed") or settled.get("rejected"):
            continue  # human-settled mappings are immutable
        aliases[key] = entry
        if not auto and queue_reviews:
            layer.setdefault("needs_review", []).append(
                {
                    "queued_at": now,
                    "source_ref": f"rebaseline:{new_path.name}",
                    "quote": (
                        f"rebaseline proposes {old_id} -> {m['new_id']} "
                        f"via {m['matched_by']} — confirm the mapping "
                        f"(same vulnerability?) or reject"
                    ),
                    "author": "finding_identity/rebaseline",
                    "suggested_finding_ref": m["new_id"],
                    "queue_reason": "rebaseline_mapping",
                    "status": "pending",
                }
            )
            queued += 1
    for old_id in result["unmatched_old"] if queue_reviews else []:
        layer.setdefault("needs_review", []).append(
            {
                "queued_at": now,
                "source_ref": f"rebaseline:{new_path.name}",
                "quote": (
                    f"{old_id} from {old_path.name} has no match in "
                    f"{new_path.name} — fixed, moved, or dropped? Its "
                    f"ledger history stays under the old id until a "
                    f"human maps or closes it"
                ),
                "author": "finding_identity/rebaseline",
                "suggested_finding_ref": old_id,
                "queue_reason": "rebaseline_unmatched",
                "status": "pending",
            }
        )
        queued += 1
    layer["metadata"]["updated"] = now

    # Migrate the layer's claim-hash pins to the new baseline. An old id
    # that is superseded (aliased to a successor, or unmatched WITH a
    # queued needs_review decision) and absent from the new report would
    # otherwise fail every future build_cumulative run as a "baselined
    # finding missing from the audit report". Only covered ids are
    # dropped — an id with no alias and no queued decision keeps its pin,
    # so the tamper guard still fires for genuine silent deletions. The
    # next `baseline_claims.py record` pins the new report's claims.
    new_ids = {f.get("id") for f in (new.get("findings") or [])}
    claims = layer["metadata"].get("claim_hashes") or {}
    covered = set(result["mapped"])
    covered |= {
        k.split(":", 1)[-1] for k, v in aliases.items() if v.get("from_report") == old_path.name
    }
    if queue_reviews:
        covered |= set(result["unmatched_old"])
    migrated = [fid for fid in list(claims) if fid not in new_ids and fid in covered]
    for fid in migrated:
        del claims[fid]
    result["migrated_claims"] = migrated

    # The layer now tracks the new baseline report.
    new_commit = str((new.get("metadata") or {}).get("commit") or "")
    if re.fullmatch(r"[0-9a-f]{7,40}", new_commit):
        layer["metadata"]["audit_commit"] = new_commit

    if not dry_run:
        from traust_engine.ledger import LedgerService

        layer_path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
        svc = ledger_service or LedgerService()
        svc.sign(layer_path)
    result["queued_reviews"] = queued
    return result


def _persist_report(report_path: Path, report: dict) -> None:
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def run_fingerprint(report_path: Path, *, write: bool = False) -> int:
    rep = json.loads(report_path.read_text(encoding="utf-8"))
    n = annotate_report(rep)
    if write and n:
        _persist_report(report_path, rep)
    for f in rep.get("findings") or []:
        print(f"{f['id']}  {f['fingerprint']}")
    print(f"{n} field(s) {'written' if write else 'would change'}")
    return 0


def run_backfill(root: Path, *, dry_run: bool = False) -> int:
    seen = changed_files = findings = 0
    for p in sorted(root.rglob("*-security-audit.json")):
        if "_manifest" in p.parts:
            continue
        try:
            rep = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"skip {p}: {e}", file=sys.stderr)
            continue
        seen += 1
        n = annotate_report(rep)
        findings += len(rep.get("findings") or [])
        if n and not dry_run:
            _persist_report(p, rep)
        if n:
            changed_files += 1
    print(
        f"backfill: {seen} reports scanned, {changed_files} "
        f"{'updated' if not dry_run else 'would update'}, "
        f"{findings} findings fingerprinted"
    )
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
